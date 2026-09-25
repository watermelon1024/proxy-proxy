// Package config loads and validates proxy-proxy.yaml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration accepts flexible spellings like "3h", "30min", "2hr", "1d", "1h30m", or a bare number of seconds.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	parsed, err := ParseFlexDuration(value.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", value.Line, err)
	}
	*d = Duration(parsed)
	return nil
}

var (
	dayRe = regexp.MustCompile(`(\d+(?:\.\d+)?)d`)
	// Longest spellings first so e.g. "mins" is not mangled by "min".
	unitReplacer = strings.NewReplacer(
		"days", "d", "day", "d",
		"hours", "h", "hour", "h", "hrs", "h", "hr", "h",
		"minutes", "m", "minute", "m", "mins", "m", "min", "m",
		"seconds", "s", "second", "s", "secs", "s", "sec", "s",
	)
)

// ParseFlexDuration parses "3h", "30min", "1d", "1h30m", "90s" or a bare number (interpreted as seconds).
func ParseFlexDuration(s string) (time.Duration, error) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(n * float64(time.Second)), nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	s = unitReplacer.Replace(s)
	s = dayRe.ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseFloat(strings.TrimSuffix(m, "d"), 64)
		return strconv.FormatFloat(n*24, 'f', -1, 64) + "h"
	})
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

type Sub struct {
	Name     string   `yaml:"name"`
	URL      string   `yaml:"url"`      // HTTP(S) URL; file:// is kept for compatibility
	File     string   `yaml:"file"`     // local filesystem path
	Type     string   `yaml:"type"`     // auto | base64 | raw | clash
	Interval Duration `yaml:"interval"` // default 1h, minimum 1m
}

type Key struct {
	Key         string   `yaml:"key"`
	AllowedSubs []string `yaml:"allowed_subs"` // empty = all subs

	// Resolved is AllowedSubs expanded and ordered by subs config order.
	Resolved []string `yaml:"-"`
}

// Relay forwards downstream http/socks5 clients through one of its upstream proxies.
// Relays are validated by the relay package, which skips invalid ones instead of failing the whole config.
type Relay struct {
	Name       string       `yaml:"name"`
	Strategy   string       `yaml:"strategy"` // url-test | fallback | round-robin | consistent-hashing | sticky-sessions (default url-test)
	Upstream   []Upstream   `yaml:"upstream"`
	Downstream []Downstream `yaml:"downstream"`
}

// Upstream is either a `sub:` reference or an inline Clash proxy map.
type Upstream struct {
	Sub      string         // sub name, or an http(s) URL fetched only for relays
	Interval Duration       // refresh period of a sub URL; a named sub keeps its own
	Proxy    map[string]any // inline Clash proxy, handed to mihomo as-is

	// SubName is the store key Sub resolves to: the sub's name, or for a URL its entry in
	// Config.RelaySubs. Empty if the URL is malformed.
	SubName string
}

func (u *Upstream) UnmarshalYAML(value *yaml.Node) error {
	var m map[string]any
	if err := value.Decode(&m); err != nil {
		return err
	}
	if _, ok := m["sub"]; !ok {
		u.Proxy = m
		return nil
	}
	for k := range m {
		if k != "sub" && k != "interval" {
			return fmt.Errorf("line %d: sub only allows interval next to it, not %q", value.Line, k)
		}
	}
	var ref struct {
		Sub      string   `yaml:"sub"`
		Interval Duration `yaml:"interval"`
	}
	if err := value.Decode(&ref); err != nil {
		return err
	}
	if ref.Sub == "" {
		return fmt.Errorf("line %d: sub must be a sub name or URL", value.Line)
	}
	u.Sub, u.Interval = ref.Sub, ref.Interval
	return nil
}

// IsSubURL reports whether a `sub:` reference is a URL rather than a sub name.
func IsSubURL(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

type Downstream struct {
	Type     string `yaml:"type"`   // http | socks5 | mixed (default mixed)
	Listen   string `yaml:"listen"` // bind address (default all interfaces)
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Config struct {
	Listen    string   `yaml:"listen"`     // default :8080
	UserAgent string   `yaml:"user_agent"` // default clash.meta UA
	Timeout   Duration `yaml:"timeout"`    // upstream fetch timeout, default 30s
	Subs      []Sub    `yaml:"subs"`
	Keys      []Key    `yaml:"keys"`
	Relays    []Relay  `yaml:"relay"`

	// RelaySubs are subs that relay upstreams reference only by URL.
	// They are refreshed like Subs but never served by /sub.
	RelaySubs []Sub `yaml:"-"`
}

// FileURLToPath converts a legacy file:// URL into an OS path.
func FileURLToPath(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("want file URL, got scheme %q", u.Scheme)
	}

	path := u.Path
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		if runtime.GOOS == "windows" {
			return filepath.FromSlash("//" + u.Host + path), nil
		}
		return "", fmt.Errorf("file URL host %q is not local", u.Host)
	}
	if runtime.GOOS == "windows" {
		if len(path) >= 3 && path[0] == '/' && isDriveLetter(path[1]) && path[2] == ':' {
			path = path[1:]
		}
	}
	if path == "" {
		return "", errors.New("file URL path is empty")
	}
	return filepath.FromSlash(path), nil
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// SubNames returns sub names in config order.
func (c *Config) SubNames() []string {
	names := make([]string, len(c.Subs))
	for i, s := range c.Subs {
		names[i] = s.Name
	}
	return names
}

// FetchedSubs returns every sub to refresh: Subs followed by RelaySubs.
func (c *Config) FetchedSubs() []Sub {
	return append(slices.Clone(c.Subs), c.RelaySubs...)
}

// FetchedSubNames returns the names of FetchedSubs.
func (c *Config) FetchedSubNames() []string {
	names := c.SubNames()
	for _, s := range c.RelaySubs {
		names = append(names, s.Name)
	}
	return names
}

const (
	defaultListen    = ":8080"
	defaultUserAgent = "clash.meta/1.19.0 (proxy-proxy)"
	defaultTimeout   = 30 * time.Second
	defaultInterval  = time.Hour
	minInterval      = time.Minute
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.UserAgent == "" {
		c.UserAgent = defaultUserAgent
	}
	if c.Timeout <= 0 {
		c.Timeout = Duration(defaultTimeout)
	}
	if len(c.Subs) == 0 {
		return errors.New("no subs configured")
	}
	seenNames, err := c.validateSubs()
	if err != nil {
		return err
	}
	if err := c.validateKeys(seenNames); err != nil {
		return err
	}
	c.resolveRelaySubs(seenNames)
	return nil
}

// resolveRelaySubs fills Upstream.SubName. A sub name is kept as is; the relay package checks that
// it exists. A URL becomes a RelaySubs entry named "relay:<host>" with the upstream's interval
// (default 1h, minimum 1m), shared by every upstream with the same URL at the shortest interval.
func (c *Config) resolveRelaySubs(seenNames map[string]bool) {
	byURL := map[string]int{} // URL -> index in RelaySubs
	for i := range c.Relays {
		for j := range c.Relays[i].Upstream {
			up := &c.Relays[i].Upstream[j]
			if up.Sub == "" {
				continue
			}
			if !IsSubURL(up.Sub) {
				up.SubName = up.Sub
				continue
			}
			interval := up.Interval
			if interval <= 0 {
				interval = Duration(defaultInterval)
			}
			interval = max(interval, Duration(minInterval))
			if k, ok := byURL[up.Sub]; ok {
				c.RelaySubs[k].Interval = min(c.RelaySubs[k].Interval, interval)
				up.SubName = c.RelaySubs[k].Name
				continue
			}
			u, err := url.Parse(up.Sub)
			if err != nil || u.Hostname() == "" {
				continue
			}
			baseName := "relay:" + u.Hostname()
			name := baseName
			for n := 2; seenNames[name]; n++ {
				name = fmt.Sprintf("%s-%d", baseName, n)
			}
			seenNames[name] = true
			byURL[up.Sub] = len(c.RelaySubs)
			c.RelaySubs = append(c.RelaySubs, Sub{Name: name, URL: up.Sub, Type: "auto", Interval: interval})
			up.SubName = name
		}
	}
}

func (c *Config) validateSubs() (map[string]bool, error) {
	seenNames := map[string]bool{}
	for i := range c.Subs {
		if err := validateSub(&c.Subs[i], i, seenNames); err != nil {
			return nil, err
		}
	}
	return seenNames, nil
}

func validateSub(s *Sub, index int, seenNames map[string]bool) error {
	source, err := parseSubSource(s, index)
	if err != nil {
		return err
	}
	switch s.Type {
	case "":
		s.Type = "auto"
	case "auto", "base64", "raw", "clash":
		// golang has no fallthrough, so we can safely leave this case empty,
		// it won't go to the next case segment.
	default:
		return fmt.Errorf("subs[%d]: invalid type %q (want auto, base64, raw or clash)", index, s.Type)
	}
	if s.Interval <= 0 {
		s.Interval = Duration(defaultInterval)
	}
	if s.Interval.D() < minInterval {
		s.Interval = Duration(minInterval)
	}
	if s.Name == "" {
		baseName := defaultSubName(source)
		s.Name = baseName
		for n := 2; seenNames[s.Name]; n++ {
			s.Name = fmt.Sprintf("%s-%d", baseName, n)
		}
	}
	if seenNames[s.Name] {
		return fmt.Errorf("subs[%d]: duplicate name %q", index, s.Name)
	}
	seenNames[s.Name] = true
	return nil
}

type subSource struct {
	url      *url.URL
	filePath string
}

func parseSubSource(s *Sub, index int) (subSource, error) {
	hasURL := s.URL != ""
	hasFile := s.File != ""
	if hasURL && hasFile {
		return subSource{}, fmt.Errorf("subs[%d]: url and file cannot both be set", index)
	}
	if !hasURL && !hasFile {
		return subSource{}, fmt.Errorf("subs[%d]: url or file is required", index)
	}
	if hasFile {
		return subSource{filePath: s.File}, nil
	}

	u, err := url.Parse(s.URL)
	if err != nil {
		return subSource{}, fmt.Errorf("subs[%d]: invalid url %q", index, s.URL)
	}
	switch strings.ToLower(u.Scheme) {
	case "file":
		path, err := FileURLToPath(s.URL)
		if err != nil {
			return subSource{}, fmt.Errorf("subs[%d]: invalid url %q: %w", index, s.URL, err)
		}
		s.File = path
		s.URL = ""
		return subSource{filePath: path}, nil
	case "http", "https":
		return subSource{url: u}, nil
	default:
		return subSource{}, fmt.Errorf("subs[%d]: invalid url %q", index, s.URL)
	}
}

func (c *Config) validateKeys(seenNames map[string]bool) error {
	seenKeys := map[string]bool{}
	for i := range c.Keys {
		k := &c.Keys[i]
		if k.Key == "" {
			return fmt.Errorf("keys[%d]: key is required", i)
		}
		if seenKeys[k.Key] {
			return fmt.Errorf("keys[%d]: duplicate key", i)
		}
		seenKeys[k.Key] = true

		if len(k.AllowedSubs) == 0 {
			k.Resolved = c.SubNames()
			continue
		}
		allowed := map[string]bool{}
		for _, name := range k.AllowedSubs {
			if !seenNames[name] {
				return fmt.Errorf("keys[%d]: allowed_subs references unknown sub %q", i, name)
			}
			allowed[name] = true
		}
		for _, s := range c.Subs {
			if allowed[s.Name] {
				k.Resolved = append(k.Resolved, s.Name)
			}
		}
	}
	return nil
}

func defaultSubName(source subSource) string {
	if source.filePath != "" {
		name := filepath.Base(source.filePath)
		if name != "." && name != string(filepath.Separator) && name != "" {
			return name
		}
		return "file"
	}
	return source.url.Hostname()
}
