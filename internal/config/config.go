// Package config loads and validates proxy-proxy.yaml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
	URL      string   `yaml:"url"`
	Type     string   `yaml:"type"`     // auto | base64 | clash
	Interval Duration `yaml:"interval"` // default 1h, minimum 1m
}

type Key struct {
	Key         string   `yaml:"key"`
	AllowedSubs []string `yaml:"allowed_subs"` // empty = all subs

	// Resolved is AllowedSubs expanded and ordered by subs config order.
	Resolved []string `yaml:"-"`
}

type Config struct {
	Listen    string   `yaml:"listen"`     // default :8080
	UserAgent string   `yaml:"user_agent"` // default clash.meta UA
	Timeout   Duration `yaml:"timeout"`    // upstream fetch timeout, default 30s
	Subs      []Sub    `yaml:"subs"`
	Keys      []Key    `yaml:"keys"`
}

// SubNames returns sub names in config order.
func (c *Config) SubNames() []string {
	names := make([]string, len(c.Subs))
	for i, s := range c.Subs {
		names[i] = s.Name
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

	seenNames := map[string]bool{}
	for i := range c.Subs {
		s := &c.Subs[i]
		if s.URL == "" {
			return fmt.Errorf("subs[%d]: url is required", i)
		}
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("subs[%d]: invalid url %q", i, s.URL)
		}
		switch s.Type {
		case "":
			s.Type = "auto"
		case "auto", "base64", "clash":
		default:
			return fmt.Errorf("subs[%d]: invalid type %q (want auto, base64 or clash)", i, s.Type)
		}
		if s.Interval <= 0 {
			s.Interval = Duration(defaultInterval)
		}
		if s.Interval.D() < minInterval {
			s.Interval = Duration(minInterval)
		}
		if s.Name == "" {
			s.Name = u.Hostname()
			for n := 2; seenNames[s.Name]; n++ {
				s.Name = fmt.Sprintf("%s-%d", u.Hostname(), n)
			}
		}
		if seenNames[s.Name] {
			return fmt.Errorf("subs[%d]: duplicate name %q", i, s.Name)
		}
		seenNames[s.Name] = true
	}

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
