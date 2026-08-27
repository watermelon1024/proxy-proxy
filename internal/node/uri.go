package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var errUnsupported = errors.New("unsupported scheme")

// FromURI parses one subscription line. Unparseable or unknown-scheme lines
// become pass-through nodes (kept verbatim in base64 output, absent from
// clash output). Returns nil for blanks and comments.
func FromURI(sub, line string) *Node {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil
	}
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok {
		return nil
	}

	var m map[string]any
	var err error
	switch strings.ToLower(scheme) {
	case "ss":
		m, err = parseSS(rest)
	case "vmess":
		m, err = parseVmess(rest)
	case "vless":
		m, err = parseVless(line)
	case "trojan":
		m, err = parseTrojan(line)
	case "hysteria2", "hy2":
		m, err = parseHysteria2(line)
	default:
		err = errUnsupported
	}
	if err != nil {
		raw := line
		name := ""
		if i := strings.LastIndex(line, "#"); i >= 0 {
			name, _ = url.PathUnescape(line[i+1:])
		}
		return &Node{Sub: sub, Name: name, Key: "raw|" + stripFragment(raw), Raw: raw}
	}
	return &Node{Sub: sub, Name: str(m["name"]), Key: clashKey(m), Clash: m, Raw: line}
}

func stripFragment(s string) string {
	if i := strings.LastIndex(s, "#"); i >= 0 {
		return s[:i]
	}
	return s
}

// b64Decode tolerates std/url alphabets, padding or none, and embedded
// whitespace.
func b64Decode(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

func splitHostPort(hostport string) (string, int, error) {
	hostport = strings.TrimSuffix(hostport, "/")
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return host, port, nil
}

// parseSS handles SIP002 (base64 or percent-encoded userinfo) and the legacy
// fully-base64 form.
func parseSS(rest string) (map[string]any, error) {
	name := ""
	if i := strings.LastIndex(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	if !strings.Contains(rest, "@") {
		dec, err := b64Decode(rest)
		if err != nil {
			return nil, fmt.Errorf("ss: %w", err)
		}
		rest = string(dec)
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return nil, errors.New("ss: missing @")
	}
	userinfo, hostport := rest[:at], rest[at+1:]

	var method, password string
	if dec, err := b64Decode(userinfo); err == nil && strings.Contains(string(dec), ":") {
		method, password, _ = strings.Cut(string(dec), ":")
	} else {
		ui, err := url.PathUnescape(userinfo)
		if err != nil {
			ui = userinfo
		}
		var ok bool
		method, password, ok = strings.Cut(ui, ":")
		if !ok {
			return nil, errors.New("ss: malformed userinfo")
		}
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	m := map[string]any{
		"name": name, "type": "ss", "server": host, "port": port,
		"cipher": method, "password": password, "udp": true,
	}
	if query != "" {
		if v, err := url.ParseQuery(query); err == nil {
			applySSPlugin(m, v.Get("plugin"))
		}
	}
	return m, nil
}

func applySSPlugin(m map[string]any, plugin string) {
	if plugin == "" {
		return
	}
	parts := strings.Split(plugin, ";")
	opts := map[string]any{}
	for _, p := range parts[1:] {
		k, v, _ := strings.Cut(p, "=")
		opts[k] = v
	}
	switch parts[0] {
	case "obfs-local", "simple-obfs", "obfs":
		po := map[string]any{"mode": str(opts["obfs"])}
		if h := str(opts["obfs-host"]); h != "" {
			po["host"] = h
		}
		m["plugin"] = "obfs"
		m["plugin-opts"] = po
	case "v2ray-plugin":
		po := map[string]any{"mode": "websocket"}
		if _, ok := opts["tls"]; ok {
			po["tls"] = true
		}
		if h := str(opts["host"]); h != "" {
			po["host"] = h
		}
		if p := str(opts["path"]); p != "" {
			po["path"] = p
		}
		m["plugin"] = "v2ray-plugin"
		m["plugin-opts"] = po
	}
}

// parseVmess handles the v2rayN base64-JSON form.
func parseVmess(rest string) (map[string]any, error) {
	dec, err := b64Decode(rest)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	var j map[string]any
	if err := json.Unmarshal(dec, &j); err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	server, port, uuid := str(j["add"]), toInt(j["port"]), str(j["id"])
	if server == "" || port == 0 || uuid == "" {
		return nil, errors.New("vmess: missing add/port/id")
	}
	cipher := str(j["scy"])
	if cipher == "" {
		cipher = "auto"
	}
	m := map[string]any{
		"name": str(j["ps"]), "type": "vmess", "server": server, "port": port,
		"uuid": uuid, "alterId": toInt(j["aid"]), "cipher": cipher, "udp": true,
	}
	if toBool(j["tls"]) {
		m["tls"] = true
		if sni := str(j["sni"]); sni != "" {
			m["servername"] = sni
		}
	}
	if fp := str(j["fp"]); fp != "" {
		m["client-fingerprint"] = fp
	}
	if alpn := str(j["alpn"]); alpn != "" {
		m["alpn"] = splitList(alpn)
	}
	host, path := str(j["host"]), str(j["path"])
	switch str(j["net"]) {
	case "ws":
		m["network"] = "ws"
		m["ws-opts"] = wsOpts(path, host)
	case "grpc":
		m["network"] = "grpc"
		m["grpc-opts"] = map[string]any{"grpc-service-name": path}
	case "h2", "http":
		m["network"] = "h2"
		o := map[string]any{}
		if path != "" {
			o["path"] = path
		}
		if host != "" {
			o["host"] = []string{host}
		}
		m["h2-opts"] = o
	}
	return m, nil
}

func wsOpts(path, host string) map[string]any {
	if path == "" {
		path = "/"
	}
	o := map[string]any{"path": path}
	if host != "" {
		o["headers"] = map[string]any{"Host": host}
	}
	return o
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func parseStdURL(line string) (u *url.URL, host string, port int, err error) {
	u, err = url.Parse(line)
	if err != nil {
		return nil, "", 0, err
	}
	port, err = strconv.Atoi(u.Port())
	if err != nil || u.Hostname() == "" {
		return nil, "", 0, errors.New("missing host or port")
	}
	return u, u.Hostname(), port, nil
}

func parseVless(line string) (map[string]any, error) {
	u, host, port, err := parseStdURL(line)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, errors.New("vless: missing uuid")
	}
	q := u.Query()
	m := map[string]any{
		"name": u.Fragment, "type": "vless", "server": host, "port": port,
		"uuid": uuid, "udp": true,
	}
	sec := q.Get("security")
	if sec == "tls" || sec == "reality" {
		m["tls"] = true
	}
	if sni := q.Get("sni"); sni != "" {
		m["servername"] = sni
	}
	if flow := q.Get("flow"); flow != "" {
		m["flow"] = flow
	}
	if fp := q.Get("fp"); fp != "" {
		m["client-fingerprint"] = fp
	}
	if pbk := q.Get("pbk"); pbk != "" {
		ro := map[string]any{"public-key": pbk}
		if sid := q.Get("sid"); sid != "" {
			ro["short-id"] = sid
		}
		m["reality-opts"] = ro
	}
	if v := q.Get("allowInsecure"); v == "1" || v == "true" {
		m["skip-cert-verify"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		m["alpn"] = splitList(alpn)
	}
	applyTransport(m, q)
	return m, nil
}

func parseTrojan(line string) (map[string]any, error) {
	u, host, port, err := parseStdURL(line)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	password := userinfoString(u)
	if password == "" {
		return nil, errors.New("trojan: missing password")
	}
	q := u.Query()
	m := map[string]any{
		"name": u.Fragment, "type": "trojan", "server": host, "port": port,
		"password": password, "udp": true,
	}
	if sni := firstOf(q.Get("sni"), q.Get("peer")); sni != "" {
		m["sni"] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		m["client-fingerprint"] = fp
	}
	if v := q.Get("allowInsecure"); v == "1" || v == "true" {
		m["skip-cert-verify"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		m["alpn"] = splitList(alpn)
	}
	applyTransport(m, q)
	return m, nil
}

func parseHysteria2(line string) (map[string]any, error) {
	u, host, port, err := parseStdURL(line)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	q := u.Query()
	m := map[string]any{
		"name": u.Fragment, "type": "hysteria2", "server": host, "port": port,
		"password": userinfoString(u),
	}
	if sni := q.Get("sni"); sni != "" {
		m["sni"] = sni
	}
	if v := q.Get("insecure"); v == "1" || v == "true" {
		m["skip-cert-verify"] = true
	}
	if obfs := q.Get("obfs"); obfs != "" {
		m["obfs"] = obfs
		if pw := q.Get("obfs-password"); pw != "" {
			m["obfs-password"] = pw
		}
	}
	if ports := firstOf(q.Get("mport"), q.Get("ports")); ports != "" {
		m["ports"] = ports
	}
	if alpn := q.Get("alpn"); alpn != "" {
		m["alpn"] = splitList(alpn)
	}
	return m, nil
}

// applyTransport maps the standard type/host/path/serviceName query params
// onto Clash network options.
func applyTransport(m map[string]any, q url.Values) {
	switch q.Get("type") {
	case "ws":
		m["network"] = "ws"
		m["ws-opts"] = wsOpts(q.Get("path"), q.Get("host"))
	case "grpc":
		m["network"] = "grpc"
		m["grpc-opts"] = map[string]any{"grpc-service-name": firstOf(q.Get("serviceName"), q.Get("path"))}
	case "h2", "http":
		m["network"] = "h2"
		o := map[string]any{}
		if p := q.Get("path"); p != "" {
			o["path"] = p
		}
		if h := q.Get("host"); h != "" {
			o["host"] = []string{h}
		}
		m["h2-opts"] = o
	}
}

// userinfoString returns the full decoded userinfo, rejoining any
// user:password split done by url.Parse.
func userinfoString(u *url.URL) string {
	s := u.User.Username()
	if p, ok := u.User.Password(); ok {
		s += ":" + p
	}
	return s
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
