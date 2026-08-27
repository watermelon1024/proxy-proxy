package node

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
)

// BuildURI renders a Clash proxy map as a share-link URI with the given name.
// ok is false for proxy types without a URI representation.
func BuildURI(m map[string]any, name string) (string, bool) {
	switch str(m["type"]) {
	case "ss":
		return buildSS(m, name), true
	case "vmess":
		return buildVmess(m, name), true
	case "vless":
		return buildStdURL("vless", m, name, vlessQuery(m)), true
	case "trojan":
		return buildStdURL("trojan", m, name, trojanQuery(m)), true
	case "hysteria2":
		return buildStdURL("hysteria2", m, name, hysteria2Query(m)), true
	default:
		return "", false
	}
}

func mapHostPort(m map[string]any) string {
	return net.JoinHostPort(str(m["server"]), strconv.Itoa(toInt(m["port"])))
}

func subMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func joinList(v any) string {
	switch l := v.(type) {
	case []string:
		out := ""
		for i, s := range l {
			if i > 0 {
				out += ","
			}
			out += s
		}
		return out
	case []any:
		out := ""
		for i, s := range l {
			if i > 0 {
				out += ","
			}
			out += str(s)
		}
		return out
	default:
		return str(v)
	}
}

func buildSS(m map[string]any, name string) string {
	userinfo := base64.RawURLEncoding.EncodeToString(
		[]byte(str(m["cipher"]) + ":" + str(m["password"])))
	s := "ss://" + userinfo + "@" + mapHostPort(m)
	if plugin := ssPluginString(m); plugin != "" {
		s += "?plugin=" + url.QueryEscape(plugin)
	}
	return s + "#" + url.PathEscape(name)
}

func ssPluginString(m map[string]any) string {
	po := subMap(m, "plugin-opts")
	switch str(m["plugin"]) {
	case "obfs":
		s := "obfs-local;obfs=" + str(po["mode"])
		if h := str(po["host"]); h != "" {
			s += ";obfs-host=" + h
		}
		return s
	case "v2ray-plugin":
		s := "v2ray-plugin"
		if toBool(po["tls"]) {
			s += ";tls"
		}
		if h := str(po["host"]); h != "" {
			s += ";host=" + h
		}
		if p := str(po["path"]); p != "" {
			s += ";path=" + p
		}
		return s
	default:
		return ""
	}
}

func buildVmess(m map[string]any, name string) string {
	j := map[string]any{
		"v":    "2",
		"ps":   name,
		"add":  str(m["server"]),
		"port": strconv.Itoa(toInt(m["port"])),
		"id":   str(m["uuid"]),
		"aid":  strconv.Itoa(toInt(m["alterId"])),
		"scy":  str(m["cipher"]),
		"net":  "tcp",
		"type": "none",
	}
	if j["scy"] == "" {
		j["scy"] = "auto"
	}
	if toBool(m["tls"]) {
		j["tls"] = "tls"
		if sni := str(m["servername"]); sni != "" {
			j["sni"] = sni
		}
	}
	if fp := str(m["client-fingerprint"]); fp != "" {
		j["fp"] = fp
	}
	if alpn := joinList(m["alpn"]); alpn != "" {
		j["alpn"] = alpn
	}
	switch str(m["network"]) {
	case "ws":
		j["net"] = "ws"
		if o := subMap(m, "ws-opts"); o != nil {
			j["path"] = str(o["path"])
			if h := subMap(o, "headers"); h != nil {
				j["host"] = str(h["Host"])
			}
		}
	case "grpc":
		j["net"] = "grpc"
		if o := subMap(m, "grpc-opts"); o != nil {
			j["path"] = str(o["grpc-service-name"])
		}
	case "h2":
		j["net"] = "h2"
		if o := subMap(m, "h2-opts"); o != nil {
			j["path"] = str(o["path"])
			j["host"] = joinList(o["host"])
		}
	}
	b, _ := json.Marshal(j)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func buildStdURL(scheme string, m map[string]any, name string, q url.Values) string {
	var user *url.Userinfo
	switch scheme {
	case "vless":
		user = url.User(str(m["uuid"]))
	default:
		user = url.User(str(m["password"]))
	}
	u := url.URL{
		Scheme:   scheme,
		User:     user,
		Host:     mapHostPort(m),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String()
}

func transportQuery(m map[string]any, q url.Values) {
	switch str(m["network"]) {
	case "ws":
		q.Set("type", "ws")
		if o := subMap(m, "ws-opts"); o != nil {
			if p := str(o["path"]); p != "" {
				q.Set("path", p)
			}
			if h := subMap(o, "headers"); h != nil {
				if host := str(h["Host"]); host != "" {
					q.Set("host", host)
				}
			}
		}
	case "grpc":
		q.Set("type", "grpc")
		if o := subMap(m, "grpc-opts"); o != nil {
			if s := str(o["grpc-service-name"]); s != "" {
				q.Set("serviceName", s)
			}
		}
	case "h2":
		q.Set("type", "http")
		if o := subMap(m, "h2-opts"); o != nil {
			if p := str(o["path"]); p != "" {
				q.Set("path", p)
			}
			if h := joinList(o["host"]); h != "" {
				q.Set("host", h)
			}
		}
	default:
		q.Set("type", "tcp")
	}
}

func vlessQuery(m map[string]any) url.Values {
	q := url.Values{}
	q.Set("encryption", "none")
	ro := subMap(m, "reality-opts")
	switch {
	case ro != nil:
		q.Set("security", "reality")
		q.Set("pbk", str(ro["public-key"]))
		if sid := str(ro["short-id"]); sid != "" {
			q.Set("sid", sid)
		}
	case toBool(m["tls"]):
		q.Set("security", "tls")
	case true:
		q.Set("security", "none")
	}
	if sni := str(m["servername"]); sni != "" {
		q.Set("sni", sni)
	}
	if flow := str(m["flow"]); flow != "" {
		q.Set("flow", flow)
	}
	if fp := str(m["client-fingerprint"]); fp != "" {
		q.Set("fp", fp)
	}
	if toBool(m["skip-cert-verify"]) {
		q.Set("allowInsecure", "1")
	}
	if alpn := joinList(m["alpn"]); alpn != "" {
		q.Set("alpn", alpn)
	}
	transportQuery(m, q)
	return q
}

func trojanQuery(m map[string]any) url.Values {
	q := url.Values{}
	if sni := str(m["sni"]); sni != "" {
		q.Set("sni", sni)
	}
	if fp := str(m["client-fingerprint"]); fp != "" {
		q.Set("fp", fp)
	}
	if toBool(m["skip-cert-verify"]) {
		q.Set("allowInsecure", "1")
	}
	if alpn := joinList(m["alpn"]); alpn != "" {
		q.Set("alpn", alpn)
	}
	transportQuery(m, q)
	return q
}

func hysteria2Query(m map[string]any) url.Values {
	q := url.Values{}
	if sni := str(m["sni"]); sni != "" {
		q.Set("sni", sni)
	}
	if toBool(m["skip-cert-verify"]) {
		q.Set("insecure", "1")
	}
	if obfs := str(m["obfs"]); obfs != "" {
		q.Set("obfs", obfs)
		if pw := str(m["obfs-password"]); pw != "" {
			q.Set("obfs-password", pw)
		}
	}
	if ports := str(m["ports"]); ports != "" {
		q.Set("mport", ports)
	}
	if alpn := joinList(m["alpn"]); alpn != "" {
		q.Set("alpn", alpn)
	}
	return q
}
