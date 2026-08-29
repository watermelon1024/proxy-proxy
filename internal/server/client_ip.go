package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

const (
	cloudflareClientIPHeader = "CF-Connecting-IP"
	xForwardedForHeader      = "X-Forwarded-For"
	xffSourcePrefix          = "xff:"
	headerSourcePrefix       = "header:"
	privateTrustKeyword      = "private"
	firstXFFHop              = 1
)

type clientIPSourceKind uint8

const (
	clientIPDirect clientIPSourceKind = iota
	clientIPHeader
	clientIPXFF
	clientIPXFFTrusted
)

// ClientIPSource is an immutable request client-IP selection policy.
type ClientIPSource struct {
	kind         clientIPSourceKind
	headerName   string
	xffHop       int
	trustPrivate bool
	trustedNets  []netip.Prefix
	trustedSpec  string // canonical form of the trusted list, for String
}

// ParseClientIPSource accepts direct, cf, xff:<n>, xff:<trusted-proxies>, or header:<name>.
func ParseClientIPSource(value string) (ClientIPSource, error) {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case lower == "direct":
		return ClientIPSource{kind: clientIPDirect}, nil
	case lower == "cf":
		return newHeaderClientIPSource(cloudflareClientIPHeader)
	case strings.HasPrefix(lower, xffSourcePrefix):
		return newXFFClientIPSource(value[len(xffSourcePrefix):])
	case strings.HasPrefix(lower, headerSourcePrefix):
		return newHeaderClientIPSource(value[len(headerSourcePrefix):])
	default:
		return ClientIPSource{}, fmt.Errorf(
			"invalid client IP source %q (want direct, cf, xff:<n>, xff:<trusted-proxies>, or header:<name>)", value,
		)
	}
}

// newXFFClientIPSource takes either a hop count (xff:2) or a trusted-proxy
// list (xff:private,100.64.0.0/10); an integer always means a hop count.
func newXFFClientIPSource(value string) (ClientIPSource, error) {
	trimmed := strings.TrimSpace(value)
	if hop, err := strconv.Atoi(trimmed); err == nil {
		if hop < firstXFFHop {
			return ClientIPSource{}, fmt.Errorf("XFF hop must be a positive integer, got %q", value)
		}
		return ClientIPSource{kind: clientIPXFF, xffHop: hop}, nil
	}
	return newTrustedXFFClientIPSource(trimmed)
}

func newTrustedXFFClientIPSource(value string) (ClientIPSource, error) {
	src := ClientIPSource{kind: clientIPXFFTrusted}
	parts := strings.Split(value, ",")
	canonical := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.EqualFold(part, privateTrustKeyword) {
			src.trustPrivate = true
			canonical = append(canonical, privateTrustKeyword)
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			src.trustedNets = append(src.trustedNets, p.Masked())
			canonical = append(canonical, p.Masked().String())
			continue
		}
		if a, err := netip.ParseAddr(part); err == nil && a.Zone() == "" {
			p := netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			src.trustedNets = append(src.trustedNets, p)
			canonical = append(canonical, p.String())
			continue
		}
		return ClientIPSource{}, fmt.Errorf(
			"invalid trusted proxy %q (want a CIDR, an IP, or %q)", part, privateTrustKeyword,
		)
	}
	src.trustedSpec = strings.Join(canonical, ",")
	return src, nil
}

func newHeaderClientIPSource(value string) (ClientIPSource, error) {
	name := strings.TrimSpace(value)
	if !validHeaderName(name) {
		return ClientIPSource{}, fmt.Errorf("invalid client IP header name %q", value)
	}
	return ClientIPSource{kind: clientIPHeader, headerName: name}, nil
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	const tokenPunctuation = "!#$%&'*+-.^_`|~"
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune(tokenPunctuation, rune(c)) {
			return false
		}
	}
	return true
}

func (s ClientIPSource) String() string {
	switch s.kind {
	case clientIPDirect:
		return "direct"
	case clientIPHeader:
		return headerSourcePrefix + s.headerName
	case clientIPXFF:
		return xffSourcePrefix + strconv.Itoa(s.xffHop)
	case clientIPXFFTrusted:
		return xffSourcePrefix + s.trustedSpec
	default:
		return "invalid"
	}
}

// Resolve returns one validated IP according to the configured source.
func (s ClientIPSource) Resolve(r *http.Request) (string, error) {
	switch s.kind {
	case clientIPDirect:
		return resolveDirectIP(r.RemoteAddr)
	case clientIPHeader:
		return resolveHeaderIP(r.Header, s.headerName)
	case clientIPXFF:
		return resolveXFFIP(r.Header, s.xffHop)
	case clientIPXFFTrusted:
		return s.resolveTrustedXFFIP(r.Header, r.RemoteAddr)
	default:
		return "", fmt.Errorf("invalid client IP source kind %d", s.kind)
	}
}

// resolveTrustedXFFIP walks X-Forwarded-For right to left, skipping trusted
// proxies; the first untrusted hop is the client. An untrusted direct peer is
// the client itself (its headers are ignored), and a fully trusted chain
// means the request originated inside the infrastructure, so its leftmost
// hop wins.
func (s ClientIPSource) resolveTrustedXFFIP(header http.Header, remoteAddr string) (string, error) {
	origin, err := parseDirectAddr(remoteAddr)
	if err != nil {
		return "", err
	}
	if !s.trustsProxy(origin) {
		return origin.String(), nil
	}
	values := header.Values(xForwardedForHeader)
	if len(values) == 0 {
		return origin.String(), nil
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil || addr.Zone() != "" {
			return "", fmt.Errorf(
				"X-Forwarded-For hop %d from the right is not a valid IP address: %q", len(hops)-i, hops[i],
			)
		}
		addr = addr.Unmap()
		if !s.trustsProxy(addr) {
			return addr.String(), nil
		}
		origin = addr
	}
	return origin.String(), nil
}

func (s ClientIPSource) trustsProxy(addr netip.Addr) bool {
	if s.trustPrivate && (addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
		return true
	}
	for _, p := range s.trustedNets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func resolveHeaderIP(header http.Header, name string) (string, error) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", fmt.Errorf("header %s must contain exactly one value, got %d", name, len(values))
	}
	return parseForwardedIP(values[0], "header "+name)
}

func resolveXFFIP(header http.Header, hop int) (string, error) {
	values := header.Values(xForwardedForHeader)
	if len(values) == 0 {
		return "", fmt.Errorf("X-Forwarded-For has 0 hops, need hop %d from the right", hop)
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	if len(hops) < hop {
		return "", fmt.Errorf("X-Forwarded-For has %d hops, need hop %d from the right", len(hops), hop)
	}
	return parseForwardedIP(hops[len(hops)-hop], fmt.Sprintf("X-Forwarded-For hop %d", hop))
}

func resolveDirectIP(remoteAddr string) (string, error) {
	addr, err := parseDirectAddr(remoteAddr)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func parseDirectAddr(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid TCP remote address %q: %w", remoteAddr, err)
	}
	return addr.Unmap(), nil
}

func parseForwardedIP(value, source string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("%s is not a valid IP address: %q", source, value)
	}
	return addr.Unmap().String(), nil
}

func (s *Server) clientIPLogArgs(r *http.Request) []any {
	clientIP, clientErr := s.ClientIPSource.Resolve(r)
	peerIP, peerErr := resolveDirectIP(r.RemoteAddr)
	args := make([]any, 0, 8)
	if clientErr == nil {
		args = append(args, "remote", clientIP)
	} else {
		args = append(args, "client_ip_source", s.ClientIPSource.String(), "client_ip_error", clientErr)
	}
	if peerErr == nil {
		return append(args, "peer", peerIP)
	}
	return append(args, "peer_addr", r.RemoteAddr, "peer_ip_error", peerErr)
}
