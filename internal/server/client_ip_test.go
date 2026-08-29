package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseClientIPSource(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"direct", "direct"},
		{"DIRECT", "direct"},
		{"cf", "header:CF-Connecting-IP"},
		{"CF", "header:CF-Connecting-IP"},
		{"xff:1", "xff:1"},
		{"XFF: 2", "xff:2"},
		{"xff:private", "xff:private"},
		{"XFF:Private, 100.64.0.0/10", "xff:private,100.64.0.0/10"},
		{"xff:100.64.7.7/10", "xff:100.64.0.0/10"},
		{"xff:1.2.3.4", "xff:1.2.3.4/32"},
		{"xff:2001:db8::/32", "xff:2001:db8::/32"},
		{"header:X-Real-IP", "header:X-Real-IP"},
	}
	for _, c := range cases {
		source, err := ParseClientIPSource(c.input)
		if err != nil {
			t.Errorf("ParseClientIPSource(%q): %v", c.input, err)
			continue
		}
		if got := source.String(); got != c.want {
			t.Errorf("ParseClientIPSource(%q).String() = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestParseClientIPSourceRejectsInvalidValues(t *testing.T) {
	bad := []string{
		"", "xff", "xff:0", "xff:-1", "xff:nope", "xff:10.0.0.0/33", "xff:private,",
		"header:", "header:bad header", "unknown",
	}
	for _, input := range bad {
		if _, err := ParseClientIPSource(input); err == nil {
			t.Errorf("ParseClientIPSource(%q) should fail", input)
		}
	}
}

func TestClientIPSourceResolve(t *testing.T) {
	cases := []struct {
		name, source, remote, want string
		headers                    map[string][]string
		wantErr                    string
	}{
		{name: "direct ignores headers", source: "direct", remote: "203.0.113.9:1234", headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}, want: "203.0.113.9"},
		{name: "direct IPv6", source: "direct", remote: "[2001:db8::1]:1234", want: "2001:db8::1"},
		{name: "cloudflare shortcut", source: "cf", remote: "10.0.0.2:1234", headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4"}}, want: "1.2.3.4"},
		{name: "arbitrary header", source: "header:X-Real-IP", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Real-IP": {"2001:db8::2"}}, want: "2001:db8::2"},
		{name: "mapped IPv4", source: "header:X-Real-IP", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Real-IP": {"::ffff:192.0.2.1"}}, want: "192.0.2.1"},
		{name: "XFF rightmost", source: "xff:1", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"6.6.6.6, 1.2.3.4, 198.51.100.5"}}, want: "198.51.100.5"},
		{name: "XFF second from right ignores spoofed left entry", source: "xff:2", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"fake, 1.2.3.4, 198.51.100.5"}}, want: "1.2.3.4"},
		{name: "XFF repeated fields", source: "xff:2", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"6.6.6.6, 1.2.3.4", "198.51.100.5"}}, want: "1.2.3.4"},
		{name: "missing header", source: "cf", remote: "10.0.0.2:1234", wantErr: "exactly one value"},
		{name: "multiple header values", source: "cf", remote: "10.0.0.2:1234", headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4", "5.6.7.8"}}, wantErr: "exactly one value"},
		{name: "header list rejected", source: "cf", remote: "10.0.0.2:1234", headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4, 5.6.7.8"}}, wantErr: "not a valid IP address"},
		{name: "XFF hop absent", source: "xff:3", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, 198.51.100.5"}}, wantErr: "has 2 hops"},
		{name: "XFF selected hop invalid", source: "xff:2", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"fake, 1.2.3.4"}}, wantErr: "not a valid IP address"},
		{name: "trusted rightmost untrusted wins", source: "xff:private", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"6.6.6.6, 203.0.113.7"}}, want: "203.0.113.7"},
		{name: "trusted untrusted peer ignores XFF", source: "xff:private", remote: "203.0.113.9:1234", headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}, want: "203.0.113.9"},
		{name: "trusted extra CIDR skipped", source: "xff:private,100.64.0.0/10", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"203.0.113.7, 100.64.0.1"}}, want: "203.0.113.7"},
		{name: "trusted single IP entry", source: "xff:1.2.3.4", remote: "1.2.3.4:1234", headers: map[string][]string{"X-Forwarded-For": {"9.9.9.9"}}, want: "9.9.9.9"},
		{name: "trusted mapped hop unmapped before check", source: "xff:private", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"203.0.113.7, ::ffff:192.168.0.9"}}, want: "203.0.113.7"},
		{name: "trusted whole chain takes leftmost", source: "xff:private", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"192.168.1.5, 10.0.0.3"}}, want: "192.168.1.5"},
		{name: "trusted no XFF takes peer", source: "xff:private", remote: "127.0.0.1:1234", want: "127.0.0.1"},
		{name: "trusted walk hits invalid hop", source: "xff:private", remote: "10.0.0.2:1234", headers: map[string][]string{"X-Forwarded-For": {"203.0.113.7, fake"}}, wantErr: "hop 1 from the right is not a valid IP"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			source, err := ParseClientIPSource(c.source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := source.Resolve(newClientIPRequest(c.remote, c.headers))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("Resolve() error = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("Resolve() = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

func newClientIPRequest(remote string, values map[string][]string) *http.Request {
	header := http.Header{}
	for name, entries := range values {
		for _, value := range entries {
			header.Add(name, value)
		}
	}
	return &http.Request{RemoteAddr: remote, Header: header}
}
