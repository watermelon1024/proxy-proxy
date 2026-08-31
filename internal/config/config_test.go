package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestParseFlexDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"3h":     3 * time.Hour,
		"30min":  30 * time.Minute,
		"2hr":    2 * time.Hour,
		"1d":     24 * time.Hour,
		"1h30m":  90 * time.Minute,
		"90s":    90 * time.Second,
		"3600":   time.Hour,
		"2 days": 48 * time.Hour,
	}
	for in, want := range cases {
		got, err := ParseFlexDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseFlexDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "3x"} {
		if _, err := ParseFlexDuration(bad); err == nil {
			t.Errorf("ParseFlexDuration(%q) should fail", bad)
		}
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy-proxy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsAndResolution(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
subs:
  - url: https://a.example.com/sub
    name: A
    interval: 3h
  - url: https://b.example.com/sub
    name: B
keys:
  - key: pp-all
  - key: pp-b-only
    allowed_subs: [B]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.Subs[0].Interval.D() != 3*time.Hour || cfg.Subs[1].Interval.D() != time.Hour {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	if got := cfg.Keys[0].Resolved; len(got) != 2 || got[0] != "A" {
		t.Fatalf("empty allowed_subs should resolve to all: %v", got)
	}
	if got := cfg.Keys[1].Resolved; len(got) != 1 || got[0] != "B" {
		t.Fatalf("allowed_subs resolution wrong: %v", got)
	}
}

func TestLoadRawSubscriptionType(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
subs:
  - url: https://a.example.com/sub
    type: raw
keys:
  - key: raw
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Subs[0].Type != "raw" {
		t.Fatalf("want raw subscription type, got %q", cfg.Subs[0].Type)
	}
}

func TestFileURLToPath(t *testing.T) {
	want := filepath.FromSlash("/tmp/local subscription.txt")
	got, err := FileURLToPath("file://localhost/tmp/local%20subscription.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("want path %q, got %q", want, got)
	}
	if _, err := FileURLToPath("https://example.com/sub"); err == nil {
		t.Fatal("non-file URL should fail")
	}
	remote, err := FileURLToPath("file://server/share/sub.txt")
	if runtime.GOOS == "windows" {
		if err != nil || remote != filepath.FromSlash("//server/share/sub.txt") {
			t.Fatalf("want Windows UNC path, got %q, %v", remote, err)
		}
	} else if err == nil {
		t.Fatal("remote file URL should fail outside Windows")
	}
}

func TestLoadFileSubscription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local subscription.txt")
	cfg, err := Load(writeConfig(t, fmt.Sprintf(`
subs:
  - file: %s
keys:
  - key: local
`, path)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Subs[0].File != path || cfg.Subs[0].URL != "" {
		t.Fatalf("file source changed during load: %+v", cfg.Subs[0])
	}
	if cfg.Subs[0].Name != filepath.Base(path) {
		t.Fatalf("want default file name %q, got %q", filepath.Base(path), cfg.Subs[0].Name)
	}
}

func TestLoadFileSubscriptionURLCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local-subscription.txt")
	rawURL := "file://" + filepath.ToSlash(path)
	cfg, err := Load(writeConfig(t, fmt.Sprintf(`
subs:
  - url: %s
keys:
  - key: local
`, rawURL)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Subs[0].File != path || cfg.Subs[0].URL != "" {
		t.Fatalf("legacy file URL was not normalized: %+v", cfg.Subs[0])
	}
	if cfg.Subs[0].Name != filepath.Base(path) {
		t.Fatalf("want default file name %q, got %q", filepath.Base(path), cfg.Subs[0].Name)
	}
}

func TestLoadRejectsBadConfigs(t *testing.T) {
	bad := []string{
		"subs: []\n",
		"subs:\n  - url: \"\"\n",
		"subs:\n  - file: \"\"\n",
		"subs:\n  - url: https://a/s\n    file: /tmp/sub.txt\n",
		"subs:\n  - url: not-a-url\n",
		"subs:\n  - url: file://\n",
		"subs:\n  - url: https://a/s\n    type: nope\n",
		"subs:\n  - url: https://a/s\n    name: X\n  - url: https://b/s\n    name: X\n",
		"subs:\n  - url: https://a/s\n    name: A\nkeys:\n  - key: k\n    allowed_subs: [Missing]\n",
		"subs:\n  - url: https://a/s\nkeys:\n  - key: k\n  - key: k\n",
		"subs:\n  - url: https://a/s\n    typo_field: 1\n",
	}
	for i, c := range bad {
		if _, err := Load(writeConfig(t, c)); err == nil {
			t.Errorf("case %d should fail:\n%s", i, c)
		}
	}
}
