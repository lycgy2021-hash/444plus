package config

import (
	"gopoc/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStrictConfigDefaultsAndActiveOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("http:\n  timeout: 3s\n  rate: 0\nactive:\n  enabled: true\n  canary:\n    file_path: /tmp/gopoc-test.txt\n    expected: GOPOC-TEST-123456\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.HTTP.Timeout != 3*time.Second || c.HTTP.MaxBodySize != 1<<20 || c.HTTP.Rate != 0 {
		t.Fatalf("defaults/load: %+v %v", c, err)
	}
	if err := c.Validate(model.ModeActiveCanary); err != nil {
		t.Fatal(err)
	}
	c.Active.Enabled = false
	if err := c.Validate(model.ModeActiveCanary); err == nil {
		t.Fatal("active mode accepted without enable")
	}
	for _, raw := range []string{"http:\n  timeuot: 3s\n", "http: {}\n---\nhttp: {}\n", "active:\n  enabled: true\n  enabled: false\n"} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("invalid config accepted: %s", raw)
		}
	}
}
