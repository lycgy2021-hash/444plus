package model

import "testing"

func TestNormalizeTargets(t *testing.T) {
	for input, want := range map[string]string{
		"HTTP://Example.COM:80":        "http://example.com/",
		"https://Example.COM.:443/app": "https://example.com/app",
		"http://[::1]:8080/":           "http://[::1]:8080/",
		"http://127.0.0.1:8080/a%2fb":  "http://127.0.0.1:8080/a%2fb",
	} {
		target, err := ParseTarget(input)
		if err != nil || target.BaseURL != want {
			t.Errorf("%q => %+v, %v; want %s", input, target, err, want)
		}
	}
	for _, input := range []string{"example.com", "file:///tmp/test", "http://user:pass@host", "http://host/?secret=x", "http://host/#x", "http://host:70000", "http://host:", "http://-host", "http://a..b", "http://[fe80::1%25eth0]"} {
		if _, err := ParseTarget(input); err == nil {
			t.Errorf("accepted invalid target %q", input)
		}
	}
}
