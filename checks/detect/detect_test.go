package detect

import (
	"regexp"
	"testing"
)

func TestExtractVersion(t *testing.T) {
	nginxRE := regexp.MustCompile(`(?i)(?:^|[^a-z])nginx/([0-9]+\.[0-9]+\.[0-9]+)`)
	apacheRE := regexp.MustCompile(`(?i)(?:^|[\s(])Apache/([0-9]+\.[0-9]+\.[0-9]+)`)
	cases := []struct {
		re     *regexp.Regexp
		banner string
		want   string
		ok     bool
	}{
		{nginxRE, "nginx/1.29.0", "1.29.0", true},
		{nginxRE, "nginx/1.30.4 (Ubuntu)", "1.30.4", true},
		{nginxRE, "nginx", "", false},
		{nginxRE, "", "", false},
		{nginxRE, "nginx/1.29.0.1", "", false},            // longer version rejected
		{nginxRE, "nginx/1.29.0 nginx/1.31.5", "", false}, // conflicting versions
		{nginxRE, "openresty/1.21.4", "", false},          // not nginx/
		{apacheRE, "Apache/2.4.49", "2.4.49", true},
		{apacheRE, "Apache/2.4.49 Apache/2.4.51", "", false}, // ambiguous
		{apacheRE, "Apache/2.4.49.1", "", false},
	}
	for _, tc := range cases {
		got, _, ok := ExtractVersion(tc.banner, tc.re)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ExtractVersion(%q) = (%q,%v), want (%q,%v)", tc.banner, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseVersionAndLess(t *testing.T) {
	if _, ok := ParseVersion("1.2"); ok {
		t.Error("2-part version should fail")
	}
	if _, ok := ParseVersion("1.2.x"); ok {
		t.Error("non-numeric should fail")
	}
	v, ok := ParseVersion("1.30.4")
	if !ok || v != (Version{1, 30, 4}) {
		t.Fatalf("ParseVersion 1.30.4 = %v,%v", v, ok)
	}
	if !Less(Version{1, 30, 3}, Version{1, 30, 4}) || Less(Version{1, 31, 0}, Version{1, 30, 9}) {
		t.Error("Less comparison wrong")
	}
}
