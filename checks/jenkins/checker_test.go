package jenkins

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

// mockProbe drives the ladders without a live Jenkins. Fingerprint returns the
// configured headers (the header combo is what identifies the product and the
// version); Get routes by path to the configured per-endpoint responses.
type mockProbe struct {
	fpHeaders      map[string]string
	scriptStatus   int
	scriptBody     string
	scriptLocation string
	scriptErr      error
	cliJarStatus   int
	cliStatus      int
	apiStatus      int
	whoAmIBody     string
}

func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{StatusCode: 200, Headers: canonicalHeaders(m.fpHeaders)}, nil
}

func (m mockProbe) Get(_ context.Context, _ model.Target, path string) (httpx.Response, error) {
	switch path {
	case scriptPath:
		if m.scriptErr != nil {
			return httpx.Response{}, m.scriptErr
		}
		return httpx.Response{StatusCode: m.scriptStatus, Body: []byte(m.scriptBody), Location: m.scriptLocation, Headers: map[string]string{}}, nil
	case cliJarPath:
		return httpx.Response{StatusCode: m.cliJarStatus, Headers: map[string]string{}}, nil
	case cliPath:
		return httpx.Response{StatusCode: m.cliStatus, Headers: map[string]string{}}, nil
	case apiJSONPath:
		return httpx.Response{StatusCode: m.apiStatus, Headers: map[string]string{}}, nil
	case whoAmIPath:
		return httpx.Response{StatusCode: 200, Body: []byte(m.whoAmIBody), Headers: map[string]string{}}, nil
	}
	return httpx.Response{StatusCode: 404, Headers: map[string]string{}}, nil
}

func (m mockProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) TCP(context.Context, model.Target, []byte, int) ([]byte, error) { return nil, nil }

func canonicalHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}

// realConsole is a minimal body carrying the exact markers of the live 2.568.3
// Script Console page: the label plus the named Groovy textarea.
const realConsole = `<title>Script Console - Manage Jenkins - Jenkins</title>` +
	`<h1>Script Console</h1><form action="script" method="post">` +
	`<textarea id="script" name="script" class="script"></textarea></form>`

// jenkinsHeaders is the two-signal header set a real Jenkins always sends.
func jenkinsHeaders(version string) map[string]string {
	return map[string]string{"X-Jenkins": version, "X-Hudson": "1.395", "X-Jenkins-Session": "deadbeef"}
}

func TestAnonScriptConsoleLadder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8080")
	cases := []struct {
		name   string
		probe  mockProbe
		want   model.Verdict
		reason string
	}{
		{
			name:   "not_jenkins",
			probe:  mockProbe{fpHeaders: map[string]string{"Server": "nginx"}},
			want:   model.VerdictNotFound,
			reason: "product_not_jenkins",
		},
		{
			// A single forged X-Jenkins must NOT identify the product (≥2 signals).
			name:   "single_forged_x_jenkins",
			probe:  mockProbe{fpHeaders: map[string]string{"X-Jenkins": "2.441"}, scriptStatus: 200, scriptBody: realConsole},
			want:   model.VerdictNotFound,
			reason: "product_not_jenkins",
		},
		{
			// Real secure default: /script 403. This must NEVER be likely.
			name:   "script_protected",
			probe:  mockProbe{fpHeaders: jenkinsHeaders("2.568.3"), scriptStatus: 403},
			want:   model.VerdictDetected,
			reason: "script_console_protected",
		},
		{
			// The other browser-facing form of the secure default: a redirect
			// to /login rather than a bare 403. Must also stay at detected.
			name:   "script_protected_login_redirect",
			probe:  mockProbe{fpHeaders: jenkinsHeaders("2.568.3"), scriptStatus: 302, scriptLocation: "/login?from=%2Fscript"},
			want:   model.VerdictDetected,
			reason: "script_console_protected",
		},
		{
			name:   "anonymous_script_console_exposed",
			probe:  mockProbe{fpHeaders: jenkinsHeaders("2.568.3"), scriptStatus: 200, scriptBody: realConsole, apiStatus: 200, whoAmIBody: `{"anonymous":true}`},
			want:   model.VerdictLikely,
			reason: "anonymous_script_console_exposed",
		},
		{
			// 200 but not the console page (e.g. a proxy's uniform 200) — must not elevate.
			name:   "script_200_not_console",
			probe:  mockProbe{fpHeaders: jenkinsHeaders("2.568.3"), scriptStatus: 200, scriptBody: `<html>generic landing page</html>`},
			want:   model.VerdictDetected,
			reason: "script_console_unconfirmed",
		},
		{
			name:   "script_unreachable",
			probe:  mockProbe{fpHeaders: jenkinsHeaders("2.568.3"), scriptErr: errors.New("connection refused")},
			want:   model.VerdictUnknown,
			reason: "script_console_unreachable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewAnonScriptConsole(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %s", f.Verdict, f.Reason, tc.want, tc.reason, f.Evidence.Message)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("this checker must never confirm (caps at likely)")
			}
		})
	}
}

func TestCVE202423897Ladder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8080")
	cases := []struct {
		name    string
		probe   mockProbe
		want    model.Verdict
		reason  string
		version string
	}{
		{
			name:   "not_jenkins",
			probe:  mockProbe{fpHeaders: map[string]string{"Server": "nginx"}},
			want:   model.VerdictNotFound,
			reason: "product_not_jenkins",
		},
		{
			name:    "weekly_affected_cli_exposed",
			probe:   mockProbe{fpHeaders: jenkinsHeaders("2.441"), scriptStatus: 403, cliJarStatus: 200, cliStatus: 302},
			want:    model.VerdictLikely,
			reason:  "affected_surface_exposed",
			version: "2.441",
		},
		{
			name:    "lts_affected_cli_exposed",
			probe:   mockProbe{fpHeaders: jenkinsHeaders("2.426.2"), scriptStatus: 403, cliJarStatus: 200},
			want:    model.VerdictLikely,
			reason:  "affected_surface_exposed",
			version: "2.426.2",
		},
		{
			name:    "affected_but_cli_disabled",
			probe:   mockProbe{fpHeaders: jenkinsHeaders("2.441"), scriptStatus: 403, cliJarStatus: 404, cliStatus: 404},
			want:    model.VerdictDetected,
			reason:  "affected_version",
			version: "2.441",
		},
		{
			name:    "lts_fixed",
			probe:   mockProbe{fpHeaders: jenkinsHeaders("2.426.3"), cliJarStatus: 200},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "2.426.3",
		},
		{
			name:    "weekly_fixed",
			probe:   mockProbe{fpHeaders: jenkinsHeaders("2.442"), cliJarStatus: 200},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "2.442",
		},
		{
			name:    "modern_lts_fixed",
			probe:   mockProbe{fpHeaders: jenkinsHeaders("2.568.3"), cliJarStatus: 200},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "2.568.3",
		},
		{
			// Jenkins identified by headers but the version is non-numeric and no
			// data-version in the body: affected status is unknown, must not elevate.
			name:   "version_unknown",
			probe:  mockProbe{fpHeaders: map[string]string{"X-Jenkins": "dev", "X-Hudson": "1.395"}, scriptStatus: 200, scriptBody: `<html>no version here</html>`},
			want:   model.VerdictUnknown,
			reason: "version_unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewCVE202423897(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %s", f.Verdict, f.Reason, tc.want, tc.reason, f.Evidence.Message)
			}
			if tc.version != "" && f.Evidence.Version != tc.version {
				t.Errorf("version = %q, want %q", f.Evidence.Version, tc.version)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("CVE checker must never confirm (default scan never reads a file)")
			}
		})
	}
}

// TestVersionBoundary pins the two documented fix lines directly.
func TestVersionBoundary(t *testing.T) {
	cases := []struct {
		v        string
		affected bool
	}{
		{"2.441", true},    // weekly, last affected
		{"2.442", false},   // weekly, fixed
		{"2.440", true},    // weekly, affected
		{"2.426.2", true},  // LTS, last affected
		{"2.426.3", false}, // LTS, fixed
		{"2.414.3", true},  // older LTS baseline
		{"2.440.1", false}, // next LTS baseline carries the fix
		{"2.568.3", false}, // modern LTS
		{"3.0", false},     // future major
		{"1.650", true},    // legacy major
	}
	for _, tc := range cases {
		v, ok := parseVersion(tc.v)
		if !ok {
			t.Fatalf("parseVersion(%q) failed", tc.v)
		}
		if got := affectedCVE202423897(v); got != tc.affected {
			t.Errorf("affected(%s) = %v, want %v", tc.v, got, tc.affected)
		}
	}
}

// TestRealServerScriptConsole exercises both states end-to-end through a real
// httpx.Client and HTTP server: the secure default (/script 403) must stay at
// detected, and a deliberately open console (/script 200 + console page) must
// reach likely.
func TestRealServerScriptConsole(t *testing.T) {
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 500 * time.Millisecond
	pol, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpx.New(opts, pol)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	handler := func(scriptStatus int, scriptBody string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Jenkins", "2.568.3")
			w.Header().Set("X-Hudson", "1.395")
			w.Header().Set("X-Jenkins-Session", "abc123")
			switch r.URL.Path {
			case scriptPath:
				w.WriteHeader(scriptStatus)
				w.Write([]byte(scriptBody))
			case cliJarPath:
				w.WriteHeader(200)
			default:
				w.Write([]byte("<html>Jenkins</html>"))
			}
		}
	}

	t.Run("secure_default_not_likely", func(t *testing.T) {
		s := httptest.NewServer(handler(403, "Forbidden"))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		f := NewAnonScriptConsole(client).Check(context.Background(), target)
		if f.Verdict == model.VerdictLikely || f.Verdict == model.VerdictConfirmed {
			t.Fatalf("secure default must not elevate, got %s/%s", f.Verdict, f.Reason)
		}
		if f.Verdict != model.VerdictDetected || f.Reason != "script_console_protected" {
			t.Errorf("got %s/%s, want detected/script_console_protected", f.Verdict, f.Reason)
		}
	})

	t.Run("open_console_reaches_likely", func(t *testing.T) {
		s := httptest.NewServer(handler(200, realConsole))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		f := NewAnonScriptConsole(client).Check(context.Background(), target)
		if f.Verdict != model.VerdictLikely || f.Reason != "anonymous_script_console_exposed" {
			t.Fatalf("got %s/%s, want likely/anonymous_script_console_exposed", f.Verdict, f.Reason)
		}
	})
}
