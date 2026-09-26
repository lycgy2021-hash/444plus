package papercut

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

// mockProbe drives the ladder without a live PaperCut. Only Get is used by the
// assessment; it routes by path to the configured login / SetupCompleted bodies.
type mockProbe struct {
	loginStatus int
	loginBody   string
	setupStatus int
	setupBody   string
}

func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{StatusCode: 200, Headers: map[string]string{}}, nil
}
func (m mockProbe) Get(_ context.Context, _ model.Target, path string) (httpx.Response, error) {
	switch path {
	case loginPath:
		st := m.loginStatus
		if st == 0 {
			st = 200
		}
		return httpx.Response{StatusCode: st, Body: []byte(m.loginBody), Headers: map[string]string{}}, nil
	case setupCompletedPath:
		st := m.setupStatus
		if st == 0 {
			st = 200
		}
		return httpx.Response{StatusCode: st, Body: []byte(m.setupBody), Headers: map[string]string{}}, nil
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

// Trimmed to the exact markers of the live MF 22.0.7 pages.
const loginIdentity = `<title>PaperCut Login</title>` +
	`<link rel="stylesheet" href="/css/style.css?66714papercut-mf" />`

// setupPage renders the SetupCompleted markers + the product version span, as the
// live affected server does (the access-control bypass rendering).
func setupPage(version string) string {
	return `<!-- Application: app-server --><!-- Page: SetupCompleted -->` +
		`<title>Configuration Wizard : Setup Complete</title>` +
		`<link rel="stylesheet" href="/css/style.css?64927papercut-mf" />` +
		`<div class="text"><span class="product">PaperCut MF</span>` +
		`<span>` + version + `</span><span>(Build 64927</span></div>` +
		`Copyright 1999-2026. PaperCut Software Pty Ltd.`
}

func TestCVE20232735Ladder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:9191")
	cases := []struct {
		name    string
		probe   mockProbe
		want    model.Verdict
		reason  string
		version string
	}{
		{
			name:   "not_papercut",
			probe:  mockProbe{loginBody: `<html>generic login</html>`, setupBody: `<html>nope</html>`},
			want:   model.VerdictNotFound,
			reason: "product_not_papercut",
		},
		{
			// Only one signal (bare title) — must not identify the product.
			name:   "single_weak_signal",
			probe:  mockProbe{loginBody: `<title>PaperCut</title>`, setupStatus: 404},
			want:   model.VerdictNotFound,
			reason: "product_not_papercut",
		},
		{
			name:    "affected_setup_rendered_likely",
			probe:   mockProbe{loginBody: loginIdentity, setupStatus: 200, setupBody: setupPage("22.0.7")},
			want:    model.VerdictLikely,
			reason:  "setup_completed_bypass_exposed",
			version: "22.0.7",
		},
		{
			name:    "fixed_patched_redirect_not_found",
			probe:   mockProbe{loginBody: loginIdentity, setupStatus: 302, setupBody: ""},
			want:    model.VerdictNotFound,
			reason:  "patched_setup_access_control",
			version: "",
		},
		{
			// Identity holds and SetupCompleted 200s, but no version span and not the
			// real setup page: must lock to unknown, never elevate.
			name:   "identity_surface_no_version_unknown",
			probe:  mockProbe{loginBody: loginIdentity, setupStatus: 200, setupBody: `<!-- Application: app-server --> some page, no version span`},
			want:   model.VerdictUnknown,
			reason: "version_unknown",
		},
		{
			// Version in range but the page isn't confirmed as the rendered setup
			// bypass (no setup-page marker): version match only -> detected.
			name:    "affected_version_surface_unconfirmed_detected",
			probe:   mockProbe{loginBody: loginIdentity, setupStatus: 200, setupBody: `<div class="text"><span class="product">PaperCut MF</span><span>22.0.7</span></div>`},
			want:    model.VerdictDetected,
			reason:  "affected_version",
			version: "22.0.7",
		},
		{
			// A rendered setup page whose version is at/above the fix line -> not affected.
			name:    "fixed_version_span_not_affected",
			probe:   mockProbe{loginBody: loginIdentity, setupStatus: 200, setupBody: setupPage("22.0.9")},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "22.0.9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewCVE20232735(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %s", f.Verdict, f.Reason, tc.want, tc.reason, f.Evidence.Message)
			}
			if tc.version != "" && f.Evidence.Version != tc.version {
				t.Errorf("version = %q, want %q", f.Evidence.Version, tc.version)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("this checker must never confirm (caps at likely; read-only, no exploit)")
			}
		})
	}
}

// TestVersionBoundary pins the three documented fix lines directly.
func TestVersionBoundary(t *testing.T) {
	cases := []struct {
		v        pcVersion
		affected bool
	}{
		{pcVersion{8, 0, 0}, true},   // "8.0 or later" lower edge
		{pcVersion{18, 3, 0}, true},  // old, affected
		{pcVersion{19, 2, 7}, true},  // pre-20, affected
		{pcVersion{20, 0, 9}, true},  // 20.0.x affected
		{pcVersion{20, 1, 6}, true},  // last affected on 20.1
		{pcVersion{20, 1, 7}, false}, // fixed
		{pcVersion{20, 2, 0}, false}, // above fix
		{pcVersion{21, 0, 0}, true},  // 21.0.x affected
		{pcVersion{21, 2, 10}, true}, // last affected on 21.2
		{pcVersion{21, 2, 11}, false},// fixed
		{pcVersion{21, 3, 0}, false},
		{pcVersion{22, 0, 8}, true},  // last affected on 22.0
		{pcVersion{22, 0, 9}, false}, // fixed
		{pcVersion{22, 1, 0}, false}, // 22.1 branch carries the fix
		{pcVersion{22, 1, 1}, false},
		{pcVersion{23, 0, 0}, false}, // not affected
		{pcVersion{24, 0, 2}, false},
	}
	for _, tc := range cases {
		if got := affectedCVE20232735(tc.v); got != tc.affected {
			t.Errorf("affected(%s) = %v, want %v", tc.v, got, tc.affected)
		}
	}
}

func TestParseProductVersion(t *testing.T) {
	if v, raw, ok := parseProductVersion([]byte(setupPage("22.0.7"))); !ok || raw != "22.0.7" || v != (pcVersion{22, 0, 7}) {
		t.Fatalf("parse live-shaped setup page: %v %q %v", v, raw, ok)
	}
	for _, body := range []string{``, `<html>no product block</html>`, `class="product"> no span here`} {
		if _, _, ok := parseProductVersion([]byte(body)); ok {
			t.Errorf("parseProductVersion(%q) unexpectedly ok", body)
		}
	}
}

// TestRealServerTwoState exercises the checker end-to-end through a real
// httpx.Client (with the query-path support) and HTTP server replicating
// PaperCut: affected renders SetupCompleted (200 + version) -> likely; fixed
// redirects it away -> not_found.
func TestRealServerTwoState(t *testing.T) {
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

	handler := func(affected bool, version string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch r.RequestURI {
			case loginPath:
				w.Write([]byte(loginIdentity))
			case setupCompletedPath:
				if affected {
					w.Write([]byte(setupPage(version)))
					return
				}
				http.Redirect(w, r, "/app?service=page/Home", 302)
			default:
				w.Write([]byte(`<html>PaperCut</html>`))
			}
		}
	}
	run := func(t *testing.T, affected bool, version string) model.Finding {
		s := httptest.NewServer(handler(affected, version))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		return NewCVE20232735(client).Check(context.Background(), target)
	}

	t.Run("affected_reaches_likely", func(t *testing.T) {
		f := run(t, true, "22.0.7")
		if f.Verdict != model.VerdictLikely || f.Reason != "setup_completed_bypass_exposed" {
			t.Fatalf("got %s/%s, want likely/setup_completed_bypass_exposed: %s", f.Verdict, f.Reason, f.Evidence.Message)
		}
	})
	t.Run("fixed_stays_not_found", func(t *testing.T) {
		f := run(t, false, "")
		if f.Verdict != model.VerdictNotFound || f.Reason != "patched_setup_access_control" {
			t.Fatalf("got %s/%s, want not_found/patched_setup_access_control", f.Verdict, f.Reason)
		}
	})
}
