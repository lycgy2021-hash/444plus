package gitlab

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

// mockProbe drives the ladders without a live GitLab. Fingerprint returns the
// configured headers (X-Gitlab-Meta is signal 1); Get routes by path to the
// configured per-endpoint bodies (sign-in markers = signal 2, /help = version,
// /users/password/new = reset surface).
type mockProbe struct {
	fpHeaders    map[string]string
	signInBody   string
	signInErr    error
	helpBody     string
	resetBody    string
	resetStatus  int // default 200 when a resetBody is set
	manifestBody string
}

func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{StatusCode: 200, Headers: canonicalHeaders(m.fpHeaders)}, nil
}

func (m mockProbe) Get(_ context.Context, _ model.Target, path string) (httpx.Response, error) {
	switch path {
	case signInPath:
		if m.signInErr != nil {
			return httpx.Response{}, m.signInErr
		}
		return httpx.Response{StatusCode: 200, Body: []byte(m.signInBody), Headers: map[string]string{}}, nil
	case helpPath:
		return httpx.Response{StatusCode: 200, Body: []byte(m.helpBody), Headers: map[string]string{}}, nil
	case resetNewPath:
		st := m.resetStatus
		if st == 0 {
			st = 200
		}
		return httpx.Response{StatusCode: st, Body: []byte(m.resetBody), Headers: map[string]string{}}, nil
	case manifestPath:
		return httpx.Response{StatusCode: 200, Body: []byte(m.manifestBody), Headers: map[string]string{}}, nil
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

// The exact markers of the live 16.6.0 pages, trimmed to what the matchers need.
const signInGitLab = `<!DOCTYPE html><title>Sign in · GitLab</title>` +
	`<meta content="GitLab" property="og:site_name">` +
	`<meta name="csrf-param" content="authenticity_token" />` +
	`<h1>GitLab Community Edition</h1><body data-qa-selector="login_page"></body>`

const resetFormLive = `<form class="gl-p-5" id="new_user" action="/users/password" accept-charset="UTF-8" method="post">` +
	`<input required="required" type="email" name="user[email]" id="user_email" />` +
	`<button type="submit">Reset password</button></form>`

const manifestLive = `{"name": "GitLab","short_name": "GitLab"}`

// helpVersion renders the /help gon fragment, HTML-entity-escaped exactly as
// GitLab serves it, for the given version.
func helpVersion(major, minor, patch int) string {
	return `<script>gon={};</script>` +
		`&quot;gitlab_version&quot;:{&quot;major&quot;:` + itoa(major) +
		`,&quot;minor&quot;:` + itoa(minor) +
		`,&quot;patch&quot;:` + itoa(patch) +
		`,&quot;suffix_s&quot;:&quot;&quot;}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// gitlabHeaders is the meta header a real GitLab always sends.
func gitlabHeaders() map[string]string {
	return map[string]string{"X-Gitlab-Meta": `{"correlation_id":"01ABC","version":"1"}`, "Server": "nginx"}
}

func TestCVE20237028Ladder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8929")
	cases := []struct {
		name    string
		probe   mockProbe
		want    model.Verdict
		reason  string
		version string
	}{
		{
			name:   "not_gitlab",
			probe:  mockProbe{fpHeaders: map[string]string{"Server": "nginx"}, signInBody: `<html>generic login</html>`},
			want:   model.VerdictNotFound,
			reason: "product_not_gitlab",
		},
		{
			// A single forged X-Gitlab-Meta with a non-GitLab body must NOT identify
			// the product (≥2 signals), even with an affected-looking /help version.
			name:   "single_forged_meta_header",
			probe:  mockProbe{fpHeaders: gitlabHeaders(), signInBody: `<html>not really gitlab</html>`, helpBody: helpVersion(16, 6, 0), resetBody: resetFormLive},
			want:   model.VerdictNotFound,
			reason: "product_not_gitlab",
		},
		{
			// GitLab identified but /help gave no version: affected status unknown.
			name:   "version_unknown",
			probe:  mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: `<html>help, no gon version</html>`, resetBody: resetFormLive},
			want:   model.VerdictUnknown,
			reason: "version_unknown",
		},
		{
			name:    "affected_reset_reachable_likely",
			probe:   mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: helpVersion(16, 6, 0), resetBody: resetFormLive},
			want:    model.VerdictLikely,
			reason:  "affected_surface_exposed",
			version: "16.6.0",
		},
		{
			// Affected version but the reset flow is not reachable (redirected/disabled).
			name:    "affected_reset_unreachable_detected",
			probe:   mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: helpVersion(16, 7, 1), resetStatus: 302},
			want:    model.VerdictDetected,
			reason:  "affected_version",
			version: "16.7.1",
		},
		{
			name:    "fixed_not_affected",
			probe:   mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: helpVersion(16, 6, 4), resetBody: resetFormLive},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "16.6.4",
		},
		{
			// Product identified by body markers alone + manifest tiebreaker (meta
			// header stripped by a proxy) still reaches the two-signal lock.
			name:    "proxy_stripped_header_manifest_tiebreak",
			probe:   mockProbe{fpHeaders: map[string]string{"Server": "cloudflare"}, signInBody: signInGitLab, manifestBody: manifestLive, helpBody: helpVersion(16, 5, 5), resetBody: resetFormLive},
			want:    model.VerdictLikely,
			reason:  "affected_surface_exposed",
			version: "16.5.5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewCVE20237028(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %s", f.Verdict, f.Reason, tc.want, tc.reason, f.Evidence.Message)
			}
			if tc.version != "" && f.Evidence.Version != tc.version {
				t.Errorf("version = %q, want %q", f.Evidence.Version, tc.version)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("this checker must never confirm (caps at likely; the reset is never submitted)")
			}
		})
	}
}

func TestCVE20232825Ladder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8929")
	cases := []struct {
		name    string
		probe   mockProbe
		want    model.Verdict
		reason  string
		version string
	}{
		{
			name:    "exactly_16_0_0_detected",
			probe:   mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: helpVersion(16, 0, 0), resetBody: resetFormLive},
			want:    model.VerdictDetected,
			reason:  "affected_version",
			version: "16.0.0",
		},
		{
			name:    "16_0_1_fixed",
			probe:   mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: helpVersion(16, 0, 1)},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "16.0.1",
		},
		{
			name:    "16_6_0_not_affected_by_this_cve",
			probe:   mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: helpVersion(16, 6, 0)},
			want:    model.VerdictNotFound,
			reason:  "version_not_affected",
			version: "16.6.0",
		},
		{
			name:   "version_unknown",
			probe:  mockProbe{fpHeaders: gitlabHeaders(), signInBody: signInGitLab, helpBody: `<html>no version</html>`},
			want:   model.VerdictUnknown,
			reason: "version_unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewCVE20232825(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %s", f.Verdict, f.Reason, tc.want, tc.reason, f.Evidence.Message)
			}
			if tc.version != "" && f.Evidence.Version != tc.version {
				t.Errorf("version = %q, want %q", f.Evidence.Version, tc.version)
			}
			// Version-only: it must never elevate above detected.
			if f.Verdict == model.VerdictLikely || f.Verdict == model.VerdictConfirmed {
				t.Fatalf("CVE-2023-2825 must cap at detected, got %s", f.Verdict)
			}
		})
	}
}

// TestVersionBoundary pins the documented fix lines directly against the
// affected predicates — the regression钉子 for every 16.x branch.
func TestVersionBoundary(t *testing.T) {
	cve7028 := []struct {
		v        glVersion
		affected bool
	}{
		{glVersion{16, 0, 0}, false}, // introduced in 16.1.0; 16.0.x not affected
		{glVersion{16, 0, 5}, false},
		{glVersion{16, 1, 0}, true}, // first affected
		{glVersion{16, 1, 5}, true}, // last affected on 16.1
		{glVersion{16, 1, 6}, false},
		{glVersion{16, 2, 8}, true},
		{glVersion{16, 2, 9}, false},
		{glVersion{16, 3, 6}, true},
		{glVersion{16, 3, 7}, false},
		{glVersion{16, 4, 4}, true},
		{glVersion{16, 4, 5}, false},
		{glVersion{16, 5, 5}, true},
		{glVersion{16, 5, 6}, false},
		{glVersion{16, 6, 3}, true},
		{glVersion{16, 6, 4}, false},
		{glVersion{16, 7, 1}, true}, // last affected overall
		{glVersion{16, 7, 2}, false},
		{glVersion{16, 8, 0}, false}, // upper edge: 16.8+ not affected
		{glVersion{15, 11, 13}, false},
		{glVersion{17, 0, 0}, false},
	}
	for _, tc := range cve7028 {
		if got := affectedCVE20237028(tc.v); got != tc.affected {
			t.Errorf("CVE-2023-7028 affected(%s) = %v, want %v", tc.v, got, tc.affected)
		}
	}

	cve2825 := []struct {
		v        glVersion
		affected bool
	}{
		{glVersion{16, 0, 0}, true}, // the only affected version
		{glVersion{16, 0, 1}, false},
		{glVersion{16, 1, 0}, false},
		{glVersion{15, 11, 0}, false},
		{glVersion{16, 0, 2}, false},
	}
	for _, tc := range cve2825 {
		if got := affectedCVE20232825(tc.v); got != tc.affected {
			t.Errorf("CVE-2023-2825 affected(%s) = %v, want %v", tc.v, got, tc.affected)
		}
	}
}

// TestParseVersionFromHelp covers the anonymous version source and its failure
// mode (absent gon → not ok → caller reports unknown).
func TestParseVersionFromHelp(t *testing.T) {
	if v, raw, ok := parseVersionFromHelp([]byte(helpVersion(16, 6, 0))); !ok || raw != "16.6.0" || v != (glVersion{16, 6, 0}) {
		t.Fatalf("parse live-shaped help: got %v %q %v", v, raw, ok)
	}
	for _, body := range []string{``, `<html>help index, no version</html>`, `"gitlab_version":{"major":16}`} {
		if _, _, ok := parseVersionFromHelp([]byte(body)); ok {
			t.Errorf("parseVersionFromHelp(%q) unexpectedly ok", body)
		}
	}
}

// TestRealServerTwoState exercises the checker end-to-end through a real
// httpx.Client and HTTP server that replicates GitLab's responses: an affected
// version with the reset flow live must reach `likely`; a fixed version must stay
// not_found; and a GitLab that hides /help (version unreadable) must stay unknown.
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

	// helpBody empty => /help serves no version (simulates restricted access).
	handler := func(helpBody string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Gitlab-Meta", `{"correlation_id":"01XYZ","version":"1"}`)
			switch r.URL.Path {
			case signInPath:
				w.Write([]byte(signInGitLab))
			case helpPath:
				if helpBody == "" {
					http.Redirect(w, r, signInPath, 302)
					return
				}
				w.Write([]byte(helpBody))
			case resetNewPath:
				w.Write([]byte(resetFormLive))
			case manifestPath:
				w.Write([]byte(manifestLive))
			default:
				w.Write([]byte(`<html>GitLab</html>`))
			}
		}
	}

	run := func(t *testing.T, helpBody string) model.Finding {
		s := httptest.NewServer(handler(helpBody))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		return NewCVE20237028(client).Check(context.Background(), target)
	}

	t.Run("affected_reaches_likely", func(t *testing.T) {
		f := run(t, helpVersion(16, 6, 0))
		if f.Verdict != model.VerdictLikely || f.Reason != "affected_surface_exposed" {
			t.Fatalf("got %s/%s, want likely/affected_surface_exposed: %s", f.Verdict, f.Reason, f.Evidence.Message)
		}
	})
	t.Run("fixed_stays_not_found", func(t *testing.T) {
		f := run(t, helpVersion(16, 6, 4))
		if f.Verdict != model.VerdictNotFound || f.Reason != "version_not_affected" {
			t.Fatalf("got %s/%s, want not_found/version_not_affected", f.Verdict, f.Reason)
		}
	})
	t.Run("version_hidden_stays_unknown", func(t *testing.T) {
		f := run(t, "")
		if f.Verdict != model.VerdictUnknown || f.Reason != "version_unknown" {
			t.Fatalf("got %s/%s, want unknown/version_unknown", f.Verdict, f.Reason)
		}
	})
}
