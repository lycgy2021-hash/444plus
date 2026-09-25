package sharepoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

func clientFor(t *testing.T, url string) (*httpx.Client, model.Target) {
	t.Helper()
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	c, err := httpx.New(opts, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	target, err := model.ParseTarget(url)
	if err != nil {
		t.Fatal(err)
	}
	return c, target
}

// spServer serves start.aspx with an optional build header/body marker and a
// ToolPane.aspx whose status is configurable (0 = 404 not present).
func spServer(t *testing.T, sharePoint bool, build string, toolPaneStatus int) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_layouts/15/start.aspx":
			if sharePoint {
				if build != "" {
					w.Header().Set("MicrosoftSharePointTeamServices", build)
				}
				_, _ = w.Write([]byte(`<html>_spPageContextInfo /_layouts/15/ SharePoint</html>`))
			} else {
				w.Header().Set("Server", "Microsoft-IIS/10.0")
				w.Header().Set("X-Powered-By", "ASP.NET")
				_, _ = w.Write([]byte(`<html>plain IIS site</html>`))
			}
		case toolShellPath:
			if toolPaneStatus == 0 {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(toolPaneStatus)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestToolShellLadder(t *testing.T) {
	cases := []struct {
		name     string
		sp       bool
		build    string
		toolPane int
		want     model.Verdict
		reason   string
	}{
		{"not_sharepoint", false, "", 200, model.VerdictNotFound, "product_not_sharepoint"},
		{"build_unknown", true, "", 200, model.VerdictUnknown, "build_unknown"},
		{"patched_2019", true, "16.0.10417.20037", 200, model.VerdictNotFound, "patched"},
		{"detected_2019", true, "16.0.10417.20020", 0, model.VerdictDetected, "affected_build"},
		{"likely_2019", true, "16.0.10417.20020", 200, model.VerdictLikely, "toolshell_surface_exposed"},
		{"likely_SE_gated", true, "16.0.18526.20400", 401, model.VerdictLikely, "toolshell_surface_exposed"},
		{"patched_SE", true, "16.0.18526.20508", 200, model.VerdictNotFound, "patched"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := spServer(t, tc.sp, tc.build, tc.toolPane)
			client, target := clientFor(t, url)
			f := NewCVE202553770(client).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got verdict=%s reason=%s, want %s/%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("ToolShell must not confirm")
			}
		})
	}
}

func TestBuildParseAndLine(t *testing.T) {
	cases := []struct {
		s    string
		ok   bool
		line string
		aff  bool
	}{
		{"16.0.10417.20020", true, "2019", true},
		{"16.0.10417.20037", true, "2019", false}, // exactly fixed
		{"16.0.5513.1000", true, "2016", true},
		{"16.0.5513.1001", true, "2016", false},
		{"16.0.18526.20400", true, "SE", true},
		{"16.0.0.10417", false, "", false}, // ambiguous header form: no revision
		{"nginx/1.2.3", false, "", false},
	}
	for _, tc := range cases {
		b, ok := parseBuild(tc.s)
		if ok != tc.ok {
			t.Fatalf("parseBuild(%q) ok=%v want %v", tc.s, ok, tc.ok)
		}
		if !ok {
			continue
		}
		aff, ln, _ := affectedBuild(b)
		if ln != tc.line || aff != tc.aff {
			t.Errorf("affectedBuild(%q) = line %q aff %v, want %q %v", tc.s, ln, aff, tc.line, tc.aff)
		}
	}
}
