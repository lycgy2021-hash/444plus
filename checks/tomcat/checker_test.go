package tomcat

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

// tomcatServer serves a version banner on GET and an Allow header on OPTIONS.
func tomcatServer(t *testing.T, banner string, writable bool, coyote bool) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if coyote {
			w.Header().Set("Server", "Apache-Coyote/1.1")
		}
		if r.Method == http.MethodOptions {
			if writable {
				w.Header().Set("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE")
			} else {
				w.Header().Set("Allow", "OPTIONS, GET, HEAD, POST")
			}
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
		if banner != "" {
			_, _ = w.Write([]byte("<h1>HTTP Status 404</h1><h3>" + banner + "</h3>"))
		} else {
			_, _ = w.Write([]byte("not found"))
		}
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestTomcatLadder(t *testing.T) {
	cases := []struct {
		name     string
		banner   string
		writable bool
		coyote   bool
		want     model.Verdict
		reason   string
	}{
		{"not_tomcat", "", false, false, model.VerdictNotFound, "product_not_tomcat"},
		{"version_unknown", "", false, true, model.VerdictUnknown, "version_unknown"}, // coyote header, no banner
		{"not_affected", "Apache Tomcat/9.0.99", false, true, model.VerdictNotFound, "version_not_affected"},
		{"detected", "Apache Tomcat/9.0.97", false, true, model.VerdictDetected, "affected_version"},
		{"likely", "Apache Tomcat/9.0.97", true, true, model.VerdictLikely, "writable_default_servlet"},
		{"detected_1013x", "Apache Tomcat/10.1.34", false, true, model.VerdictDetected, "affected_version"},
		{"not_affected_1013x", "Apache Tomcat/10.1.35", false, true, model.VerdictNotFound, "version_not_affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := tomcatServer(t, tc.banner, tc.writable, tc.coyote)
			client, target := clientFor(t, url)
			f := NewCVE202524813(client).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("CVE-2025-24813 must not confirm (no deserialization/RCE attempted)")
			}
		})
	}
}
