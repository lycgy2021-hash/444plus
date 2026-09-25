package ingressnginx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

func clientFor(t *testing.T, url string, mode model.Mode) (*httpx.Client, model.Target) {
	t.Helper()
	p, err := policy.New(mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.InsecureTLS = true // lab admission webhooks use self-signed certs
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

func TestAdmissionProbeVerdicts(t *testing.T) {
	cases := []struct {
		name   string
		mode   model.Mode
		expose bool
		want   model.Verdict
		reason string
	}{
		{"exposed", model.ModeActiveProbe, true, model.VerdictLikely, "admission_webhook_exposed"},
		{"refused", model.ModeActiveProbe, false, model.VerdictNotFound, "webhook_not_reachable"},
		{"passive", model.ModePassive, true, model.VerdictUnknown, "requires_active_probe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != admissionPath || r.Method != http.MethodPost {
					w.WriteHeader(404)
					return
				}
				if !tc.expose {
					w.WriteHeader(401)
					return
				}
				body, _ := io.ReadAll(r.Body)
				uid := "unknown"
				if i := strings.Index(string(body), `"uid":"`); i >= 0 {
					rest := string(body)[i+7:]
					if j := strings.Index(rest, `"`); j >= 0 {
						uid = rest[:j]
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","response":{"uid":"` + uid + `","allowed":true}}`))
			}))
			defer s.Close()
			client, target := clientFor(t, s.URL, tc.mode)
			f := NewCVE20251974(client, tc.mode).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got verdict=%s reason=%s, want verdict=%s reason=%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
		})
	}
}

// Regression: the real ingress-nginx v1.11.2 webhook returns whitespace-formatted
// JSON that echoes the request and carries response.uid. An exact substring match
// missed it; the JSON-parsing check must recognize it.
func TestIsAdmissionReviewRealFormat(t *testing.T) {
	uid := "a0c992addd1f673627c270a989a1b0c5"
	real := `{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": { "uid": "` + uid + `" },
  "response": { "uid": "` + uid + `", "allowed": true }
}`
	if !isAdmissionReview(real, uid) {
		t.Fatal("real pretty-printed AdmissionReview not recognized")
	}
	if isAdmissionReview(real, "other-uid") {
		t.Fatal("must require our echoed uid")
	}
	if isAdmissionReview(`{"message":"not found"}`, uid) {
		t.Fatal("non-admission body accepted")
	}
}

// The benign probe must carry no annotations (the injection vector) and no rules.
func TestProbeBodyIsBenign(t *testing.T) {
	if strings.Contains(benignReview, "annotations") || strings.Contains(benignReview, "nginx.ingress.kubernetes.io") {
		t.Fatal("probe body must not contain annotations")
	}
	if !strings.Contains(benignReview, `"rules":[]`) {
		t.Fatal("probe body must define an empty ingress spec")
	}
}
