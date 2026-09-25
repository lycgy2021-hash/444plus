package nginxui

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestRestoreConfirmVerdicts(t *testing.T) {
	backup := `{"scope":"backup","code":4511,"message":"Backup file not found","params":["request Content-Type isn't multipart/form-data"]}`
	cases := []struct {
		name          string
		mode          model.Mode
		restoreStatus int
		restoreBody   string
		controlStatus int // GET /api/settings
		want          model.Verdict
		reason        string
	}{
		// restore reached unauth + auth control rejected -> confirmed
		{"confirmed", model.ModeActiveProbe, 500, backup, 401, model.VerdictConfirmed, "unauthenticated_restore"},
		// restore itself requires auth -> not_found
		{"auth_required", model.ModeActiveProbe, 403, `{"message":"Authorization failed"}`, 401, model.VerdictNotFound, "authentication_required"},
		// restore reached, but control is not a clean auth-required endpoint (500) -> likely
		{"control_broken", model.ModeActiveProbe, 500, backup, 500, model.VerdictLikely, "restore_reachable"},
		// unknown endpoint -> inconclusive
		{"not_nginxui", model.ModeActiveProbe, 404, `{"message":"not found"}`, 404, model.VerdictUnknown, "inconclusive"},
		// passive mode never probes
		{"passive", model.ModePassive, 200, "", 200, model.VerdictUnknown, "requires_active_probe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == restorePath:
					w.WriteHeader(tc.restoreStatus)
					_, _ = w.Write([]byte(tc.restoreBody))
				case r.Method == http.MethodGet && r.URL.Path == authControlPath:
					w.WriteHeader(tc.controlStatus)
					if tc.controlStatus == 401 {
						_, _ = w.Write([]byte(`{"message":"Authorization failed"}`))
					}
				default:
					w.WriteHeader(404)
				}
			}))
			defer s.Close()
			client, target := clientFor(t, s.URL, tc.mode)
			f := NewCVE202642238(client, tc.mode).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got verdict=%s reason=%s, want verdict=%s reason=%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			if tc.want == model.VerdictConfirmed && !f.Evidence.Confirmation.Passed() {
				t.Fatalf("confirmed without a passing confirmation: %+v", f.Evidence.Confirmation)
			}
		})
	}
}

func TestPassiveModeSendsNoRequests(t *testing.T) {
	var reqs int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reqs++ }))
	defer s.Close()
	client, target := clientFor(t, s.URL, model.ModePassive)
	NewCVE202642238(client, model.ModePassive).Check(context.Background(), target)
	if reqs != 0 {
		t.Fatalf("passive mode made %d request(s)", reqs)
	}
}
