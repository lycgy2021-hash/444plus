package fortinet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// server serves a fingerprint body at "/" and, when exposeMgmt is set, a Fortinet
// login surface at the management paths (otherwise 404).
func server(t *testing.T, rootBody string, exposeMgmt bool) string {
	t.Helper()
	mgmt := map[string]bool{"/remote/login": true, "/login": true, "/admin": true}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(rootBody))
			return
		}
		if mgmt[r.URL.Path] && exposeMgmt {
			_, _ = w.Write([]byte(`<html>fgt_lang login</html>`))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestFortinetVerdictLadder(t *testing.T) {
	fortiOS7016 := `<html><title>FortiGate</title> fgt_lang "version":"7.0.16"</html>`
	cases := []struct {
		name       string
		newChecker func(httpx.Probe) *advisoryChecker
		rootBody   string
		exposeMgmt bool
		want       model.Verdict
		reason     string
	}{
		{"not_fortinet", NewCVE202455591, `<html>nginx welcome</html>`, false, model.VerdictNotFound, "product_not_fortinet"},
		{"unclassified", NewCVE202455591, `<html>logindisclaimer fortinet</html>`, false, model.VerdictUnknown, "product_unclassified"},
		{"out_of_scope", NewCVE202455591, `<html>FortiMail login "version":"7.6.2"</html>`, true, model.VerdictNotFound, "product_out_of_scope"},
		{"version_unknown", NewCVE202455591, `<html>FortiGate fgt_lang login</html>`, true, model.VerdictUnknown, "version_unknown"},
		{"not_affected", NewCVE202455591, `<html>FortiGate fgt_lang "version":"7.2.0"</html>`, true, model.VerdictNotFound, "version_not_affected"},
		{"detected", NewCVE202455591, fortiOS7016, false, model.VerdictDetected, "affected_version"},
		{"likely", NewCVE202455591, fortiOS7016, true, model.VerdictLikely, "affected_and_exposed"},
		{"32756_mail_likely", NewCVE202532756, `<html>FortiMail "version":"7.6.2"</html>`, true, model.VerdictLikely, "affected_and_exposed"},
		{"32756_mail_fixed", NewCVE202532756, `<html>FortiMail "version":"7.6.3"</html>`, true, model.VerdictNotFound, "version_not_affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := server(t, tc.rootBody, tc.exposeMgmt)
			client, target := clientFor(t, url)
			f := tc.newChecker(client).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got verdict=%s reason=%s, want verdict=%s reason=%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			// These advisories must never reach confirmed.
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("fortinet advisory must not confirm")
			}
		})
	}
}

func TestAffectedRangeLookup(t *testing.T) {
	cases := []struct {
		product, version string
		ranges           []AffectedRange
		want             bool
	}{
		{"FortiOS", "7.0.16", FGIR24535, true},
		{"FortiOS", "7.0.17", FGIR24535, false},
		{"FortiOS", "7.2.0", FGIR24535, false},
		{"FortiProxy", "7.2.12", FGIR24535, true},
		{"FortiProxy", "7.0.20", FGIR24535, false},
		{"FortiMail", "7.6.2", FGIR25254, true},
		{"FortiMail", "7.6.3", FGIR25254, false},
		{"FortiVoice", "7.2.0", FGIR25254, true},
		{"FortiCamera", "2.0.5", FGIR25254, true}, // "all 2.0.x" branch
	}
	for _, tc := range cases {
		if got, _ := affected(tc.ranges, tc.product, tc.version); got != tc.want {
			t.Errorf("affected(%s %s) = %v, want %v", tc.product, tc.version, got, tc.want)
		}
	}
}

// Guard against markers accidentally matching non-Fortinet pages.
func TestFingerprintPrecision(t *testing.T) {
	if _, ok := fingerprint("<html>welcome to nginx</html>"); ok {
		t.Fatal("nginx page fingerprinted as Fortinet")
	}
	if p, ok := fingerprint(strings.ToLower("<title>FortiMail</title>")); !ok || p != "FortiMail" {
		t.Fatalf("FortiMail not classified: %q %v", p, ok)
	}
}
