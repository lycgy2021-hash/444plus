package netscaler

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
	p, _ := policy.New(model.ModePassive, nil)
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

// nsServer serves root/vpn/aaa bodies independently, so different service faces
// can be simulated.
func nsServer(t *testing.T, root, vpn, aaa string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vpn/index.html":
			_, _ = w.Write([]byte(vpn))
		case "/logon/LogonPoint/tmindex.html":
			_, _ = w.Write([]byte(aaa))
		default:
			_, _ = w.Write([]byte(root))
		}
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestNetScalerLadder(t *testing.T) {
	nsRoot := `<html>NetScaler AAA</html>`
	gatewayVPN := `<html>Citrix Gateway /vpn/js/gateway_login_form_view.js NS14.1 47.46</html>`
	aaaPage := `<html>LogonPoint /nf/auth doAuthentication NS13.1-FIPS 37.240</html>`
	cases := []struct {
		name           string
		root, vpn, aaa string
		want           model.Verdict
		reason         string
	}{
		// (1) generic Citrix, not NetScaler -> not_found
		{"citrix_not_netscaler", `<html>Citrix Workspace login</html>`, "", "", model.VerdictNotFound, "product_not_netscaler"},
		// (2) NetScaler fingerprint but no version -> unknown
		{"ns_no_version", `<html>NetScaler _ctxstxt</html>`, "", "", model.VerdictUnknown, "version_unknown"},
		// (3) affected version, no service face -> detected
		{"affected_detected", `<html>NetScaler NS14.1 47.46</html>`, "", "", model.VerdictDetected, "affected_version"},
		// (4) affected + Gateway exposed -> likely
		{"gateway_likely", nsRoot, gatewayVPN, "", model.VerdictLikely, "affected_service_exposed"},
		// (5) affected + AAA exposed -> likely
		{"aaa_likely", nsRoot, "", aaaPage, model.VerdictLikely, "affected_service_exposed"},
		// (6) affected version but no affected service face -> detected
		{"affected_no_face", `<html>NetScaler NS13.1 59.20</html>`, "", "", model.VerdictDetected, "affected_version"},
		// (7) fixed version -> not_found
		{"fixed_not_found", `<html>NetScaler NS14.1 47.48</html>`, "", "", model.VerdictNotFound, "version_not_affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := nsServer(t, tc.root, tc.vpn, tc.aaa)
			client, target := clientFor(t, url)
			f := NewCVE20257775(client).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("NetScaler advisory must not confirm")
			}
		})
	}
}

// Independent fix lines: same version, same product, different CVE verdicts.
// Proves the rules are per-CVE, not "old NetScaler = every CVE fires".
func TestIndependentFixLines(t *testing.T) {
	cases := []struct {
		version string
		aff6543 bool
		aff7775 bool
	}{
		{"NS14.1 47.45", true, true},        // both affected
		{"NS14.1 47.46", false, true},       // 6543 fixed, 7775 still affected
		{"NS14.1 47.47", false, true},       // 6543 fixed, 7775 still affected
		{"NS14.1 47.48", false, false},      // both fixed
		{"NS12.1-FIPS 55.320", false, true}, // 6543 does not affect 12.1-FIPS; 7775 does
		{"NS13.1-FIPS 37.238", false, true}, // 6543 fixed (>=37.236), 7775 affected (<37.241)
	}
	for _, tc := range cases {
		v, ok := parseVersion(tc.version)
		if !ok {
			t.Fatalf("parse %q failed", tc.version)
		}
		if got := affected(v, affected6543); got != tc.aff6543 {
			t.Errorf("%s: 6543 affected=%v want %v", tc.version, got, tc.aff6543)
		}
		if got := affected(v, affected7775); got != tc.aff7775 {
			t.Errorf("%s: 7775 affected=%v want %v", tc.version, got, tc.aff7775)
		}
	}
}

// (9) version-branch boundaries across product lines.
func TestNetScalerBranchBoundaries(t *testing.T) {
	cases := []struct {
		s   string
		aff bool
	}{
		{"NS14.1 47.46", true},        // < 47.48
		{"NS14.1 47.48", false},       // fixed
		{"NS13.1-FIPS 37.240", true},  // < 37.241
		{"NS13.1-FIPS 37.241", false}, // fixed
		{"NS12.1-NDcPP 55.320", true}, // < 55.330
		{"12.1-49.23", true},          // 12.1 EOL, always affected
		{"NS14.1 48.10", false},       // beyond fix on 14.1
	}
	for _, tc := range cases {
		v, ok := parseVersion(tc.s)
		if !ok {
			t.Fatalf("parseVersion(%q) failed", tc.s)
		}
		if got := affected(v, affected7775); got != tc.aff {
			t.Errorf("affected(%q=%+v) = %v, want %v", tc.s, v, got, tc.aff)
		}
	}
}
