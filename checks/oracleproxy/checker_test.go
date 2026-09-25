package oracleproxy

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

// srv serves "/" with a Server header + body, and "/console" with a routing body.
func srv(t *testing.T, server, rootBody, consoleBody string, wlProxyHeader bool) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		if wlProxyHeader {
			w.Header().Set("WL-Proxy-Client-IP", "10.0.0.1")
		}
		if r.URL.Path == "/console" {
			_, _ = w.Write([]byte(consoleBody))
			return
		}
		_, _ = w.Write([]byte(rootBody))
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestOracleProxyLadder(t *testing.T) {
	cases := []struct {
		name          string
		server        string
		rootBody      string
		consoleBody   string
		wlProxyHeader bool
		mk            func(httpx.Probe) *advisoryChecker
		want          model.Verdict
		reason        string
	}{
		// (3) plain Apache -> not_found  (4) plain IIS -> not_found
		{"plain_apache", "Apache/2.4.58", "<html>It works</html>", "", false, NewCVE202621962, model.VerdictNotFound, "product_not_oracle_proxy"},
		{"plain_iis", "Microsoft-IIS/10.0", "<html>IIS</html>", "", false, NewCVE202621962, model.VerdictNotFound, "product_not_oracle_proxy"},
		// (5) proxy evidence but no version -> unknown (Apache + WL-Proxy header, plugin version not exposed)
		{"apache_proxy_no_version", "Apache/2.4.58", "<html>WebLogic Bridge Message</html>", "", true, NewCVE202621962, model.VerdictUnknown, "version_unknown"},
		// (6) OHS affected version, no routing -> detected
		{"ohs_detected", "Oracle-HTTP-Server/12.2.1.4.0", "<html>ohs</html>", "<html>404</html>", false, NewCVE202621962, model.VerdictDetected, "affected_version"},
		// (7) OHS affected + routing to WebLogic -> likely
		{"ohs_likely", "Oracle-HTTP-Server/12.2.1.4.0", "<html>ohs</html>", "<html>WebLogic Bridge Message</html>", false, NewCVE202621962, model.VerdictLikely, "weblogic_routing_confirmed"},
		// (8) fixed/out-of-scope version -> not_found
		{"ohs_fixed", "Oracle-HTTP-Server/14.1.3.0.0", "<html>ohs</html>", "", false, NewCVE202621962, model.VerdictNotFound, "version_not_affected"},
		// 60364 does not cover OHS front-end (proxy plug-in only) -> OHS 12.2.1.4 out of its per-frontend scope
		{"60364_ohs_out_of_scope", "Oracle-HTTP-Server/12.2.1.4.0", "<html>ohs</html>", "", false, NewCVE202660364, model.VerdictNotFound, "version_not_affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := srv(t, tc.server, tc.rootBody, tc.consoleBody, tc.wlProxyHeader)
			client, target := clientFor(t, url)
			f := tc.mk(client).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			// (9) never confirmed
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("oracle proxy advisory must not confirm")
			}
		})
	}
}
