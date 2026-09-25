package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
	"gopoc/internal/registry"
)

// Phase A false-positive corpus: adversarial NEGATIVE targets that look
// superficially like a product but are not vulnerable. No checker may elevate any
// of them to likely or confirmed. detected is tolerated but reported for review.
// This is a permanent CI gate: confirmed FP = 0, likely FP = 0.

func runAllCheckers(t *testing.T, mode model.Mode, targetURL string) map[string]model.Finding {
	t.Helper()
	p, err := policy.New(mode, []string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond // corpus targets are local; keep the audit fast
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	reg, err := Builtin(client, mode, model.CanaryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	checkers, err := reg.Select(registry.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := model.ParseTarget(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.Finding{}
	for _, c := range checkers {
		out[c.ID()] = c.Check(context.Background(), target)
	}
	return out
}

// assertNoElevation fails on any likely/confirmed and logs detected for review.
func assertNoElevation(t *testing.T, name string, findings map[string]model.Finding) {
	t.Helper()
	for id, f := range findings {
		switch f.Verdict {
		case model.VerdictConfirmed, model.VerdictLikely:
			t.Errorf("[FP] %s: %s wrongly elevated to %s (%s): %s", name, id, f.Verdict, f.Reason, f.Evidence.Message)
		case model.VerdictDetected:
			t.Logf("[review] %s: %s -> detected (%s)", name, id, f.Reason)
		}
	}
}

func TestFalsePositiveCorpusHTTP(t *testing.T) {
	// Each scenario: a handler for ALL paths, plus optional response headers.
	corpus := []struct {
		name    string
		server  string // Server header
		handler http.HandlerFunc
	}{
		{"nginx_as_apache", "Apache/2.4.49", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body>welcome to nginx</body></html>`))
		}},
		{"plain_iis", "Microsoft-IIS/10.0", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "ASP.NET")
			w.Write([]byte(`<html>IIS Windows Server</html>`))
		}},
		{"citrix_workspace", "", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>Citrix Workspace app download</html>`))
		}},
		{"mentions_weblogic", "", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>Our platform runs on WebLogic and Tomcat internally.</html>`))
		}},
		{"waf_403", "cloudflare", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`<html>Access denied by WAF</html>`))
		}},
		{"spa_200", "", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<!doctype html><html><div id="app">loading</div></html>`))
		}},
		{"bad_500", "", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			w.Write([]byte(`<html>Internal Server Error</html>`))
		}},
		{"proxy_404", "nginx", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
			w.Write([]byte(`<html>404 Not Found</html>`))
		}},
		{"iis_allow_put_no_tomcat", "Microsoft-IIS/10.0", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE")
			}
			w.Write([]byte(`<html>static file server</html>`))
		}},
		{"apache_bridge_word", "Apache/2.4.58", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>our data bridge pipeline failed to sync</html>`))
		}},
		// Adversarial: a generic API whose 500 error mentions multipart/form-data
		// (very common) must not trip the nginx-ui restore detector.
		{"api_500_multipart", "", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"request body must be multipart/form-data"}`))
		}},
		// Adversarial: a server that reflects the request body must not let the
		// ingress AdmissionReview probe see its own request echoed as a response.
		{"reflect_body", "", func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			w.Write(body[:n])
		}},
		// Adversarial: everything requires auth (401) — nothing to elevate.
		{"everything_401", "", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"Authorization failed"}`))
		}},
		// Adversarial: an ordinary, unrelated Digest challenge must not be read as
		// JBoss/WildFly's management interface just because it is a 401.
		{"plain_digest_401", "", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Digest realm="corporate-intranet", qop="auth"`)
			w.WriteHeader(401)
		}},
		// Adversarial: a generic Java admin console must not be fingerprinted as
		// JBoss/WildFly.
		{"generic_java_admin", "Apache-Coyote/1.1", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body><h1>Admin Console</h1><form>Login</form></body></html>`))
		}},
		// Adversarial: the literal string "ManagementRealm" sitting in a page BODY
		// (not a WWW-Authenticate header) must not be mistaken for the real
		// challenge, whatever else the page says.
		{"managementrealm_text_in_body", "", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>Contact support to reset your ManagementRealm password.</html>`))
		}},
		// Adversarial: a forged WildFly welcome page, unsupported by any real
		// management-interface evidence, must never reach likely/confirmed.
		{"fake_wildfly_welcome", "", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body>Welcome to WildFly - powered by our totally unrelated product</body></html>`))
		}},
	}
	for _, tc := range corpus {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.server != "" {
					w.Header().Set("Server", tc.server)
				}
				tc.handler(w, r)
			}))
			defer s.Close()
			// active-probe exercises the POST-based checkers too (the riskiest).
			assertNoElevation(t, tc.name, runAllCheckers(t, model.ModeActiveProbe, s.URL))
		})
	}
}

// A4 verdict-elevation guards: when a product is fingerprinted AND its dangerous
// surface is exposed, but the VERSION cannot be read, the verdict must stay
// `unknown` — never jump to detected/likely on fingerprint+exposure alone.
func TestVerdictElevationGuards(t *testing.T) {
	cases := []struct {
		name    string
		checker string
		handler http.HandlerFunc
	}{
		{"netscaler_gateway_no_version", "CVE-2025-7775", func(w http.ResponseWriter, r *http.Request) {
			// Gateway service face present, but no version string anywhere.
			if r.URL.Path == "/vpn/index.html" {
				w.Write([]byte(`<html>Citrix Gateway login /vpn/js/gateway_login_form_view.js</html>`))
				return
			}
			w.Write([]byte(`<html>NetScaler _ctxstxt</html>`))
		}},
		{"oracleproxy_ohs_routing_no_version", "CVE-2026-21962", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Oracle-HTTP-Server") // no version number
			if r.URL.Path == "/console" {
				w.Write([]byte(`<html>WebLogic Bridge Message</html>`)) // routing evidence
				return
			}
			w.Write([]byte(`<html>ohs</html>`))
		}},
		{"fortinet_exposed_no_version", "CVE-2024-55591", func(w http.ResponseWriter, r *http.Request) {
			// FortiOS fingerprint + management surface, but no version exposed.
			w.Write([]byte(`<html>FortiGate fgt_lang /remote/login logindisclaimer</html>`))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(tc.handler)
			defer s.Close()
			findings := runAllCheckers(t, model.ModeActiveProbe, s.URL)
			if v := findings[tc.checker].Verdict; v != model.VerdictUnknown {
				t.Errorf("[A4] %s: %s = %s (%s), want unknown (fingerprint+exposure but no version must not elevate)",
					tc.name, tc.checker, v, findings[tc.checker].Reason)
			}
			assertNoElevation(t, tc.name, findings) // and nothing else may elevate
		})
	}
}

// A2 malformed / boundary version audit: garbage or edge-case version strings
// must never parse into an affected match, must not crash, and must not elevate.
// The target checker must end up unknown or not_found (never detected/likely).
func TestVersionMalformedNoElevation(t *testing.T) {
	lowTier := func(v model.Verdict) bool {
		return v == model.VerdictUnknown || v == model.VerdictNotFound || v == model.VerdictError
	}
	cases := []struct {
		name     string
		checker  string
		server   string
		body     string
		spHeader string
	}{
		{"tomcat_incomplete_version", "CVE-2025-24813", "Apache-Coyote/1.1", `Apache Tomcat/9`, ""},
		{"tomcat_garbage_version", "CVE-2025-24813", "Apache-Coyote/1.1", `Apache Tomcat/x.y.z`, ""},
		{"nginx_incomplete", "CVE-2026-42533", "nginx/1.30", ``, ""},
		{"nginx_garbage", "CVE-2026-42533", "nginx/abc", ``, ""},
		{"sharepoint_ambiguous_build", "CVE-2025-53770", "Microsoft-IIS/10.0", `/_layouts/15/ _spPageContextInfo`, "16.0.0.10417"},
		{"sharepoint_unmapped_build", "CVE-2025-53770", "Microsoft-IIS/10.0", `/_layouts/15/ _spPageContextInfo`, "16.0.99999.1"},
		{"netscaler_impossible_branch", "CVE-2025-7775", "", `NetScaler _ctxstxt NS99.9 88.77`, ""},
		{"fortinet_garbage_version", "CVE-2024-55591", "", `FortiGate fgt_lang "version":"abcd"`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.server != "" {
					w.Header().Set("Server", tc.server)
				}
				if tc.spHeader != "" {
					w.Header().Set("MicrosoftSharePointTeamServices", tc.spHeader)
				}
				if tc.server == "Apache-Coyote/1.1" {
					w.WriteHeader(404) // Tomcat banner lives on the 404 page
				}
				w.Write([]byte(tc.body))
			}))
			defer s.Close()
			findings := runAllCheckers(t, model.ModeActiveProbe, s.URL)
			if v := findings[tc.checker].Verdict; !lowTier(v) {
				t.Errorf("[A2] %s: %s = %s (%s), want unknown/not_found — a malformed version must not elevate",
					tc.name, tc.checker, v, findings[tc.checker].Reason)
			}
			assertNoElevation(t, tc.name, findings)
		})
	}
}

// A non-WebLogic TCP service must not be mistaken for T3 just because it returns
// a banner to our handshake.
func TestFalsePositiveCorpusTCP(t *testing.T) {
	banners := []string{"220 ProFTPD ready\r\n", "SSH-2.0-OpenSSH_8.9\r\n", "* OK IMAP4 ready\r\n", "GARBAGE HELO not-a-prefix\r\n"}
	for _, banner := range banners {
		t.Run(banner[:6], func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					_, _ = conn.Write([]byte(banner))
					conn.Close()
				}
			}()
			assertNoElevation(t, "tcp:"+banner[:6], runAllCheckers(t, model.ModeActiveProbe, "http://"+ln.Addr().String()))
		})
	}
}
