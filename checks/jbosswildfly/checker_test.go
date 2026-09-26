package jbosswildfly

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

// mockProbe drives the checker's ladder without a live JBoss/WildFly. The
// checker fingerprints via a plain Get("/") (client.Fingerprint's shared cache
// always nils out Body, so a body-based signal must use a fresh Get instead —
// see doAssess), so Get answers "/" with the configured app-port body,
// managementPath with the configured management response, and anything else
// with a bare 404.
type mockProbe struct {
	fpBody      string
	fpHeaders   map[string]string
	mgmtStatus  int
	mgmtBody    string
	mgmtHeaders map[string]string
	mgmtErr     error
}

func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}

func (m mockProbe) Get(_ context.Context, _ model.Target, path string) (httpx.Response, error) {
	if path == "/" {
		h := m.fpHeaders
		if h == nil {
			h = map[string]string{}
		}
		return httpx.Response{StatusCode: 200, Body: []byte(m.fpBody), Headers: h}, nil
	}
	if path != managementPath {
		return httpx.Response{StatusCode: 404, Headers: map[string]string{}}, nil
	}
	if m.mgmtErr != nil {
		return httpx.Response{}, m.mgmtErr
	}
	return httpx.Response{StatusCode: m.mgmtStatus, Body: []byte(m.mgmtBody), Headers: canonicalHeaders(m.mgmtHeaders)}, nil
}

// canonicalHeaders mirrors what httpx.Client actually stores: header keys read
// off the wire via Go's net/http are already canonical (e.g.
// "Www-Authenticate", not "WWW-Authenticate"), and httpx.Response.Get looks
// them up canonically. A hand-built test map must match that or a real header
// name silently fails to match.
func canonicalHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}

func (m mockProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) TCP(context.Context, model.Target, []byte, int) ([]byte, error) { return nil, nil }

func TestUnauthManagementLadder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8080")
	cases := []struct {
		name    string
		probe   mockProbe
		want    model.Verdict
		reason  string
		version string
	}{
		{
			name:   "not_jbosswildfly",
			probe:  mockProbe{fpBody: "<html>welcome to nginx</html>", mgmtStatus: 404, mgmtBody: "not found"},
			want:   model.VerdictNotFound,
			reason: "product_not_jbosswildfly",
		},
		{
			name:   "management_unreachable",
			probe:  mockProbe{fpBody: "<html>Welcome to WildFly</html>", mgmtErr: errors.New("dial tcp: connection refused")},
			want:   model.VerdictUnknown,
			reason: "management_unreachable",
		},
		{
			// Real default WildFly behavior: 401 Digest realm="ManagementRealm".
			// This must NEVER be reported likely.
			name:   "management_requires_auth",
			probe:  mockProbe{fpBody: "<html>Welcome to WildFly</html>", mgmtStatus: 401, mgmtHeaders: map[string]string{"WWW-Authenticate": `Digest realm="ManagementRealm", domain="/management", nonce="abc", opaque="def", algorithm=MD5, qop="auth"`}},
			want:   model.VerdictDetected,
			reason: "management_requires_auth",
		},
		{
			// Deliberately open test management interface: 200 + DMR JSON.
			// This is the one case that must reach likely.
			name:    "unauthenticated_management_exposed",
			probe:   mockProbe{fpBody: "<html>Welcome to WildFly</html>", mgmtStatus: 200, mgmtBody: `{"outcome":"success","result":{"product-name":"WildFly Full","product-version":"31.0.1.Final","management-major-version":22}}`},
			want:    model.VerdictLikely,
			reason:  "unauthenticated_management_exposed",
			version: "31.0.1.Final",
		},
		{
			// Regression: a real WildFly GET /management returns the bare DMR root
			// resource with NO "outcome" wrapper (confirmed on live 41.0.1.Final);
			// this must still reach likely.
			name:    "unauth_management_bare_get",
			probe:   mockProbe{fpBody: "<html>Welcome to WildFly</html>", mgmtStatus: 200, mgmtBody: `{"management-major-version" : 34, "management-micro-version" : 0, "management-minor-version" : 0, "name" : "8f788e71215a", "product-name" : "WildFly", "product-version" : "41.0.1.Final", "release-version" : "33.0.1.Final"}`},
			want:    model.VerdictLikely,
			reason:  "unauthenticated_management_exposed",
			version: "41.0.1.Final",
		},
		{
			name:   "management_state_unclear",
			probe:  mockProbe{fpBody: "<html>Welcome to WildFly</html>", mgmtStatus: 200, mgmtBody: "<html>some other page</html>"},
			want:   model.VerdictUnknown,
			reason: "management_state_unclear",
		},
		// Adversarial: a generic, unrelated Digest challenge must not be treated
		// as this product's management interface just because it is a 401.
		{
			name:   "generic_digest_401_unrelated",
			probe:  mockProbe{fpBody: "<html>plain app</html>", mgmtStatus: 401, mgmtHeaders: map[string]string{"WWW-Authenticate": `Digest realm="corporate-intranet"`}},
			want:   model.VerdictNotFound,
			reason: "product_not_jbosswildfly",
		},
		// Adversarial: the literal text "ManagementRealm" appearing in a page BODY
		// (not the WWW-Authenticate header) must not be mistaken for the real
		// challenge.
		{
			name:   "managementrealm_text_in_body_not_header",
			probe:  mockProbe{fpBody: "<html>this is not a JBoss ManagementRealm login</html>", mgmtStatus: 401, mgmtHeaders: map[string]string{"WWW-Authenticate": `Basic realm="secure area"`}},
			want:   model.VerdictNotFound,
			reason: "product_not_jbosswildfly",
		},
		// Adversarial: a forged "Welcome to WildFly" page is enough to pass the
		// weak fingerprint signal, but without real management JSON evidence the
		// verdict must stay unknown, never likely/detected.
		{
			name:   "forged_welcome_no_real_management",
			probe:  mockProbe{fpBody: "<html>Welcome to WildFly - totally fake</html>", mgmtStatus: 200, mgmtBody: "<html>Welcome to WildFly - totally fake</html>"},
			want:   model.VerdictUnknown,
			reason: "management_state_unclear",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewUnauthenticatedManagement(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			if tc.version != "" && f.Evidence.Version != tc.version {
				t.Errorf("version = %q, want %q", f.Evidence.Version, tc.version)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("this checker must never confirm (v1 caps at likely)")
			}
		})
	}
}

// TestRealServerLadder exercises the checker end-to-end (real httpx.Client,
// real HTTP server) for the two acceptance scenarios: WildFly's secure default
// (401 Digest/ManagementRealm) must not elevate, and a deliberately open
// management interface (200 + product-version JSON) must reach likely.
func TestRealServerLadder(t *testing.T) {
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

	t.Run("secure_default_not_likely", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == managementPath {
				w.Header().Set("WWW-Authenticate", `Digest realm="ManagementRealm", domain="/management", nonce="n", opaque="o", algorithm=MD5, qop="auth"`)
				w.WriteHeader(401)
				return
			}
			w.Write([]byte("<html>Welcome to WildFly</html>"))
		}))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		f := NewUnauthenticatedManagement(client).Check(context.Background(), target)
		if f.Verdict == model.VerdictLikely || f.Verdict == model.VerdictConfirmed {
			t.Fatalf("secure default must not elevate, got %s/%s", f.Verdict, f.Reason)
		}
		if f.Verdict != model.VerdictDetected || f.Reason != "management_requires_auth" {
			t.Errorf("got %s/%s, want detected/management_requires_auth", f.Verdict, f.Reason)
		}
	})

	// Regression: the checker used to fingerprint via client.Fingerprint(),
	// whose shared cache always nils out the response Body — so a real client
	// never actually saw the welcome page and this case wrongly came back
	// not_found. Isolate the fingerprint-only path: the app port 404s on
	// /management (no real management API there) and the conventional
	// fallback ports are (almost certainly) closed in this test environment,
	// so the welcome page's body is the ONLY route to isProduct=true.
	t.Run("welcome_page_alone_is_read_by_a_real_client", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == managementPath {
				w.WriteHeader(404)
				return
			}
			w.Write([]byte("<html>Welcome to WildFly</html>"))
		}))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		f := NewUnauthenticatedManagement(client).Check(context.Background(), target)
		if f.Reason == "product_not_jbosswildfly" {
			t.Fatalf("fingerprint body was not read by the real client: got %s/%s", f.Verdict, f.Reason)
		}
		if f.Verdict != model.VerdictUnknown || f.Reason != "management_state_unclear" {
			t.Errorf("got %s/%s, want unknown/management_state_unclear", f.Verdict, f.Reason)
		}
	})

	t.Run("open_management_reaches_likely", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == managementPath {
				w.Write([]byte(`{"outcome":"success","result":{"product-name":"WildFly Full","product-version":"31.0.1.Final"}}`))
				return
			}
			w.Write([]byte("<html>Welcome to WildFly</html>"))
		}))
		defer s.Close()
		target, _ := model.ParseTarget(s.URL)
		f := NewUnauthenticatedManagement(client).Check(context.Background(), target)
		if f.Verdict != model.VerdictLikely || f.Reason != "unauthenticated_management_exposed" {
			t.Fatalf("got %s/%s, want likely/unauthenticated_management_exposed", f.Verdict, f.Reason)
		}
	})
}

// portKeyedProbe answers /management differently depending on which candidate
// port was asked, so it can prove probeManagement actually tries every
// candidate rather than stopping at the first port that answers at all.
type portKeyedProbe struct {
	byPort map[int]httpx.Response
}

func (p portKeyedProbe) Get(_ context.Context, target model.Target, path string) (httpx.Response, error) {
	if path != managementPath {
		return httpx.Response{StatusCode: 404, Headers: map[string]string{}}, nil
	}
	if r, ok := p.byPort[target.Port]; ok {
		return r, nil
	}
	return httpx.Response{StatusCode: 404, Headers: map[string]string{}}, nil
}
func (p portKeyedProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (p portKeyedProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (p portKeyedProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (p portKeyedProbe) TCP(context.Context, model.Target, []byte, int) ([]byte, error) {
	return nil, nil
}

// TestProbeManagementTriesEveryCandidate is a regression test for a real bug:
// probeManagement used to return on the FIRST candidate that answered at
// all, even an irrelevant 404 from the app's own port — so it never even
// tried the real management port (9990) once the app port (here 8080)
// answered anything. This pins the fix: the app port's own 404 must not
// shadow a real signal on 9990.
func TestProbeManagementTriesEveryCandidate(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8080")
	probe := portKeyedProbe{byPort: map[int]httpx.Response{
		8080: {StatusCode: 404, Headers: map[string]string{}}, // app port: no /management here
		9990: {StatusCode: 401, Headers: canonicalHeaders(map[string]string{"WWW-Authenticate": `Digest realm="ManagementRealm"`})},
	}}
	mgmt, _ := probeManagement(context.Background(), probe, target)
	if mgmt.err != nil || mgmt.target.Port != 9990 || !requiresAuth(mgmt.response) {
		t.Fatalf("probeManagement did not reach the real management port: %+v", mgmt)
	}
}

// TestCandidateManagementTargetSchemes pins the management endpoint source of
// truth: 9990 is plain HTTP, 9993 is its TLS counterpart, and — crucially — the
// input scheme (a scan-entry fact) never suppresses the correct product-protocol
// candidate. If the user enters http://host:9993, we must STILL probe the real
// https://host:9993; dedup is by origin, not port. Probing 9993 as http hits the
// TLS listener with plaintext and misses the real management interface.
func TestCandidateManagementTargetSchemes(t *testing.T) {
	origins := func(url string) map[string]bool {
		target, err := model.ParseTarget(url)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", url, err)
		}
		got := map[string]bool{}
		for _, cand := range candidateManagementTargets(target) {
			got[cand.Origin()] = true
		}
		return got
	}
	cases := []struct {
		in   string
		must []string
	}{
		{"http://host:8080", []string{"http://host:9990", "https://host:9993"}},
		// Input already on a management port but WRONG scheme: correct candidate
		// must survive dedup, not be shadowed by the input's scheme.
		{"http://host:9993", []string{"https://host:9993", "http://host:9990"}},
		{"https://host:9990", []string{"http://host:9990", "https://host:9993"}},
	}
	for _, tc := range cases {
		got := origins(tc.in)
		for _, want := range tc.must {
			if !got[want] {
				t.Errorf("candidateManagementTargets(%q): missing %q (got %v)", tc.in, want, got)
			}
		}
	}
}

// remotingProbe answers the jboss-remoting HTTP-upgrade handshake sent over
// TCP, computing a correct/incorrect Sec-JbossRemoting-Accept from the actual
// key the caller sent — exercising the real handshake logic deterministically,
// without a real network round-trip.
type remotingProbe struct{ mode string }

func (p remotingProbe) TCP(_ context.Context, _ model.Target, payload []byte, _ int) ([]byte, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return nil, err
	}
	key := req.Header.Get("Sec-JbossRemoting-Key")
	switch p.mode {
	case "correct":
		accept := expectedRemotingAccept(key)
		return []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: jboss-remoting\r\nConnection: Upgrade\r\nSec-JbossRemoting-Accept: " + accept + "\r\n\r\n"), nil
	case "wrong_accept":
		return []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: jboss-remoting\r\nConnection: Upgrade\r\nSec-JbossRemoting-Accept: bm90LWEtcmVhbC1hY2NlcHQ=\r\n\r\n"), nil
	case "not_upgrade":
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), nil
	case "websocket_impersonation":
		// A plain WebSocket server would 101 on an Upgrade request too; it must
		// not be mistaken for jboss-remoting without the matching Accept.
		return []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: irrelevant\r\n\r\n"), nil
	default:
		return nil, nil
	}
}
func (p remotingProbe) Get(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (p remotingProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (p remotingProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (p remotingProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}

func TestRemotingExposed(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:8080")
	cases := []struct {
		mode string
		want bool
	}{
		{"correct", true},
		{"wrong_accept", false},
		{"not_upgrade", false},
		{"websocket_impersonation", false},
		{"empty", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			exposed, obs := RemotingExposed(context.Background(), remotingProbe{mode: tc.mode}, target)
			if exposed != tc.want {
				t.Errorf("mode %s: exposed = %v, want %v (obs: %+v)", tc.mode, exposed, tc.want, obs)
			}
		})
	}
}
