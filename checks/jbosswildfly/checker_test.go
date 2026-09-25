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

// mockProbe drives the checker's ladder without a live JBoss/WildFly. Get
// answers managementPath with the configured management response and 404 for
// anything else; Fingerprint answers with the configured app-port body.
type mockProbe struct {
	fpBody      string
	fpHeaders   map[string]string
	mgmtStatus  int
	mgmtBody    string
	mgmtHeaders map[string]string
	mgmtErr     error
}

func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	h := m.fpHeaders
	if h == nil {
		h = map[string]string{}
	}
	return httpx.Response{StatusCode: 200, Body: []byte(m.fpBody), Headers: h}, nil
}

func (m mockProbe) Get(_ context.Context, _ model.Target, path string) (httpx.Response, error) {
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
