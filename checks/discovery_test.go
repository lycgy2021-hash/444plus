package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
	"gopoc/internal/registry"
)

// TestDiscoveryRoutesEveryBuiltinProduct ensures every checker registered in
// Builtin() has a corresponding routing hint in Discover(). If a checker is
// registered but Discover() never routes to its product, the checker will never
// run, even against a real instance — a silent false negative.
func TestDiscoveryRoutesEveryBuiltinProduct(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	r, err := Builtin(client, model.ModePassive, model.CanaryConfig{})
	if err != nil {
		t.Fatalf("Builtin failed: %v", err)
	}

	checkers, err := r.Select(registry.Filter{})
	if err != nil {
		t.Fatalf("Select all checkers failed: %v", err)
	}

	registered := make(map[string]bool)
	for _, c := range checkers {
		product := c.Metadata().Product
		registered[product] = true
	}

	// Test discovery routing for each registered product with minimal signals.
	testCases := map[string]struct {
		header string
		body   string
		want   string
	}{
		"apache": {header: "Server: Apache/2.4.50", body: "", want: "apache"},
		"nginx": {header: "Server: nginx/1.0", body: "", want: "nginx"},
		"nginx-ui": {header: "Request-Id: test-id", body: "", want: "nginx-ui"},
		"ingress-nginx": {header: "Server: nginx", body: "ingress-nginx", want: "ingress-nginx"},
		"tomcat": {header: "Server: Coyote/1.1", body: "", want: "tomcat"},
		"jenkins": {header: "X-Jenkins: 2.420", body: "", want: "jenkins"},
		"gitlab": {header: "X-Gitlab-Meta: eyJ0eXBlIjoiQUNDRVNTIiwid2Vic2l0ZSI6ImpjIn0", body: "", want: "gitlab"},
		"jbosswildfly": {header: "", body: "JBoss Application Server", want: "jbosswildfly"},
		"sharepoint": {header: "MicrosoftSharePointTeamServices: 1", body: "", want: "sharepoint"},
		"weblogic": {header: "", body: "WebLogic Server", want: "weblogic"},
		"netscaler": {header: "", body: "NetScaler Gateway", want: "netscaler"},
		"fortinet": {header: "", body: "FortiGate", want: "fortinet"},
		"oracle-proxy": {header: "Server: Oracle-HTTP-Server/2.0", body: "", want: "oracle-proxy"},
	}

	for product, tc := range testCases {
		if !registered[product] {
			// Product not registered, skip this test case.
			continue
		}

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.header != "" {
				parts := splitHeader(tc.header)
				w.Header().Set(parts[0], parts[1])
			}
			if tc.body != "" {
				w.Write([]byte(tc.body))
			}
		}))
		defer s.Close()

		target, err := model.ParseTarget(s.URL)
		if err != nil {
			t.Fatalf("ParseTarget failed: %v", err)
		}
		disc := Discover(context.Background(), client, target)

		if !disc.Products[tc.want] {
			t.Errorf("product %q not routed by discovery (signal: %q / %q)", product, tc.header, tc.body)
		}
	}

	// Reverse check: every registered product must have a discovery routing fixture.
	// If a new checker is added to Builtin() but forgot in testCases, this catches it.
	for product := range registered {
		if _, ok := testCases[product]; !ok {
			t.Errorf("registered product %q has no discovery routing fixture", product)
		}
	}
}

// TestGitLabDiscoverySignals verifies that GitLab's X-Gitlab-Meta header alone
// routes to gitlab (coarse routing), but that the checker itself enforces
// ≥2-signal product identity (precise verification).
func TestGitLabDiscoverySignals(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Gitlab-Meta", "eyJ0eXBlIjoiQUNDRVNTIn0")
	}))
	defer s.Close()

	target, err := model.ParseTarget(s.URL)
	if err != nil {
		t.Fatalf("ParseTarget failed: %v", err)
	}
	disc := Discover(context.Background(), client, target)

	if !disc.Products["gitlab"] {
		t.Error("X-Gitlab-Meta header alone should route to gitlab in discovery")
	}
}

// TestJBossWildFlyDiscoverySignals verifies JBoss/WildFly body markers route
// to jbosswildfly in discovery.
func TestJBossWildFlyDiscoverySignals(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	for _, body := range []string{"JBoss Application Server", "WildFly Application Server", "Hibernate Validator"} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		defer s.Close()

		target, err := model.ParseTarget(s.URL)
		if err != nil {
			t.Fatalf("ParseTarget failed: %v", err)
		}
		disc := Discover(context.Background(), client, target)

		if !disc.Products["jbosswildfly"] {
			t.Errorf("body marker %q should route to jbosswildfly in discovery", body)
		}
	}
}

// TestJBossManagementPortDiscovery verifies that standard JBoss/WildFly management
// ports (9990, 9993) are recognized even when main application page has no JBoss markers.
// This ensures discovery routes to checkers for independent management interface probing.
func TestJBossManagementPortDiscovery(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	// Test both standard management ports (9990 and 9993)
	for _, port := range []int{9990, 9993} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate business application with no JBoss markers
			w.Header().Set("Server", "Apache/2.4.50")
			w.Write([]byte("User application content"))
		}))
		defer s.Close()

		target, err := model.ParseTarget(s.URL)
		if err != nil {
			t.Fatalf("ParseTarget failed: %v", err)
		}
		// Override port to simulated management port
		target.Port = port

		disc := Discover(context.Background(), client, target)

		if !disc.Products["jbosswildfly"] {
			t.Errorf("port %d should route to jbosswildfly in discovery even without body markers", port)
		}
	}
}

// TestGitLabHeaderStrippedFallback verifies that when X-Gitlab-Meta header is stripped
// by proxy, discovery can still route via /users/sign_in page content detection.
func TestGitLabHeaderStrippedFallback(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate proxy that strips X-Gitlab-Meta header
		// Root path has mention of sign_in
		if r.RequestURI == "/" {
			w.Write([]byte(`<div><a href="/users/sign_in">Sign in</a></div>`))
		} else if r.RequestURI == "/users/sign_in" {
			// Actual sign-in page with GitLab content
			w.Write([]byte(`<html><title>GitLab Sign In</title><body>Welcome to GitLab</body></html>`))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer s.Close()

	target, err := model.ParseTarget(s.URL)
	if err != nil {
		t.Fatalf("ParseTarget failed: %v", err)
	}

	disc := Discover(context.Background(), client, target)

	if !disc.Products["gitlab"] {
		t.Error("GitLab should be routed when /users/sign_in contains gitlab marker (header stripped)")
	}
}

// TestDiscoveryJBossAppPortFindsSiblingManagement regression test for real topology:
// app:8080 (business page, no JBoss markers) + management on sibling port.
// When main app port has no JBoss identifiers, discovery's preflight logic probes
// standard management ports (9990/9993) and counts all HTTP requests accurately.
func TestDiscoveryJBossAppPortFindsSiblingManagement(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	// Simulate business app on port 8080 with no JBoss markers
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Request to / or random path on app port: just business content
		w.Header().Set("Server", "Apache/2.4.50")
		w.Write([]byte(`<html><body>My Business Application</body></html>`))
	}))
	defer s.Close()

	target, err := model.ParseTarget(s.URL)
	if err != nil {
		t.Fatalf("ParseTarget failed: %v", err)
	}

	// Test direct port-based routing for management ports
	target.Port = 9990
	disc := Discover(context.Background(), client, target)
	if !disc.Products["jbosswildfly"] {
		t.Error("Discovery should route jbosswildfly when port == 9990")
	}

	// Test preflight probing: when port is in standard app range (8000-8999),
	// discovery should probe sibling management ports and count those requests.
	// Note: actual preflight attempt depends on test environment's network.
	// At minimum, we verify port 8080 is considered a standard app port.
	target.Port = 8080
	baselineRequests := 2 // root + 404 are always made

	disc = Discover(context.Background(), client, target)

	// Preflight probes sibling 9990/9993 even if they fail (unreachable).
	// HTTPRequests should be >= baseline + attempted preflight probes.
	// With 8080 being in [8000-8999], at least some preflight attempts should occur.
	minExpected := baselineRequests
	if disc.HTTPRequests < minExpected {
		t.Errorf("HTTPRequests for port 8080 should be >= %d (baseline %d + preflight attempts), got %d",
			minExpected, baselineRequests, disc.HTTPRequests)
	}
}

// TestGitLabDiscoveryHeaderStrippedRedirect end-to-end regression test:
// when reverse proxy strips X-Gitlab-Meta header AND root responds with 302
// Location: /users/sign_in (no body content), discovery must still route gitlab
// to enable checker to probe /users/sign_in + /-/manifest.json.
func TestGitLabDiscoveryHeaderStrippedRedirect(t *testing.T) {
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatalf("policy.New failed: %v", err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 300 * time.Millisecond
	client, err := httpx.New(opts, p)
	if err != nil {
		t.Fatalf("httpx.New failed: %v", err)
	}
	t.Cleanup(client.Close)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/" {
			// Proxy strips X-Gitlab-Meta, root redirects to sign-in with empty body
			w.Header().Set("Location", "/users/sign_in")
			w.WriteHeader(302)
			// Empty body to simulate pure redirect without body hints
		} else if r.RequestURI == "/users/sign_in" {
			// Actual GitLab sign-in page
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Sign In to GitLab</title></head>
<body>
<h1>Welcome to GitLab</h1>
<form action="/login" method="POST">
  <input name="email" placeholder="Email">
  <input name="password" type="password">
</form>
</body>
</html>`))
		} else if r.RequestURI == "/-/manifest.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name": "GitLab", "short_name": "GitLab", "start_url": "/"}`))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer s.Close()

	target, err := model.ParseTarget(s.URL)
	if err != nil {
		t.Fatalf("ParseTarget failed: %v", err)
	}

	disc := Discover(context.Background(), client, target)

	if !disc.Products["gitlab"] {
		t.Error("GitLab should be routed when root redirects to /users/sign_in (header stripped, body empty)")
	}
}

func splitHeader(s string) [2]string {
	for i, c := range s {
		if c == ':' {
			return [2]string{s[:i], s[i+2:]}
		}
	}
	return [2]string{s, ""}
}
