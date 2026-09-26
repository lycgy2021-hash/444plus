package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// Discovery is the result of a light, low-noise recon pass on one target: which
// products are plausibly present, so the scan runs only their checkers. It is
// deliberately coarse and recall-oriented — a candidate means "maybe this
// product"; each checker re-verifies precisely, so over-inclusion never causes a
// false positive, only a few extra (self-negating) checks.
type Discovery struct {
	Products     map[string]bool
	Observations []model.Observation
	HTTPRequests int
	TCPRequests  int
}

// Discover probes the target and returns candidate products. It makes at most
// two baseline HTTP GETs (root + 404), then conditional HTTP GETs: up to two for
// JBoss management preflight (9990, 9993), and up to one for GitLab sign_in fallback.
// Only when the response hints WebLogic, one T3 handshake.
func Discover(ctx context.Context, client httpx.Probe, target model.Target) Discovery {
	d := Discovery{Products: map[string]bool{}}
	add := func(p string) { d.Products[p] = true }

	root, err := client.Get(ctx, target, "/")
	d.HTTPRequests++
	d.Observations = append(d.Observations, root.Observation("discover_root", err))

	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	notFound, err := client.Get(ctx, target, "/gopoc-"+hex.EncodeToString(rnd[:]))
	d.HTTPRequests++
	d.Observations = append(d.Observations, notFound.Observation("discover_404", err))

	server := strings.ToLower(root.Get("Server") + " " + notFound.Get("Server"))
	body := strings.ToLower(string(root.Body) + " " + string(notFound.Body))
	hasHeader := func(k string) bool { return root.Get(k) != "" || notFound.Get(k) != "" }

	// Server-header signals.
	switch {
	case strings.Contains(server, "oracle-http-server"):
		add("oracle-proxy")
	case strings.Contains(server, "coyote"):
		add("tomcat")
	}
	if strings.Contains(server, "apache") {
		add("apache")
		add("oracle-proxy") // Apache may front the WebLogic proxy plug-in
	}
	if strings.Contains(server, "nginx") {
		add("nginx")
		add("ingress-nginx") // the ingress-nginx data plane is nginx
	}
	if strings.Contains(server, "microsoft-iis") {
		add("sharepoint")
		add("oracle-proxy") // IIS may front the WebLogic proxy plug-in
	}

	// Body/product signals (coarse; checkers re-verify).
	if strings.Contains(body, "apache tomcat") {
		add("tomcat")
	}
	if hasHeader("Request-Id") || hasHeader("X-Nginx-Ui") {
		add("nginx-ui")
	}
	// Jenkins advertises X-Jenkins/X-Hudson on every response, including 403s;
	// the checkers re-verify with the ≥2-signal rule, so a single header here is
	// only a routing hint.
	if hasHeader("X-Jenkins") || hasHeader("X-Hudson") {
		add("jenkins")
	}
	// GitLab emits X-Gitlab-Meta on every response; the checkers require ≥2
	// independent signals (header + body/manifest), so this is a routing hint only.
	if hasHeader("X-Gitlab-Meta") {
		add("gitlab")
	}
	// Fallback: when X-Gitlab-Meta is stripped by proxy, probe for GitLab's sign-in page.
	// This catches cases where: (1) body hints at /users/sign_in, or (2) Location redirects to it,
	// or (3) page mentions GitLab. The checker verifies via body + manifest.
	if !hasHeader("X-Gitlab-Meta") {
		shouldProbeSignIn := false
		// Case 1: body mentions sign_in or GitLab
		if strings.Contains(body, "/users/sign_in") || strings.Contains(body, "new_user") || strings.Contains(body, "gitlab") {
			shouldProbeSignIn = true
		}
		// Case 2: Location header redirects to /users/sign_in (typical GitLab pattern)
		if root.Location != "" && strings.Contains(strings.ToLower(root.Location), "/users/sign_in") {
			shouldProbeSignIn = true
		}
		if notFound.Location != "" && strings.Contains(strings.ToLower(notFound.Location), "/users/sign_in") {
			shouldProbeSignIn = true
		}

		if shouldProbeSignIn {
			signInResp, err := client.Get(ctx, target, "/users/sign_in")
			if err == nil && signInResp.StatusCode >= 200 && signInResp.StatusCode < 300 && strings.Contains(strings.ToLower(string(signInResp.Body)), "gitlab") {
				d.HTTPRequests++
				add("gitlab")
			}
		}
	}
	// JBoss/WildFly Management Interface signals. /management probe happens in the
	// checker itself; this is purely a routing hint based on product name/structure.
	if strings.Contains(body, "jboss") || strings.Contains(body, "wildfly") || strings.Contains(body, "hibernate validator") {
		add("jbosswildfly")
	}
	// Management interface typically on 9990 (http) or 9993 (https), even if main app
	// has no JBoss markers. This routes checkers to explore independent management endpoint.
	if target.Port == 9990 || target.Port == 9993 {
		add("jbosswildfly")
	}
	// Preflight: when app port has no JBoss markers, probe sibling management port.
	// Real topology: app:8080 (business page) + management:9990/9993 (WildFly).
	// Only probe standard app ports (80, 443, 8000-8999) to avoid noisy probes
	// against unrelated services. 9990=HTTP, 9993=HTTPS (correct protocols).
	isStandardAppPort := (target.Port == 80 || target.Port == 443 ||
		(target.Port >= 8000 && target.Port <= 8999))

	if !strings.Contains(body, "jboss") && !strings.Contains(body, "wildfly") &&
		target.Port != 9990 && target.Port != 9993 && isStandardAppPort {

		candidates := []struct {
			port   int
			scheme string
		}{
			{9990, "http"},
			{9993, "https"},
		}

		for _, candidate := range candidates {
			mgmtTarget := target
			mgmtTarget.Port = candidate.port
			mgmtTarget.Scheme = candidate.scheme

			mgmtResp, err := client.Get(ctx, mgmtTarget, "/management")
			d.HTTPRequests++

			if err != nil {
				continue
			}

			// Check for management interface signatures
			if mgmtResp.StatusCode >= 200 && mgmtResp.StatusCode < 300 {
				body := strings.ToLower(string(mgmtResp.Body))
				if strings.Contains(body, "managementrealm") || strings.Contains(body, "dmr") || strings.Contains(body, "wildfly") {
					add("jbosswildfly")
					break
				}
			} else if mgmtResp.StatusCode == 401 {
				// 401 with basic auth challenge is typical for management interface
				add("jbosswildfly")
				break
			}
		}
	}
	if hasHeader("MicrosoftSharePointTeamServices") || hasHeader("X-SharePointHealthScore") || strings.Contains(body, "/_layouts/15/") {
		add("sharepoint")
	}
	if containsAnyLower(body, []string{"netscaler", "citrix gateway", "nsgslb", "_ctxstxt", "/vpn/js/", "logonpoint"}) {
		add("netscaler")
	}
	if containsAnyLower(body, []string{"fgt_lang", "fortigate", "fortimail", "fortivoice", "fortindr", "forticamera", "fortiproxy", "/remote/login", "logindisclaimer"}) {
		add("fortinet")
	}
	weblogicHTTP := strings.Contains(body, "error 404--not found") || strings.Contains(body, "weblogic server") || strings.Contains(body, "/console/login/")
	if weblogicHTTP {
		add("weblogic")
	}

	// T3 handshake only when HTTP hints WebLogic or the port is the WebLogic default,
	// to avoid a TCP probe against every unrelated HTTP service.
	if weblogicHTTP || target.Port == 7001 {
		resp, err := client.TCP(ctx, target, []byte("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"), 256)
		d.TCPRequests++
		obs := model.Observation{Kind: "discover_t3", URL: target.Origin(), Bytes: len(resp)}
		if err != nil {
			obs.Error = err.Error()
		} else if strings.HasPrefix(string(resp), "HELO:") {
			add("weblogic")
		}
		d.Observations = append(d.Observations, obs)
	}
	return d
}

func containsAnyLower(s string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
