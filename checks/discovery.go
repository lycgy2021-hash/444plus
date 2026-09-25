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
// two HTTP GETs and, only when the response hints WebLogic, one T3 handshake.
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
