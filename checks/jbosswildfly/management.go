package jbosswildfly

import (
	"context"
	"regexp"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// managementPath is the HTTP management API root on both WildFly 8+/EAP 7+
// and legacy JBoss AS 7/EAP 6.
const managementPath = "/management"

// managementPorts are the conventional ports for the HTTP management
// interface, tried on the scanned host in addition to the target's own port.
// Confirmed default on a live WildFly image: app HTTP on 8080, management on
// 9990 — a separate listener, not multiplexed onto the app port.
var managementPorts = []int{9990, 9993}

// managementProbe is the result of probing one candidate host:port for the
// management API.
type managementProbe struct {
	target   model.Target
	response httpx.Response
	err      error
}

// candidateManagementTargets returns target plus one Target per conventional
// management port on the same host, deduplicated by port. Reusing the scanned
// target's own host keeps every candidate inside the caller's policy scope
// (checked per-request by httpx.Client against the same host).
func candidateManagementTargets(target model.Target) []model.Target {
	seen := map[int]bool{target.Port: true}
	out := []model.Target{target}
	for _, port := range managementPorts {
		if seen[port] {
			continue
		}
		seen[port] = true
		cand := target
		cand.Port = port
		out = append(out, cand)
	}
	return out
}

// probeManagement issues one GET managementPath against each candidate target
// on the host. It keeps trying every candidate until one gives the definitive
// signal (an auth challenge or unauthenticated management data) — a plain 200
// or 404 from the app's OWN port (the common topology: app on 8080, real
// management API on a separate 9990) is not that signal and must not shadow
// the real management port. Confirmed on a live WildFly image scanned at its
// app port only: stopping at the first port that answers AT ALL (even a
// 404 from the app port itself) never even tried 9990, so a real, reachable
// secure instance came back not_found instead of detected. Only once no
// candidate answers definitively does this fall back to the best "reachable
// but unclear" response or, failing that, the last connection error.
func probeManagement(ctx context.Context, client httpx.Probe, target model.Target) (managementProbe, []model.Observation) {
	var obs []model.Observation
	var reached, last managementProbe
	haveReached := false
	for _, cand := range candidateManagementTargets(target) {
		r, err := client.Get(ctx, cand, managementPath)
		o := r.Observation("management_probe", err)
		o.URL = cand.Origin() + managementPath
		obs = append(obs, o)
		last = managementProbe{target: cand, response: r, err: err}
		if err != nil {
			continue
		}
		if requiresAuth(r) || unauthenticatedData(r) {
			return last, obs
		}
		if !haveReached {
			reached, haveReached = last, true
		}
	}
	if haveReached {
		return reached, obs
	}
	return last, obs
}

// managementDataRE matches the DMR (detyped management resource) JSON fields
// the root management resource reports about itself: product-name,
// product-version, release-version, management-major-version. These field
// names are specific to the WildFly Core management kernel; an unrelated JSON
// API is very unlikely to combine them with a DMR "outcome" wrapper.
var managementDataRE = regexp.MustCompile(`"(?:product-name|product-version|release-version|management-major-version)"\s*:`)

// requiresAuth reports whether r is the management HTTP interface demanding
// authentication: a 401 whose WWW-Authenticate challenge names the realm the
// management subsystem creates by default. Confirmed on a live default
// WildFly image: `401 WWW-Authenticate: Digest realm="ManagementRealm"`.
// Matching the realm name (not just "any 401" or "realm=" in general) is what
// keeps an ordinary, unrelated Digest/Basic login page from being reported as
// this product's management interface.
func requiresAuth(r httpx.Response) bool {
	if r.StatusCode != 401 {
		return false
	}
	return strings.Contains(strings.ToLower(r.Get("WWW-Authenticate")), "managementrealm")
}

// unauthenticatedData reports whether r is the management API answering with
// product/version data and NO authentication challenge — the misconfiguration
// this package exists to find. A GET read-resource on WildFly returns the bare
// DMR root JSON (product-name/product-version/release-version plus the kernel's
// own "management-major-version"), with NO "outcome" wrapper (confirmed on a live
// WildFly 41.0.1.Final with management auth removed); "outcome" only wraps POST
// operation results. So we accept either shape, but still require the WildFly
// management kernel's own metadata field so an unrelated JSON API that merely
// carries a "product-version" string is not mistaken for this interface.
func unauthenticatedData(r httpx.Response) bool {
	if r.StatusCode != 200 {
		return false
	}
	body := string(r.Body)
	if !managementDataRE.MatchString(body) {
		return false
	}
	return strings.Contains(body, `"management-major-version"`) || strings.Contains(body, `"outcome"`)
}
