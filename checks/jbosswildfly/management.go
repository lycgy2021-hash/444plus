package jbosswildfly

import (
	"context"
	"regexp"
	"strings"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// managementPath is the HTTP management API root on both WildFly 8+/EAP 7+
// and legacy JBoss AS 7/EAP 6.
const managementPath = "/management"

// discoveryBudget bounds the TOTAL wall-clock cost of the sibling-management
// preflight that Discover() runs against ordinary web targets. Management ports
// that are firewalled with DROP (not RST) would otherwise each cost a full
// httpx timeout; capping the whole preflight keeps low-noise discovery cheap.
const discoveryBudget = 1 * time.Second

// managementEndpoint is one conventional management listener: its port and the
// scheme that listener speaks. This is the single source of truth for "where and
// how the WildFly/JBoss management interface is reached" — the checker and
// discovery both build their candidates from it, so a scheme fix here reaches
// both and they can never disagree on, say, whether 9993 is HTTPS.
type managementEndpoint struct {
	Port   int
	Scheme string
}

// managementEndpoints are the conventional management listeners, tried on the
// scanned host in addition to the target's own port. Confirmed default on a live
// WildFly image: app HTTP on 8080, management on 9990 — a separate listener, not
// multiplexed onto the app port. 9990 is the plain-HTTP management port; 9993 is
// its TLS counterpart, so it must be probed as https or the TLS listener sees a
// plaintext request and the real management interface is missed.
var managementEndpoints = []managementEndpoint{
	{Port: 9990, Scheme: "http"},
	{Port: 9993, Scheme: "https"},
}

// managementProbe is the result of probing one candidate host:port for the
// management API.
type managementProbe struct {
	target   model.Target
	response httpx.Response
	err      error
}

// candidateManagementTargets returns target plus one Target per conventional
// management endpoint on the same host, each carrying the endpoint's own scheme
// (9990=http, 9993=https). Dedup is by full origin (scheme+host+port), not port
// alone: when the input already sits on a management port but with the wrong
// scheme (e.g. http://host:9993), we still add the correctly-schemed candidate
// (https://host:9993) rather than letting the input's scheme suppress it — the
// input scheme is a scan-entry fact, not the product's protocol fact. Reusing
// the scanned target's own host keeps every candidate inside the caller's policy
// scope (checked per-request by httpx.Client against the same host).
func candidateManagementTargets(target model.Target) []model.Target {
	var out []model.Target
	seen := map[string]bool{}
	add := func(t model.Target) {
		if seen[t.Origin()] {
			return
		}
		seen[t.Origin()] = true
		out = append(out, t)
	}
	add(target)
	for _, ep := range managementEndpoints {
		cand := target
		cand.Port = ep.Port
		cand.Scheme = ep.Scheme
		add(cand)
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

// ManagementDiscoveryHint is the low-cost routing hint Discover() uses when an
// ordinary web target shows no JBoss/WildFly markers on its own port: it probes
// the conventional management ports on the SAME host and reports whether one
// answers with a definitive management signal. It reuses the checker's own
// requiresAuth / unauthenticatedData predicates — the single source of truth for
// "this is the WildFly management interface" — so discovery never routes on a
// weaker rule (e.g. any 401) than the checker verifies with, and the two can
// never drift apart. The whole preflight shares one short deadline so a
// DROP-firewalled port cannot stall discovery, and every probe (success, miss,
// or policy-blocked error) is returned as an Observation so the caller can both
// account for the request and tell "no management here" apart from "policy
// blocked the probe". Returns whether a management interface was seen and the
// per-probe observations (also the exact count of HTTP requests made).
func ManagementDiscoveryHint(ctx context.Context, client httpx.Probe, target model.Target) (bool, []model.Observation) {
	ctx, cancel := context.WithTimeout(ctx, discoveryBudget)
	defer cancel()

	var obs []model.Observation
	hit := false
	for _, cand := range candidateManagementTargets(target) {
		if cand.Port == target.Port {
			continue // the caller has already fetched the app port itself
		}
		r, err := client.Get(ctx, cand, managementPath)
		o := r.Observation("discover_management", err)
		o.URL = cand.Origin() + managementPath
		obs = append(obs, o)
		if err != nil {
			continue
		}
		if requiresAuth(r) || unauthenticatedData(r) {
			hit = true
			break
		}
	}
	return hit, obs
}
