package oracleproxy

import (
	"context"
	"strings"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type assessment struct {
	frontend string // ohs / apache / iis / ""
	isProxy  bool   // OHS, or Apache/IIS with plug-in evidence
	version  string
	routing  bool // a request is confirmed to be forwarded to a WebLogic backend
	obs      []model.Observation
}

// assess returns the shared Oracle-proxy assessment, memoized per scan.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "oracle-proxy"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

// doAssess fingerprints the front-end, establishes the WebLogic proxy plug-in,
// and checks whether requests are actually routed to a WebLogic backend. OHS
// ships the plug-in component; Apache/IIS require explicit plug-in evidence.
func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment
	r, err := client.Get(ctx, target, "/")
	a.obs = append(a.obs, r.Observation("frontend", err))
	if err != nil {
		return a
	}
	a.frontend = frontend(r)
	switch a.frontend {
	case "ohs":
		a.isProxy = true // Oracle HTTP Server bundles the affected proxy component
	case "apache", "iis":
		a.isProxy = hasPluginEvidence(r) // plain Apache/IIS is NOT an Oracle proxy
	}
	if !a.isProxy {
		return a
	}
	a.version, _ = version(r, a.frontend)

	// Routing evidence: probe a path the proxy would forward; a bridge message or
	// WebLogic-origin response proves the plug-in is actively routing to WebLogic.
	rr, rerr := client.Get(ctx, target, "/console")
	a.obs = append(a.obs, rr.Observation("routing_probe", rerr))
	if rerr == nil {
		lower := strings.ToLower(string(rr.Body))
		if hasPluginEvidence(rr) || strings.Contains(lower, "weblogic") || strings.Contains(lower, "error 404--not found") {
			a.routing = true
		}
	}
	return a
}
