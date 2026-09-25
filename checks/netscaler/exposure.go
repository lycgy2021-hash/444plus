package netscaler

import (
	"context"
	"strings"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type assessment struct {
	isNetScaler bool
	version     nsVersion
	hasVersion  bool
	gateway     bool // VPN/ICA/CVPN/RDP Gateway face exposed
	aaa         bool // AAA vServer face exposed
	obs         []model.Observation
}

// assess returns the shared NetScaler assessment, memoized per scan.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "netscaler"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

// doAssess fingerprints NetScaler and detects which affected service faces
// (Gateway, AAA) are actually exposed. It fetches the root plus the Gateway and
// AAA logon endpoints, so exposure is judged from real product surfaces, never
// from an open port or a generic Citrix page.
func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment
	probes := []struct{ kind, path string }{
		{"root", "/"},
		{"gateway_probe", "/vpn/index.html"},
		{"aaa_probe", "/logon/LogonPoint/tmindex.html"},
	}
	for _, p := range probes {
		r, err := client.Get(ctx, target, p.path)
		a.obs = append(a.obs, r.Observation(p.kind, err))
		if err != nil {
			continue
		}
		if isNSResponse(r) {
			a.isNetScaler = true
		}
		lower := strings.ToLower(string(r.Body))
		if p.kind == "gateway_probe" && isNSResponse(r) && containsAny(lower, gatewayMarkers) {
			a.gateway = true
		}
		if p.kind == "aaa_probe" && isNSResponse(r) && containsAny(lower, aaaMarkers) {
			a.aaa = true
		}
		if !a.hasVersion {
			if v, ok := parseVersion(string(r.Body) + " " + r.Get("Server")); ok {
				a.version, a.hasVersion = v, true
			}
		}
	}
	return a
}
