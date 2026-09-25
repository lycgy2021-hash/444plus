package fortinet

import (
	"context"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// managementPaths are administrative/portal surfaces whose reachability turns an
// affected-version detected into likely: the attack surface these advisories
// require is exposed to us. Heuristic, unverified against live appliances.
var managementPaths = []string{"/remote/login", "/login", "/admin"}

// exposure probes management surfaces and reports whether one is reachable and
// still looks like a Fortinet surface, plus the observations made.
func exposure(ctx context.Context, client httpx.Probe, target model.Target) (bool, []model.Observation) {
	var obs []model.Observation
	for _, p := range managementPaths {
		r, err := client.Get(ctx, target, p)
		obs = append(obs, r.Observation("management_probe", err))
		if err != nil {
			continue
		}
		if r.StatusCode >= 500 {
			continue
		}
		// Exposed only if the management path still looks like a Fortinet surface
		// or gates behind a login redirect — not merely any 200.
		if _, ok := fingerprint(string(r.Body)); ok || isRedirect(r.StatusCode) {
			return true, obs
		}
	}
	return false, obs
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}
