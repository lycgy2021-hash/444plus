package protocol

import (
	"context"
	"regexp"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// weblogicHTTPRE matches WebLogic's HTTP fingerprints: its distinctive error
// page, the "WebLogic Server" product string, or the admin console login path.
// A bare "WebLogic" mention is intentionally excluded so an unrelated page that
// merely names WebLogic is not fingerprinted as the product.
var weblogicHTTPRE = regexp.MustCompile(`(?i)Error 404--Not Found|WebLogic Server|/console/login/`)

// HTTP fetches a page and reports whether HTTP is exposed and whether the body or
// Server header looks like WebLogic. The version, when derivable from HTTP, is a
// weak signal; T3 is preferred.
func HTTP(ctx context.Context, client httpx.Probe, target model.Target) (exposed, isWebLogic bool, obs model.Observation) {
	r, err := client.Get(ctx, target, "/console")
	obs = r.Observation("http_console", err)
	if err != nil {
		return false, false, obs
	}
	body := string(r.Body)
	if strings.Contains(strings.ToLower(r.Get("Server")), "weblogic") || weblogicHTTPRE.MatchString(body) {
		return true, true, obs
	}
	return true, false, obs
}
