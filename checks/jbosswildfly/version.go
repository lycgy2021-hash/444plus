package jbosswildfly

import (
	"regexp"

	"gopoc/internal/httpx"
)

// versionFieldRE reads the version WildFly's own management API reports about
// itself, e.g. "product-version" : "31.0.1.Final" or "release-version" :
// "26.1.3.Final". This is the only reliable unauthenticated version source: a
// live WildFly 41.0.1.Final image sends no Server header and no version on its
// welcome page (confirmed; see docs/jboss-wildfly-attack-surface.md), so
// version is reported only when the management API itself exposes it.
var versionFieldRE = regexp.MustCompile(`"(?:product|release)-version"\s*:\s*"([0-9][0-9A-Za-z_.\-]*)"`)

// extractVersion reads a product/release version from a management API
// response body. It returns ("", false) when none is present, which callers
// must treat as "unknown", never "not affected".
func extractVersion(r httpx.Response) (string, bool) {
	if m := versionFieldRE.FindSubmatch(r.Body); m != nil {
		return string(m[1]), true
	}
	return "", false
}
