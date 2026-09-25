package oracleproxy

import (
	"regexp"

	"gopoc/internal/httpx"
)

// ohsVersionRE extracts the Oracle version from an Oracle-HTTP-Server Server
// header (e.g. "Oracle-HTTP-Server/12.2.1.4.0").
var ohsVersionRE = regexp.MustCompile(`(?i)Oracle-HTTP-Server[^0-9]*([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

// version returns the Oracle version, or ("", false). It is derivable only for
// OHS via its Server header; the Apache/IIS plug-in does not expose its version,
// so those front-ends usually yield unknown — which is reported honestly.
func version(r httpx.Response, fe string) (string, bool) {
	if fe == "ohs" {
		if m := ohsVersionRE.FindStringSubmatch(r.Get("Server")); m != nil {
			return m[1], true
		}
	}
	return "", false
}
