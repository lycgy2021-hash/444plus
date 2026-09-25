// Package oracleproxy holds detection-only checkers for Oracle HTTP Server and
// the Oracle WebLogic Server Proxy Plug-in for Apache/IIS. It never treats a
// plain Apache/IIS as an Oracle proxy: WebLogic-proxy-specific evidence is
// required before any detected/likely verdict. It caps at `likely` (no exploit).
//
// No live OHS/plug-in appliance in this lab; fingerprints are heuristic and
// validated by unit tests, not a real device.
package oracleproxy

import (
	"strings"

	"gopoc/internal/httpx"
)

// frontend classifies the front-end web server from the Server header.
func frontend(r httpx.Response) string {
	s := strings.ToLower(r.Get("Server"))
	switch {
	case strings.Contains(s, "oracle-http-server"):
		return "ohs"
	case strings.Contains(s, "microsoft-iis"):
		return "iis"
	case strings.Contains(s, "apache"):
		return "apache"
	}
	return ""
}
