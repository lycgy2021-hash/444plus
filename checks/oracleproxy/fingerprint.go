package oracleproxy

import (
	"strings"

	"gopoc/internal/httpx"
)

// bridgeMarkers are error/status strings emitted by the WebLogic proxy plug-in
// (mod_wl / mod_wl_ohs / IIS iisproxy). Their presence proves the plug-in is
// active, not merely that Apache/IIS is running.
var bridgeMarkers = []string{
	"weblogic bridge message",
	"failure of server apache bridge",
	"failure of web server bridge",
}

// hasPluginEvidence reports WebLogic-proxy-specific evidence: a WL-Proxy response
// header or a bridge message in the body. Required for Apache/IIS front-ends to
// count as an Oracle proxy at all.
func hasPluginEvidence(r httpx.Response) bool {
	for k := range r.Headers {
		if strings.HasPrefix(strings.ToLower(k), "wl-proxy") {
			return true
		}
	}
	lower := strings.ToLower(string(r.Body))
	for _, m := range bridgeMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
