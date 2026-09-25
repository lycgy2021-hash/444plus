// Package sharepoint holds detection-only checkers for the Microsoft SharePoint
// "ToolShell" advisory family (CVE-2025-49704/49706/53770/53771). All four share
// one assessment pipeline (fingerprint -> build -> patch level -> ToolShell
// surface exposure) and are reported as a family. They cap at `likely`: behavioral
// confirmation would require triggering deserialization / code execution.
package sharepoint

import (
	"strings"

	"gopoc/internal/httpx"
)

// isSharePoint distinguishes SharePoint from a plain IIS/ASP.NET server: a
// Microsoft-IIS Server header alone is NOT SharePoint. SharePoint is identified
// by its own response headers or layout markers.
func isSharePoint(r httpx.Response) bool {
	if r.Get("MicrosoftSharePointTeamServices") != "" || r.Get("X-SharePointHealthScore") != "" {
		return true
	}
	lower := strings.ToLower(string(r.Body))
	for _, m := range []string{"/_layouts/15/", "_sppagecontextinfo", "microsoft sharepoint", "sharepoint", "_spmodulepath"} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
