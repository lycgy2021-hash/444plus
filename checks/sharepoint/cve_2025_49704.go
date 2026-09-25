package sharepoint

import "gopoc/internal/httpx"

// CVE-2025-49704: SharePoint code injection / RCE — the original ToolShell RCE
// component (July 2025). https://msrc.microsoft.com/update-guide
func NewCVE202549704(client httpx.Probe) *familyChecker {
	return newToolShell("CVE-2025-49704", "SharePoint ToolShell Code Injection RCE", "RCE", client)
}
