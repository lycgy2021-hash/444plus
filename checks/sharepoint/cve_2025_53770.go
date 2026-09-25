package sharepoint

import "gopoc/internal/httpx"

// CVE-2025-53770: SharePoint ViewState deserialization RCE — the in-the-wild
// ToolShell patch-bypass RCE (July 2025). https://msrc.microsoft.com/update-guide
func NewCVE202553770(client httpx.Probe) *familyChecker {
	return newToolShell("CVE-2025-53770", "SharePoint ToolShell Deserialization RCE", "RCE", client)
}
