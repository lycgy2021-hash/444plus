package sharepoint

import "gopoc/internal/httpx"

// CVE-2025-49706: SharePoint spoofing / authentication-bypass component of
// ToolShell (crafted Referer to ToolPane.aspx). https://msrc.microsoft.com/update-guide
func NewCVE202549706(client httpx.Probe) *familyChecker {
	return newToolShell("CVE-2025-49706", "SharePoint ToolShell Spoofing / Auth Bypass", "spoofing / auth-bypass", client)
}
