package sharepoint

import "gopoc/internal/httpx"

// CVE-2025-53771: SharePoint spoofing / path-traversal — the ToolShell
// patch-bypass of the spoofing component (July 2025). https://msrc.microsoft.com/update-guide
func NewCVE202553771(client httpx.Probe) *familyChecker {
	return newToolShell("CVE-2025-53771", "SharePoint ToolShell Spoofing / Bypass", "spoofing / auth-bypass", client)
}
