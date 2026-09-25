package oracleproxy

import "gopoc/internal/httpx"

// CVE-2026-21962 (Oracle CPU Jan 2026, CVSS 10.0, unauthenticated, remote,
// scope-changed): Oracle HTTP Server and the WebLogic Proxy Plug-in for
// Apache/IIS. https://www.oracle.com/security-alerts/cpujan2026.html
func NewCVE202621962(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-21962", "Oracle HTTP Server / WebLogic Proxy Plug-in Critical Compromise", "Oracle-Proxy", affected21962, client)
}
