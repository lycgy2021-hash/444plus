package oracleproxy

import "gopoc/internal/httpx"

// CVE-2026-60364 (Oracle CPU Jul 2026, CVSS 7.5, unauthenticated, HTTP):
// WebLogic Server Proxy Plug-in for Apache/IIS. Reuses the same product base.
func NewCVE202660364(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60364", "Oracle WebLogic Proxy Plug-in HTTP Vulnerability", "Oracle-Proxy", affected60364, client)
}
