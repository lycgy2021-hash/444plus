package weblogic

import "gopoc/internal/httpx"

// Oracle CPU July 2026 — WebLogic Core, HTTP attack surface (CVSS 9.8,
// unauthenticated). Likely requires the HTTP surface to be reachable.
const cpu202607 = "CPU-2026-07"

func NewCVE202660199(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60199", "Oracle WebLogic Core HTTP RCE (CPU 2026-07)", cpu202607, "HTTP", cpu2026Common, requiresHTTP, client)
}

func NewCVE202660291(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60291", "Oracle WebLogic Core HTTP RCE (CPU 2026-07)", cpu202607, "HTTP", cpu2026Common, requiresHTTP, client)
}

func NewCVE202660292(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60292", "Oracle WebLogic Core HTTP RCE (CPU 2026-07)", cpu202607, "HTTP", cpu2026Limited, requiresHTTP, client)
}
