package weblogic

import "gopoc/internal/httpx"

// Oracle CPU July 2026 — WebLogic Core, T3/IIOP attack surface. Likely requires
// a real T3 or IIOP handshake to succeed (never inferred from an open port).
func NewCVE202660198(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60198", "Oracle WebLogic Core T3/IIOP RCE (CPU 2026-07)", cpu202607, "T3/IIOP", cpu2026Common, requiresT3orIIOP, client)
}

func NewCVE202660202(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60202", "Oracle WebLogic Core T3/IIOP RCE (CPU 2026-07)", cpu202607, "T3/IIOP", cpu2026Common, requiresT3orIIOP, client)
}
