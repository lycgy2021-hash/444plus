package weblogic

import "gopoc/internal/httpx"

// Oracle CPU July 2026 — WebLogic Core, SOAP/web-service attack surface.
// Likely requires a WebLogic web-service endpoint (wls-wsat/async) to be exposed.
func NewCVE202660200(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60200", "Oracle WebLogic Core SOAP RCE (CPU 2026-07)", cpu202607, "SOAP web-service", cpu2026Common, requiresSOAP, client)
}

func NewCVE202660294(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2026-60294", "Oracle WebLogic Core SOAP RCE (CPU 2026-07)", cpu202607, "SOAP web-service", cpu2026Common, requiresSOAP, client)
}
