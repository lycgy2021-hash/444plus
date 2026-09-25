package netscaler

import "gopoc/internal/httpx"

// CVE-2025-6543 (Citrix NetScaler ADC/Gateway memory overflow -> unintended
// control flow / DoS, CVSS v4 9.2, exploited in the wild). Same preconditions as
// CVE-2025-7775 (Gateway or AAA vServer) but a DIFFERENT fix line, so a version
// affected by one may be fixed for the other.
// https://support.citrix.com/external/article/CTX694788/
func NewCVE20256543(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2025-6543", "Citrix NetScaler ADC/Gateway Memory Overflow (Control-Flow/DoS)", affected6543, client)
}
