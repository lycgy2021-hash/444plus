package netscaler

import "gopoc/internal/httpx"

// CVE-2025-7775 (Citrix NetScaler ADC/Gateway memory overflow, unauthenticated,
// exploited in the wild). Affected when configured as a Gateway (VPN/ICA/CVPN/RDP
// proxy) or AAA vServer. https://support.citrix.com/article/CTX694938
func NewCVE20257775(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2025-7775", "Citrix NetScaler ADC/Gateway Memory Overflow", affected7775, client)
}
