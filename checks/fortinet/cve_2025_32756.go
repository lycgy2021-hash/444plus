package fortinet

import "gopoc/internal/httpx"

// CVE-2025-32756 (FG-IR-25-254): stack-based buffer overflow in the HTTP/HTTPS
// administrative/portal interface of FortiVoice, FortiMail, FortiNDR,
// FortiRecorder and FortiCamera; unauthenticated RCE, exploited in the wild.
// Behavioral confirmation would corrupt memory, so this caps at likely.
// https://www.fortiguard.com/psirt/FG-IR-25-254
func NewCVE202532756(client httpx.Probe) *advisoryChecker {
	products := []string{"FortiVoice", "FortiMail", "FortiNDR", "FortiRecorder", "FortiCamera"}
	return newAdvisory("CVE-2025-32756", "Fortinet API Stack Buffer Overflow (FG-IR-25-254)", products, FGIR25254, client)
}
