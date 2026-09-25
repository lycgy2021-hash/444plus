package fortinet

import "gopoc/internal/httpx"

// FG-IR-24-535 groups CVE-2024-55591 and CVE-2025-24472: unauthenticated
// FortiOS/FortiProxy authentication bypass to super-admin, exploited in the
// wild. Both CVEs share one advisory, affected range and assessment, so they are
// two thin constructors over the same pipeline.
// https://www.fortiguard.com/psirt/FG-IR-24-535

var fgir24535Products = []string{"FortiOS", "FortiProxy"}

func NewCVE202455591(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2024-55591", "FortiOS/FortiProxy Authentication Bypass (FG-IR-24-535)", fgir24535Products, FGIR24535, client)
}

func NewCVE202524472(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2025-24472", "FortiOS/FortiProxy Authentication Bypass (FG-IR-24-535)", fgir24535Products, FGIR24535, client)
}
