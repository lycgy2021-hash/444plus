package weblogic

import "gopoc/internal/httpx"

// affected21839 lists the base WebLogic releases affected by CVE-2023-21839
// (T3/IIOP JNDI deserialization RCE). Kept as a real-appliance regression
// baseline for the T3/IIOP probes.
var affected21839 = []string{"10.3.6", "12.1.3", "12.2.1.3", "12.2.1.4", "14.1.1"}

// NewCVE202321839 detects WebLogic exposure to CVE-2023-21839 over T3/IIOP.
func NewCVE202321839(client httpx.Probe) *advisoryChecker {
	return newAdvisory("CVE-2023-21839", "Oracle WebLogic T3/IIOP JNDI Deserialization RCE", "", "T3/IIOP", affected21839, requiresT3orIIOP, client)
}
