package weblogic

import "strings"

// affected reports whether a version string starts with any affected base
// release. WebLogic PSU patch levels are not remotely observable, so a base
// match is `detected`; a real protocol exposure raises it to `likely`.
func affected(version string, set []string) bool {
	for _, v := range set {
		if version == v || strings.HasPrefix(version, v+".") {
			return true
		}
	}
	return false
}

// Oracle CPU July 2026 WebLogic Core affected base releases.
// https://www.oracle.com/security-alerts/cpujul2026.html
var (
	cpu2026Common  = []string{"12.2.1.4", "14.1.1", "14.1.2", "15.1.1"}
	cpu2026Limited = []string{"12.2.1.4", "14.1.1"} // CVE-2026-60292 only
)
