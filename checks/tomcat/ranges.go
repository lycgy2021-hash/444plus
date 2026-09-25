// Package tomcat holds a detection-only checker for Apache Tomcat
// CVE-2025-24813 (partial PUT + path equivalence RCE). It caps at `likely`: the
// full exploit needs a writable DefaultServlet AND partial-PUT temp-file
// behavior AND file-backed session persistence AND a deserialization gadget, and
// confirming it would write files and execute code. A version match alone is
// detected; writable DefaultServlet raises it to likely; the remaining
// prerequisites are reported as unverified.
package tomcat

import "gopoc/checks/detect"

// affected reports whether a Tomcat version is in CVE-2025-24813's range, with
// the fixed release. Affected: 9.0.0–9.0.98, 10.1.0–10.1.34, 11.0.0–11.0.2.
func affected(v detect.Version) (bool, string) {
	switch {
	case v[0] == 9 && v[1] == 0 && detect.Less(v, detect.Version{9, 0, 99}):
		return true, "9.0.99"
	case v[0] == 10 && v[1] == 1 && detect.Less(v, detect.Version{10, 1, 35}):
		return true, "10.1.35"
	case v[0] == 11 && v[1] == 0 && detect.Less(v, detect.Version{11, 0, 3}):
		return true, "11.0.3"
	}
	return false, ""
}
