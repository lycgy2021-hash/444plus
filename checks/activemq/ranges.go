// Package activemq holds a detection-only checker for Apache ActiveMQ
// CVE-2023-46604 (OpenWire protocol marshaller RCE). It caps at `likely`: the
// only way to prove the marshaller is actually exploitable is to send the
// crafted class-name packet that triggers arbitrary class instantiation, and
// that write IS the exploit — never attempted here.
package activemq

import "gopoc/checks/detect"

// affected reports whether v is in CVE-2023-46604's range, with the fixed
// release for that branch. Boundaries per the CVE Program record
// (CVEProject/cvelistV5), cross-checked against four real binaries: 5.16.6,
// 5.17.5, and 5.18.2 vulnerable; 5.17.6 fixed. See
// docs/activemq-attack-surface.md.
func affected(v detect.Version) (bool, string) {
	switch {
	case v[0] == 5 && v[1] == 18 && detect.Less(v, detect.Version{5, 18, 3}):
		return true, "5.18.3"
	case v[0] == 5 && v[1] == 17 && detect.Less(v, detect.Version{5, 17, 6}):
		return true, "5.17.6"
	case v[0] == 5 && v[1] == 16 && detect.Less(v, detect.Version{5, 16, 7}):
		return true, "5.16.7"
	case v[0] == 5 && detect.Less(v, detect.Version{5, 15, 16}):
		return true, "5.15.16"
	}
	return false, ""
}
