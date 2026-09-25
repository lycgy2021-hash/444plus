package oracleproxy

import "strings"

// AffectedRange scopes affected versions per front-end type, so the IIS plug-in
// scope is never conflated with Apache/OHS. Frontend "any" applies to all.
type AffectedRange struct {
	Frontend string
	Versions []string
}

func affectedForFrontend(ranges []AffectedRange, fe, version string) bool {
	for _, r := range ranges {
		if r.Frontend != "any" && r.Frontend != fe {
			continue
		}
		for _, v := range r.Versions {
			if version == v || strings.HasPrefix(version, v+".") {
				return true
			}
		}
	}
	return false
}

// CVE-2026-21962 (CPU Jan 2026, CVSS 10.0): Oracle HTTP Server and the WebLogic
// Proxy Plug-in for Apache/IIS. https://www.oracle.com/security-alerts/cpujan2026.html
var affected21962 = []AffectedRange{
	{"ohs", []string{"12.2.1.4", "14.1.1", "14.1.2"}},
	{"apache", []string{"12.2.1.4", "14.1.1", "14.1.2"}},
	{"iis", []string{"12.2.1.4", "14.1.1", "14.1.2"}},
}

// CVE-2026-60364 (CPU Jul 2026, CVSS 7.5): WebLogic Proxy Plug-in (Apache/IIS).
var affected60364 = []AffectedRange{
	{"apache", []string{"12.2.1.4", "14.1.2"}},
	{"iis", []string{"12.2.1.4", "14.1.2"}},
}
