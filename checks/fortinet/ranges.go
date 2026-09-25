// Package fortinet holds detection-only checkers for Fortinet PSIRT advisories.
// These reach at most the `likely` tier: confirming the actual bugs would mean
// attempting an authentication bypass, privileged operations, or a memory-safety
// crash, none of which a default scan should perform. The affected-version data
// lives in this table, not in checker logic, so new advisories are data edits.
//
// Fingerprints here are heuristic and have NOT been validated against a live
// Fortinet appliance in this lab; see fingerprint.go.
package fortinet

import (
	"strings"

	"gopoc/checks/detect"
)

// AffectedRange is one affected branch: Min..Max inclusive, fixed in Fixed.
type AffectedRange struct {
	Product string
	Branch  string
	Min     string
	Max     string
	Fixed   string
}

// affected reports whether product+version falls in any range, with the fixed
// release. Version must parse as major.minor.patch or it is treated as unknown.
func affected(ranges []AffectedRange, product, version string) (bool, string) {
	v, ok := detect.ParseVersion(version)
	if !ok {
		return false, ""
	}
	for _, r := range ranges {
		if !strings.EqualFold(r.Product, product) {
			continue
		}
		lo, ok1 := detect.ParseVersion(r.Min)
		hi, ok2 := detect.ParseVersion(r.Max)
		if !ok1 || !ok2 {
			continue
		}
		if !detect.Less(v, lo) && !detect.Less(hi, v) { // lo <= v <= hi
			return true, r.Fixed
		}
	}
	return false, ""
}

// FGIR24535 — CVE-2024-55591 / CVE-2025-24472 (FortiOS, FortiProxy).
// https://www.fortiguard.com/psirt/FG-IR-24-535
var FGIR24535 = []AffectedRange{
	{"FortiOS", "7.0", "7.0.0", "7.0.16", "7.0.17"},
	{"FortiProxy", "7.2", "7.2.0", "7.2.12", "7.2.13"},
	{"FortiProxy", "7.0", "7.0.0", "7.0.19", "7.0.20"},
}

// FGIR25254 — CVE-2025-32756 (FortiVoice, FortiMail, FortiNDR, FortiRecorder,
// FortiCamera). https://www.fortiguard.com/psirt/FG-IR-25-254
// "All versions / migrate" branches are encoded with a wide patch range.
var FGIR25254 = []AffectedRange{
	{"FortiCamera", "2.1", "2.1.0", "2.1.3", "2.1.4"},
	{"FortiCamera", "2.0", "2.0.0", "2.0.9999", "migrate to a fixed release"},
	{"FortiCamera", "1.1", "1.1.0", "1.1.9999", "migrate to a fixed release"},
	{"FortiMail", "7.6", "7.6.0", "7.6.2", "7.6.3"},
	{"FortiMail", "7.4", "7.4.0", "7.4.4", "7.4.5"},
	{"FortiMail", "7.2", "7.2.0", "7.2.7", "7.2.8"},
	{"FortiMail", "7.0", "7.0.0", "7.0.8", "7.0.9"},
	{"FortiNDR", "7.6", "7.6.0", "7.6.0", "7.6.1"},
	{"FortiNDR", "7.4", "7.4.0", "7.4.7", "7.4.8"},
	{"FortiNDR", "7.2", "7.2.0", "7.2.4", "7.2.5"},
	{"FortiNDR", "7.0", "7.0.0", "7.0.6", "7.0.7"},
	{"FortiRecorder", "7.2", "7.2.0", "7.2.3", "7.2.4"},
	{"FortiRecorder", "7.0", "7.0.0", "7.0.5", "7.0.6"},
	{"FortiRecorder", "6.4", "6.4.0", "6.4.5", "6.4.6"},
	{"FortiVoice", "7.2", "7.2.0", "7.2.0", "7.2.1"},
	{"FortiVoice", "7.0", "7.0.0", "7.0.6", "7.0.7"},
	{"FortiVoice", "6.4", "6.4.0", "6.4.10", "6.4.11"},
}
