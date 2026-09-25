package netscaler

// AffectedRange is one NetScaler release line: affected below FixedBuild, or
// always affected when EOL (12.1 / 13.0 are end-of-life and unfixed). Branches
// are kept separate because FIPS/NDcPP and mainline patch on different lines.
type AffectedRange struct {
	Branch     string
	FixedBuild [2]int
	EOL        bool
}

// affected reports whether a version is affected, per its branch's fix line.
func affected(v nsVersion, ranges []AffectedRange) bool {
	for _, r := range ranges {
		if r.Branch != v.branch {
			continue
		}
		if r.EOL {
			return true
		}
		return lessBuild(v.build, r.FixedBuild)
	}
	return false
}

// affected7775 — CVE-2025-7775 (Citrix NetScaler ADC/Gateway memory overflow,
// unauthenticated, exploited in the wild). Fixed builds per Citrix CTX694938.
var affected7775 = []AffectedRange{
	{"14.1", [2]int{47, 48}, false},
	{"13.1", [2]int{59, 22}, false},
	{"13.1-FIPS", [2]int{37, 241}, false},
	{"13.1-NDcPP", [2]int{37, 241}, false},
	{"12.1-FIPS", [2]int{55, 330}, false},
	{"12.1-NDcPP", [2]int{55, 330}, false},
	{"12.1", [2]int{}, true}, // EOL, unfixed
	{"13.0", [2]int{}, true}, // EOL, unfixed
}

// affected6543 — CVE-2025-6543 (memory overflow -> unintended control flow / DoS,
// exploited in the wild). DIFFERENT fix line from 7775, and 12.1-FIPS/NDcPP are
// NOT affected — encoded by their absence from this table. Per Citrix CTX694788.
var affected6543 = []AffectedRange{
	{"14.1", [2]int{47, 46}, false},
	{"13.1", [2]int{59, 19}, false},
	{"13.1-FIPS", [2]int{37, 236}, false},
	{"13.1-NDcPP", [2]int{37, 236}, false},
	{"12.1", [2]int{}, true}, // EOL, unfixed
	{"13.0", [2]int{}, true}, // EOL, unfixed
}
