package activemq

import (
	"testing"

	"gopoc/checks/detect"
)

// TestAffectedBoundaries pins every branch edge from the CVE Program record,
// cross-checked against four real Apache ActiveMQ binaries this round:
// 5.16.6, 5.17.5, and 5.18.2 vulnerable; 5.17.6 fixed (see
// docs/activemq-attack-surface.md). The other three fix boundaries (5.15.16,
// 5.16.7, 5.18.3) are pinned here even though only one branch's edge was run
// against a live binary — same discipline as WebLogic's CPU-2026-07 batch.
func TestAffectedBoundaries(t *testing.T) {
	cases := []struct {
		version string
		want    bool
		fixed   string
	}{
		// 5.18 branch: last-vulnerable and first-fixed both real binaries.
		{"5.18.2", true, "5.18.3"},  // real binary tested this round
		{"5.18.3", false, ""},       // fixed release, boundary edge
		{"5.18.0", true, "5.18.3"},  // branch floor

		// 5.17 branch: both edges are real binaries tested this round.
		{"5.17.5", true, "5.17.6"}, // real binary tested this round (vulnerable)
		{"5.17.6", false, ""},      // real binary tested this round (fixed)
		{"5.17.0", true, "5.17.6"},

		// 5.16 branch: last-vulnerable is a real binary.
		{"5.16.6", true, "5.16.7"}, // real binary tested this round
		{"5.16.7", false, ""},
		{"5.16.0", true, "5.16.7"},

		// Legacy line: everything below 5.15.16.
		{"5.15.15", true, "5.15.16"},
		{"5.15.16", false, ""},
		{"5.14.5", true, "5.15.16"},
		{"5.0.0", true, "5.15.16"},

		// Unaffected: newer than every fixed release, and the pre-5.x line.
		{"5.19.0", false, ""},
		{"5.18.4", false, ""},
		{"6.0.0", false, ""},
	}
	for _, tc := range cases {
		v, ok := detect.ParseVersion(tc.version)
		if !ok {
			t.Fatalf("ParseVersion(%q) failed", tc.version)
		}
		gotAff, gotFixed := affected(v)
		if gotAff != tc.want {
			t.Errorf("affected(%s) = %v, want %v", tc.version, gotAff, tc.want)
		}
		if gotAff && gotFixed != tc.fixed {
			t.Errorf("affected(%s) fixed = %q, want %q", tc.version, gotFixed, tc.fixed)
		}
	}
}
