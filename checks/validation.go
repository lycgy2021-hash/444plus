package checks

import "gopoc/internal/model"

// validationRecords is the one place every checker's validation status is
// recorded, keyed by checker ID exactly as each package's own ID constant is
// spelled. Centralizing it here — rather than inlining a Validation literal
// into 12 product packages' Metadata — means reviewing or updating a
// checker's validation status never touches its detection logic, and this
// file alone is where "is this actually real-machine tested" gets answered.
//
// Fill this in as a checker's status changes; nothing recomputes it
// automatically (see model.Validation's LastValidatedCommit doc — comparing
// that against a checker's current file history to flag a stale record is
// deliberately left for later).
var validationRecords = map[string]model.Validation{
	"CVE-2021-41773": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"2.4.49"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			PositivePath:    true,
		},
		EvidenceRefs: []string{"CHANGELOG.md#coverage"},
	},
	"CVE-2021-42013": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"2.4.50"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			PositivePath:    true,
		},
		EvidenceRefs: []string{"CHANGELOG.md#coverage"},
	},
	"CVE-2025-1974": {
		Tier:         model.ValidationLive,
		TestedStates: []string{"k3d_v1.11.2_cluster"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			PositivePath:    true,
		},
		EvidenceRefs: []string{"CHANGELOG.md#coverage"},
	},
	"CVE-2025-24813": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"9.0.97", "9.0.99"},
		TestedStates:   []string{"writable_default_servlet", "readonly_default", "fixed_version"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			NegativePath:    true,
			PositivePath:    true,
			FixedPath:       true,
		},
		EvidenceRefs: []string{"docs/regression-baseline.md#tomcat-3-state-cve-2025-24813"},
	},
	"CVE-2023-21839": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"12.2.1.3"},
		TestedStates:   []string{"http_and_t3_exposed"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			PositivePath:    true,
		},
		EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"},
	},
	// The CPU-2026-07 batch shares WebLogic's assessment cache with
	// CVE-2023-21839 and was run against the same live 12.2.1.3 instance —
	// but only to observe version_not_affected (12.2.1.3 predates the
	// 12.2.1.4+ affected range), never against an affected build.
	"CVE-2026-60199": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},
	"CVE-2026-60291": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},
	"CVE-2026-60292": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},
	"CVE-2026-60200": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},
	"CVE-2026-60294": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},
	"CVE-2026-60198": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},
	"CVE-2026-60202": {Tier: model.ValidationLive, TestedVersions: []string{"12.2.1.3"}, TestedStates: []string{"version_not_affected_only"}, Coverage: &model.ValidationCoverage{ProductIdentity: true, NegativePath: true}, EvidenceRefs: []string{"docs/regression-baseline.md#weblogic-t3-multi-protocol-cve-2023-21839--cpu-2026-07"}},

	"MISCONFIG-JBOSSWILDFLY-UNAUTH-MGMT": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"38.0.0.Final", "41.0.1.Final"},
		TestedStates:   []string{"management_auth_required", "management_auth_removed", "app_port_404_then_9990", "welcome_page_only"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			NegativePath:    true,
			PositivePath:    true,
		},
		EvidenceRefs:        []string{"docs/regression-baseline.md#jbosswildfly-management-interface-two-state-real-validated", "docs/jboss-wildfly-attack-surface.md"},
		LastValidatedCommit: "fab3383",
	},
	"MISCONFIG-JENKINS-ANON-SCRIPT-CONSOLE": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"2.426.2", "2.568.3"},
		TestedStates:   []string{"secure_default", "anonymous_script_console", "login_redirect_protected"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			NegativePath:    true,
			PositivePath:    true,
		},
		EvidenceRefs:        []string{"docs/regression-baseline.md#jenkins-two-lines-four-state-real-validated"},
		LastValidatedCommit: "fab3383",
	},
	"CVE-2024-23897": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"2.426.2", "2.568.3"},
		TestedStates:   []string{"affected_cli_reachable", "fixed_version"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			PositivePath:    true,
			FixedPath:       true,
		},
		EvidenceRefs:        []string{"docs/regression-baseline.md#jenkins-two-lines-four-state-real-validated"},
		LastValidatedCommit: "fab3383",
	},

	// GitLab: real 16.6.0 tested. CVE-2023-7028 is the affected version anchor
	// (positive path confirmed live); the fixed boundary is unit-test-only, not
	// real-machine patched. CVE-2023-2825 is version-only against a version we
	// never actually ran (16.0.0), so fixture tier is more honest.
	"CVE-2023-7028": {
		Tier:           model.ValidationLive,
		TestedVersions: []string{"16.6.0"},
		TestedStates:   []string{"product_identity", "password_reset_reachable"},
		Coverage: &model.ValidationCoverage{
			ProductIdentity: true,
			PositivePath:    true,
		},
		EvidenceRefs:        []string{"docs/gitlab-attack-surface.md"},
		LastValidatedCommit: "749b531",
	},
	"CVE-2023-2825": {
		Tier:        model.ValidationFixture,
		EvidenceRefs: []string{"docs/gitlab-attack-surface.md"},
	},

	// Device/mock lines: unit- and FP-corpus-validated only. Fingerprints are
	// heuristic pending a real appliance — see CHANGELOG.md#coverage.
	"CVE-2024-55591": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-24472": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-32756": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-49704": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-49706": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-53770": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-53771": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2026-21962": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2026-60364": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-7775":  {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2025-6543":  {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2026-42533": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
	"CVE-2026-42238": {Tier: model.ValidationFixture, EvidenceRefs: []string{"CHANGELOG.md#coverage"}},
}

// checkerWithValidation decorates a Checker's Metadata with its validation
// record without requiring the product package itself to carry this
// bookkeeping — every product package keeps building Metadata exactly as it
// does today.
type checkerWithValidation struct {
	model.Checker
}

func (w checkerWithValidation) Metadata() model.Metadata {
	m := w.Checker.Metadata()
	if v, ok := validationRecords[m.ID]; ok {
		m.Validation = &v
	}
	return m
}

// withValidation wraps every checker in Builtin() so its reported Metadata
// carries validationRecords' entry for its ID, if any. A checker with no
// entry here reports Validation == nil — itself a signal that no one has
// recorded its status yet, rather than a false claim either way.
func withValidation(c model.Checker) model.Checker { return checkerWithValidation{Checker: c} }
