package research

import (
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// This file is E6's freeze-gate battery: the exact list of behaviors the S10
// state-machine Candidate Producer contract must satisfy before it can be
// considered locked. Every fixture below builds REAL, non-zero
// stateauth.Fingerprint and actionauth.BoundAction values through their own
// authority packages (HTTPFixtureRegistry + ActionPolicy.Select) — never a
// struct literal — because both types refuse to be constructed with a real
// identity from outside their own package, and a test that could fake one
// would not actually be testing the authority boundary at all.

const e6ScopeHash = "e6-scope"

// e6Fingerprint builds a REAL stateauth.Fingerprint via HTTPStateProjector
// (through stateauth.HTTPFixtureRegistry — the only exported way to obtain
// one), so its Facts (status/content_type/body_sha256) are authentic
// projector output, not a fabricated map a test assembled by hand.
func e6Fingerprint(t *testing.T, status int, body string) stateauth.Fingerprint {
	t.Helper()
	raw, err := stateauth.MarshalHTTPArtifact(stateauth.HTTPArtifact{Status: status, ContentType: "application/json", Body: []byte(body)})
	if err != nil {
		t.Fatalf("MarshalHTTPArtifact: %v", err)
	}
	fp, err := stateauth.HTTPFixtureRegistry().Project(stateauth.StateArtifact{ScopeHash: e6ScopeHash, Raw: raw})
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	return fp
}

// e6BoundAction obtains a REAL actionauth.BoundAction via ActionPolicy.Select
// — the only place, in any package, a non-zero BoundAction is ever produced —
// bound to scopeHash and fp's own StateFingerprintHash, exactly as a real
// Explorer session would.
func e6BoundAction(t *testing.T, scopeHash string, fp stateauth.Fingerprint) actionauth.BoundAction {
	t.Helper()
	registry := actionauth.NewRegistry(actionauth.Registration{
		Action:       actionauth.RegisteredAction{Key: "noop"},
		Requirements: actionauth.StateRequirements{ProjectorID: fp.ProjectorID()},
	})
	policy := actionauth.NewActionPolicy(registry, actionauth.NewRecoveryRegistry())
	bound, ok := policy.Select(scopeHash, fp, nil)
	if !ok {
		t.Fatal("ActionPolicy.Select: expected a match, got none")
	}
	return bound
}

// e6Transition builds a self-consistent, fully-authorized StateTransition:
// ScopeConsistent() is true and Action.ValidFor(...) is true, exactly as
// Explorer.Step would leave it.
func e6Transition(t *testing.T, before, after stateauth.Fingerprint) StateTransition {
	t.Helper()
	return StateTransition{
		ScopeHash:              e6ScopeHash,
		BeforeFingerprint:      before,
		Action:                 e6BoundAction(t, e6ScopeHash, before),
		AfterFingerprint:       after,
		EvidenceRefs:           []string{"evidence-1"},
		TransitionArtifactHash: "explorer-own-transition-artifact-hash",
		Timestamp:              time.Now().UTC(),
	}
}

func e6AuthoritativeSource() ExpectationSource {
	return ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "e6-test-config"}
}

// --- 1. no ExpectationSource -> reject / 0 candidates -----------------------

func TestE6NoExpectationSourceRejected(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: ExpectationSource{}, // zero value: no Kind at all
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce with no ExpectationSource = %v, want nil", got)
	}
}

// --- 2. AI/LLM source -> reject / 0 candidates ------------------------------

func TestE6AIOrLLMSourceRejected(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	for _, kind := range []ExpectationSourceKind{"ai", "llm", "candidate", "proposal", "fuzz", "diff", "state_machine"} {
		c := TransitionCase{
			Transition:        e6Transition(t, before, after),
			Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
			ExpectationSource: ExpectationSource{Kind: kind, ID: "whatever"},
		}
		if got := NewStateMachineProducer().Produce(c); got != nil {
			t.Fatalf("Produce with ExpectationSource.Kind=%q = %v, want nil (non-authoritative)", kind, got)
		}
	}
}

// --- 3. State A != State B but no declared Expectation -> 0 candidates -----

func TestE6DifferentStatesWithoutExpectationIsNotAnAnomaly(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 500, "error")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{}, // no Kind declared
		ExpectationSource: e6AuthoritativeSource(),
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce with no declared Expectation.Kind = %v, want nil: differing states are never themselves an anomaly", got)
	}
}

// --- 4/5. state_unchanged ----------------------------------------------------

func TestE6StateUnchangedRealChangeProducesExactlyOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	got := NewStateMachineProducer().Produce(c)
	if len(got) != 1 {
		t.Fatalf("Produce (state changed, expected unchanged) = %d candidates, want exactly 1", len(got))
	}
}

func TestE6StateUnchangedNoChangeProducesNoCandidate(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce (state genuinely unchanged) = %v, want nil", got)
	}
}

// --- 6. fact_unchanged with an absent fact -> insufficient evidence --------

func TestE6FactUnchangedMissingFactIsInsufficientEvidenceNotViolation(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectFactUnchanged, Fact: "no_such_fact"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	p := NewStateMachineProducer()
	assessment, anomalies := p.Analyze(c)
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("Analyze (missing fact) assessment = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
	if anomalies != nil {
		t.Fatalf("Analyze (missing fact) anomalies = %v, want nil", anomalies)
	}
	if got := p.Produce(c); got != nil {
		t.Fatalf("Produce (missing fact) = %v, want nil", got)
	}
}

// --- 7/8. fact_equals --------------------------------------------------------

func TestE6FactEqualsObservedMatchesExpectedProducesNoCandidate(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce (fact_equals satisfied) = %v, want nil", got)
	}
}

func TestE6FactEqualsObservedDiffersFromExpectedProducesOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	got := NewStateMachineProducer().Produce(c)
	if len(got) != 1 {
		t.Fatalf("Produce (fact_equals violated) = %d candidates, want exactly 1", len(got))
	}
}

// --- 9/10. fact_transition ---------------------------------------------------

func TestE6FactTransitionNormalABProducesNoCandidate(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce (fact_transition satisfied, A->B as declared) = %v, want nil", got)
	}
}

func TestE6FactTransitionActuallyGoesToCProducesOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 500, "error") // declared AfterValue is 403, observed is 500
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	got := NewStateMachineProducer().Produce(c)
	if len(got) != 1 {
		t.Fatalf("Produce (fact_transition violated, A->C not A->B) = %d candidates, want exactly 1", len(got))
	}
}

// --- 11. scope-inconsistent transition -> reject ----------------------------

func TestE6ScopeInconsistentTransitionRejected(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	tr.ScopeHash = "a-completely-different-scope" // now self-contradictory
	if tr.ScopeConsistent() {
		t.Fatal("test setup bug: transition must actually be scope-inconsistent")
	}
	c := TransitionCase{
		Transition:        tr,
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce (scope-inconsistent transition) = %v, want nil", got)
	}
}

// --- 12. illegal / zero-value BoundAction transition -> reject -------------

func TestE6ZeroValueBoundActionTransitionRejected(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	tr.Action = actionauth.BoundAction{} // never actually authorized
	c := TransitionCase{
		Transition:        tr,
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if got := NewStateMachineProducer().Produce(c); got != nil {
		t.Fatalf("Produce (zero-value BoundAction) = %v, want nil", got)
	}
}

// --- 13. Candidate.State is always Hypothesis -------------------------------

func TestE6ProducedCandidateStateIsAlwaysHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	got := NewStateMachineProducer().Produce(c)
	if len(got) != 1 {
		t.Fatalf("setup: expected exactly 1 candidate, got %d", len(got))
	}
	if got[0].State != Hypothesis {
		t.Fatalf("Candidate.State = %q, want %q", got[0].State, Hypothesis)
	}
}

// --- 14. Candidate.Provenance().RawInputHash == case hash, != TransitionArtifactHash

func TestE6CandidateRawInputHashIsCaseHashNotTransitionArtifactHash(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	got := NewStateMachineProducer().Produce(c)
	if len(got) != 1 {
		t.Fatalf("setup: expected exactly 1 candidate, got %d", len(got))
	}
	wantCaseHash := transitionCaseArtifactHash(c)
	rawInputHash := got[0].Provenance().RawInputHash
	if rawInputHash != wantCaseHash {
		t.Fatalf("Provenance().RawInputHash = %q, want the TransitionCase artifact hash %q", rawInputHash, wantCaseHash)
	}
	if rawInputHash == c.Transition.TransitionArtifactHash {
		t.Fatalf("Provenance().RawInputHash must NEVER equal StateTransition.TransitionArtifactHash alone (it omits Expectation/ExpectationSource)")
	}
	if got[0].Refs["transition_artifact_hash"] != c.Transition.TransitionArtifactHash {
		t.Fatalf("Refs[transition_artifact_hash] = %q, want %q (still recorded, just not as RawInputHash)",
			got[0].Refs["transition_artifact_hash"], c.Transition.TransitionArtifactHash)
	}
	if got[0].Refs["case_artifact_hash"] != wantCaseHash {
		t.Fatalf("Refs[case_artifact_hash] = %q, want %q", got[0].Refs["case_artifact_hash"], wantCaseHash)
	}
}

// --- 15/16/17. transitionCaseArtifactHash stability and sensitivity --------

func TestE6CaseArtifactHashStableForIdenticalCase(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	c := TransitionCase{
		Transition:        e6Transition(t, before, after),
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	h1 := transitionCaseArtifactHash(c)
	h2 := transitionCaseArtifactHash(c)
	if h1 != h2 {
		t.Fatalf("transitionCaseArtifactHash is not stable across calls on the identical case: %q != %q", h1, h2)
	}
}

func TestE6CaseArtifactHashChangesWhenExpectationChanges(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	base := TransitionCase{
		Transition:        tr,
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	changed := base
	changed.Expectation.AfterValue = "418" // only the Expectation moved
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when Expectation changes")
	}
}

func TestE6CaseArtifactHashChangesWhenExpectationSourceIDChanges(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	base := TransitionCase{
		Transition:        tr,
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	changed := base
	changed.ExpectationSource.ID = "a-different-config-pointer" // only ExpectationSource.ID moved
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ExpectationSource.ID changes")
	}
}
