package research

import (
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// This file is E6's freeze-gate battery, covering both the original
// producer contract (authority, zero-FP, provenance) AND the three
// freeze-blockers from the follow-up audit:
//
//   E6-A: an Expectation is resolved from a TransitionRuleRegistry, keyed by
//         the transition's OWN (ActionID, ProjectorID) — never supplied
//         independently alongside the transition, which would let a caller
//         mismatch a legitimately authoritative Expectation to the wrong
//         action.
//   E6-B: ExpectFactTransition has an explicit PRECONDITION: a before value
//         that never matches the rule's declared BeforeValue is
//         TransitionNotApplicable, never TransitionViolated.
//   E6-C: transitionCaseArtifactHash is proven, by direct test, to be
//         sensitive to EACH of BeforeFingerprint, AfterFingerprint, the
//         action identity, ScopeHash, Expectation, and ExpectationSource
//         independently — never a bare json.Marshal of the opaque
//         Fingerprint/BoundAction types (which would silently serialize to
//         "{}", since both keep their real fields unexported).
//
// Every fixture below builds REAL, non-zero stateauth.Fingerprint and
// actionauth.BoundAction values through their own authority packages
// (HTTPFixtureRegistry + ActionPolicy.Select) — never a struct literal —
// because both types refuse to be constructed with a real identity from
// outside their own package, and a test that could fake one would not
// actually be testing the authority boundary at all.

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

// e6BoundActionForKey obtains a REAL actionauth.BoundAction, registered under
// actionKey, via ActionPolicy.Select — the only place, in any package, a
// non-zero BoundAction is ever produced — bound to scopeHash and fp's own
// StateFingerprintHash, exactly as a real Explorer session would.
func e6BoundActionForKey(t *testing.T, actionKey, scopeHash string, fp stateauth.Fingerprint) actionauth.BoundAction {
	t.Helper()
	registry := actionauth.NewRegistry(actionauth.Registration{
		Action:       actionauth.RegisteredAction{Key: actionKey},
		Requirements: actionauth.StateRequirements{ProjectorID: fp.ProjectorID()},
	})
	policy := actionauth.NewActionPolicy(registry, actionauth.NewRecoveryRegistry())
	bound, ok := policy.Select(scopeHash, fp, nil)
	if !ok {
		t.Fatalf("ActionPolicy.Select: expected a match for action %q, got none", actionKey)
	}
	return bound
}

func e6BoundAction(t *testing.T, scopeHash string, fp stateauth.Fingerprint) actionauth.BoundAction {
	t.Helper()
	return e6BoundActionForKey(t, "noop", scopeHash, fp)
}

// e6TransitionWithAction builds a self-consistent, fully-authorized
// StateTransition using the given already-bound action, exactly as
// Explorer.Step would leave it.
func e6TransitionWithAction(before, after stateauth.Fingerprint, action actionauth.BoundAction) StateTransition {
	return StateTransition{
		ScopeHash:              e6ScopeHash,
		BeforeFingerprint:      before,
		Action:                 action,
		AfterFingerprint:       after,
		EvidenceRefs:           []string{"evidence-1"},
		TransitionArtifactHash: "explorer-own-transition-artifact-hash",
		Timestamp:              time.Now().UTC(),
	}
}

// e6Transition is the common case: one registered action key ("noop"),
// bound fresh for this transition.
func e6Transition(t *testing.T, before, after stateauth.Fingerprint) StateTransition {
	t.Helper()
	return e6TransitionWithAction(before, after, e6BoundAction(t, e6ScopeHash, before))
}

func e6AuthoritativeSource() ExpectationSource {
	return ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "e6-test-config"}
}

// e6RuleFor builds a TransitionRule matching tr's own (ActionID,
// ProjectorID) — the registration a real deployment would author BEFORE
// running the Explorer session that produces tr.
func e6RuleFor(tr StateTransition, expectation TransitionExpectation, source ExpectationSource) TransitionRule {
	return TransitionRule{
		RuleID:            "rule-under-test",
		ActionID:          tr.Action.ID(),
		ProjectorID:       tr.BeforeFingerprint.ProjectorID(),
		Expectation:       expectation,
		ExpectationSource: source,
	}
}

// e6MustRegistry builds a TransitionRuleRegistry and fails the test
// immediately if NewTransitionRuleRegistry rejects it — every "happy path"
// test below is asserting behavior of a registry that WAS built
// successfully, so a construction error there is a test setup bug, not the
// thing under test.
func e6MustRegistry(t *testing.T, rules ...TransitionRule) *TransitionRuleRegistry {
	t.Helper()
	reg, err := NewTransitionRuleRegistry(rules...)
	if err != nil {
		t.Fatalf("NewTransitionRuleRegistry: %v", err)
	}
	return reg
}

// --- E6-A: rule resolution is bound to (ActionID, ProjectorID) -------------

// TestE6NoRegisteredRuleMeansNoJudgment covers gate #1 ("无 ExpectationSource
// -> reject") and #3 ("State A != State B 但没有 expectation -> 0 candidate")
// under the new registry design: with NO TransitionRule registered for this
// transition's action at all, Produce must never invent something to judge
// against, even though the states genuinely differ.
func TestE6NoRegisteredRuleMeansNoJudgment(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 500, "error")
	tr := e6Transition(t, before, after)
	p := NewStateMachineProducer(e6MustRegistry(t)) // empty registry
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce with no registered rule = %v, want nil", got)
	}
	assessment, _ := p.Analyze(TransitionCase{Transition: tr})
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("Analyze with no registered rule = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
}

// TestE6AIOrLLMSourceRejectedAtRegistration: a TransitionRule with a
// non-authoritative ExpectationSource is refused by NewTransitionRuleRegistry
// itself — it never even reaches a producer's Produce/Analyze.
func TestE6AIOrLLMSourceRejectedAtRegistration(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	for _, kind := range []ExpectationSourceKind{"ai", "llm", "candidate", "proposal", "fuzz", "diff", "state_machine"} {
		tr := e6Transition(t, before, after)
		rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, ExpectationSource{Kind: kind, ID: "whatever"})
		if _, err := NewTransitionRuleRegistry(rule); err == nil {
			t.Fatalf("NewTransitionRuleRegistry with ExpectationSource.Kind=%q = nil error, want a rejection (non-authoritative)", kind)
		}
	}
}

// TestE6ValidateItselfRejectsNonAuthoritativeSource is the defense-in-depth
// layer: resolvedTransitionCase.validate() independently re-checks
// ExpectationSource authority too, rather than assuming every
// resolvedTransitionCase in existence necessarily passed through
// NewTransitionRuleRegistry's own gate. Constructed by hand (bypassing the
// registry entirely) specifically to isolate validate() itself.
func TestE6ValidateItselfRejectsNonAuthoritativeSource(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rc := resolvedTransitionCase{
		Transition: tr,
		Rule: TransitionRule{
			RuleID:            "hand-built-rule",
			ActionID:          tr.Action.ID(),
			ProjectorID:       before.ProjectorID(),
			Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
			ExpectationSource: ExpectationSource{Kind: "ai", ID: "whatever"},
		},
	}
	if rc.validate() {
		t.Fatal("resolvedTransitionCase.validate() must independently reject a non-authoritative ExpectationSource")
	}
}

// TestE6RuleRegisteredForOneActionNeverAppliesToAnother is the core new
// guarantee E6-A adds: a legitimately authoritative rule, registered for
// action "action-a", must NEVER be applied to a transition whose actual
// action is "action-b" — even though both share the same projector and the
// same scope. Before the registry existed, an Expectation and
// ExpectationSource were free-form caller input alongside ANY transition, so
// nothing stopped exactly this mismatch.
func TestE6RuleRegisteredForOneActionNeverAppliesToAnother(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	afterA := e6Fingerprint(t, 200, "ok") // satisfies fact_equals(status=200) if it were checked
	afterB := e6Fingerprint(t, 999, "should never be judged by action-a's rule")

	actionA := e6BoundActionForKey(t, "action-a", e6ScopeHash, before)
	actionB := e6BoundActionForKey(t, "action-b", e6ScopeHash, before)

	trA := e6TransitionWithAction(before, afterA, actionA)
	ruleA := e6RuleFor(trA, TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"}, e6AuthoritativeSource())

	registry := e6MustRegistry(t, ruleA) // ONLY action-a has a registered rule
	p := NewStateMachineProducer(registry)

	// action-a's own transition: satisfied, 0 candidates.
	if got := p.Produce(TransitionCase{Transition: trA}); got != nil {
		t.Fatalf("Produce (action-a, satisfied) = %v, want nil", got)
	}

	// action-b's transition, even with a status that WOULD have violated
	// action-a's rule, must produce nothing: no rule is registered for
	// action-b, so action-a's rule must never be reused for it.
	trB := e6TransitionWithAction(before, afterB, actionB)
	if got := p.Produce(TransitionCase{Transition: trB}); got != nil {
		t.Fatalf("Produce (action-b, no rule registered for it) = %v, want nil — action-a's rule must never apply to action-b", got)
	}
}

// TestE6ZeroValueBoundActionRejectedEvenIfRuleRegisteredForItsID proves
// defense in depth for gate #12: even a rule mistakenly registered against
// the ZERO-VALUE ActionID cannot turn a zero-value (never authorized)
// BoundAction into a judgeable transition — ValidFor gates on real
// authorization regardless of what the registry contains.
func TestE6ZeroValueBoundActionRejectedEvenIfRuleRegisteredForItsID(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6TransitionWithAction(before, after, actionauth.BoundAction{}) // never actually authorized
	rule := TransitionRule{
		RuleID:            "phantom-rule",
		ActionID:          actionauth.BoundAction{}.ID(), // zero-value ActionID, matching tr.Action.ID()
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (zero-value BoundAction, rule registered for its zero ActionID) = %v, want nil", got)
	}
}

// --- final freeze condition: TransitionRuleRegistry structurally guarantees
// "(ActionID, ProjectorID) -> exactly one rule" at CONSTRUCTION time, not by
// lookup convention. --------------------------------------------------------

// TestE6DuplicateActionProjectorPairRejectedAtRegistration is the core
// guarantee: two DIFFERENT rules registered for the SAME (ActionID,
// ProjectorID) pair must never be allowed to coexist — which one lookup
// would return could otherwise depend on slice order, map iteration order,
// or another implementation detail, never a deterministic authority.
func TestE6DuplicateActionProjectorPairRejectedAtRegistration(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	action := e6BoundActionForKey(t, "shared-action", e6ScopeHash, before)
	tr := e6TransitionWithAction(before, before, action)

	ruleA := TransitionRule{
		RuleID:            "rule-a",
		ActionID:          tr.Action.ID(),
		ProjectorID:       tr.BeforeFingerprint.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	ruleB := TransitionRule{
		RuleID:            "rule-b", // different RuleID, but the SAME (ActionID, ProjectorID)
		ActionID:          tr.Action.ID(),
		ProjectorID:       tr.BeforeFingerprint.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if _, err := NewTransitionRuleRegistry(ruleA, ruleB); err == nil {
		t.Fatal("NewTransitionRuleRegistry with two rules sharing (ActionID, ProjectorID) = nil error, want a rejection")
	}
}

// TestE6DuplicateRuleIDRejectedAtRegistration: two rules (even for different
// actions) must never share a RuleID — a RuleID is meant to be an
// independent audit handle, and letting two DIFFERENT rules claim the same
// one would make Refs["rule_id"] ambiguous.
func TestE6DuplicateRuleIDRejectedAtRegistration(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	actionA := e6BoundActionForKey(t, "action-a", e6ScopeHash, before)
	actionB := e6BoundActionForKey(t, "action-b", e6ScopeHash, before)

	ruleA := TransitionRule{
		RuleID:            "shared-rule-id",
		ActionID:          actionA.ID(),
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	ruleB := TransitionRule{
		RuleID:            "shared-rule-id", // same RuleID, different action
		ActionID:          actionB.ID(),
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if _, err := NewTransitionRuleRegistry(ruleA, ruleB); err == nil {
		t.Fatal("NewTransitionRuleRegistry with a duplicate RuleID = nil error, want a rejection")
	}
}

// TestE6EmptyRuleIDRejectedAtRegistration: a RuleID is the audit handle
// Refs["rule_id"] points at — an empty one is never accepted.
func TestE6EmptyRuleIDRejectedAtRegistration(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	action := e6BoundActionForKey(t, "some-action", e6ScopeHash, before)
	rule := TransitionRule{
		RuleID:            "",
		ActionID:          action.ID(),
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectStateUnchanged},
		ExpectationSource: e6AuthoritativeSource(),
	}
	if _, err := NewTransitionRuleRegistry(rule); err == nil {
		t.Fatal("NewTransitionRuleRegistry with an empty RuleID = nil error, want a rejection")
	}
}

// TestE6RuleRegistryUnaffectedByMutatingCallersSliceAfterConstruction proves
// a built registry is independent of the slice it was built from: mutating
// the caller's own slice element AFTER construction must have no effect on
// anything the registry resolves — TransitionRule holds no pointers/slices,
// so range-copying each rule into the registry's own map already severs the
// connection; this test proves it rather than merely asserting it.
func TestE6RuleRegistryUnaffectedByMutatingCallersSliceAfterConstruction(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)

	rules := []TransitionRule{e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"}, e6AuthoritativeSource())}
	registry := e6MustRegistry(t, rules...)

	// Mutate the caller's own slice element AFTER the registry was built —
	// flip it to a rule that WOULD be satisfied (so if the registry were
	// somehow still aliasing this data, the outcome below would flip too).
	rules[0].Expectation = TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "403"}
	rules[0].ExpectationSource = ExpectationSource{Kind: "ai", ID: "mutated-after-construction"}

	p := NewStateMachineProducer(registry)
	got := p.Produce(TransitionCase{Transition: tr}) // after.status=403 != the ORIGINAL rule's AfterValue=200
	if len(got) != 1 {
		t.Fatalf("Produce after mutating caller's slice = %d candidates, want exactly 1 (registry must still use the ORIGINAL rule: AfterValue=200, violated)", len(got))
	}
}

// --- state_unchanged ---------------------------------------------------------

func TestE6StateUnchangedRealChangeProducesExactlyOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	got := p.Produce(TransitionCase{Transition: tr})
	if len(got) != 1 {
		t.Fatalf("Produce (state changed, expected unchanged) = %d candidates, want exactly 1", len(got))
	}
}

func TestE6StateUnchangedNoChangeProducesNoCandidate(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (state genuinely unchanged) = %v, want nil", got)
	}
}

// --- fact_unchanged with an absent fact -> insufficient evidence -----------

func TestE6FactUnchangedMissingFactIsInsufficientEvidenceNotViolation(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactUnchanged, Fact: "no_such_fact"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	assessment, anomalies := p.Analyze(TransitionCase{Transition: tr})
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("Analyze (missing fact) assessment = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
	if anomalies != nil {
		t.Fatalf("Analyze (missing fact) anomalies = %v, want nil", anomalies)
	}
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (missing fact) = %v, want nil", got)
	}
}

// --- fact_equals -------------------------------------------------------------

func TestE6FactEqualsObservedMatchesExpectedProducesNoCandidate(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 200, "ok")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (fact_equals satisfied) = %v, want nil", got)
	}
}

func TestE6FactEqualsObservedDiffersFromExpectedProducesOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	got := p.Produce(TransitionCase{Transition: tr})
	if len(got) != 1 {
		t.Fatalf("Produce (fact_equals violated) = %d candidates, want exactly 1", len(got))
	}
}

// --- E6-B: fact_transition, including the new not_applicable state --------

func TestE6FactTransitionNormalABProducesNoCandidate(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	assessment, _ := p.Analyze(TransitionCase{Transition: tr})
	if assessment != TransitionSatisfied {
		t.Fatalf("Analyze (fact_transition A->B as declared) = %q, want %q", assessment, TransitionSatisfied)
	}
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (fact_transition satisfied, A->B as declared) = %v, want nil", got)
	}
}

func TestE6FactTransitionActuallyGoesToCProducesOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 500, "error") // declared AfterValue is 403, observed is 500
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	assessment, _ := p.Analyze(TransitionCase{Transition: tr})
	if assessment != TransitionViolated {
		t.Fatalf("Analyze (fact_transition A->C not A->B) = %q, want %q", assessment, TransitionViolated)
	}
	got := p.Produce(TransitionCase{Transition: tr})
	if len(got) != 1 {
		t.Fatalf("Produce (fact_transition violated, A->C not A->B) = %d candidates, want exactly 1", len(got))
	}
}

// TestE6FactTransitionPreconditionNeverHeldIsNotApplicable is the E6-B fix
// itself: the observed transition did not even start at the rule's declared
// BeforeValue, so the rule's "if before==A then after must==B" constraint
// never engaged. This must be TransitionNotApplicable, and must NEVER
// produce a candidate — treating it as "violated" would flag every
// transition the rule was simply never written for.
func TestE6FactTransitionPreconditionNeverHeldIsNotApplicable(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok") // rule's BeforeValue is declared as "999", not "200"
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "999", AfterValue: "403"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	assessment, anomalies := p.Analyze(TransitionCase{Transition: tr})
	if assessment != TransitionNotApplicable {
		t.Fatalf("Analyze (precondition before=200 != declared BeforeValue=999) = %q, want %q", assessment, TransitionNotApplicable)
	}
	if anomalies != nil {
		t.Fatalf("Analyze (not_applicable) anomalies = %v, want nil", anomalies)
	}
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (precondition never held) = %v, want nil: not_applicable must never produce a candidate", got)
	}
}

// TestE6FactTransitionBeforeMissingIsInsufficientEvidenceNotNotApplicable
// distinguishes "we don't know what before was" (insufficient_evidence) from
// "we know what before was, and it wasn't the declared precondition"
// (not_applicable) — the same absence-vs-mismatch discipline as
// analyzeFactUnchanged/analyzeFactEquals, now also proven for the
// precondition check itself.
func TestE6FactTransitionBeforeMissingIsInsufficientEvidenceNotNotApplicable(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "no_such_fact", BeforeValue: "200", AfterValue: "403"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	assessment, _ := p.Analyze(TransitionCase{Transition: tr})
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("Analyze (before fact absent) = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
}

// TestE6FactTransitionAfterMissingIsInsufficientEvidence covers "before
// matched the precondition, but the fact is absent from AFTER" ->
// insufficient_evidence, never violated and never satisfied. Both real
// projectors this codebase has (HTTPStateProjector, RawLenProjector) always
// populate a FIXED set of Fact keys regardless of input content, so this
// specific combination — the same named fact present before, absent after —
// cannot arise through Explorer's own validated Produce/Analyze path (which
// requires both fingerprints to share one projector, and therefore one fixed
// key set). It is still real defensive code (structurally identical to the
// analogous ok-checks in analyzeFactUnchanged/analyzeFactEquals, and a future
// projector's Facts could legitimately be content-dependent), so this test
// exercises analyzeFactTransition directly with two REAL, independently
// projector-built Fingerprints — deliberately bypassing Analyze's own
// validate() (which would reject a cross-projector transition before ever
// reaching this code path) to isolate the analyzer helper's own ok-check
// logic.
func TestE6FactTransitionAfterMissingIsInsufficientEvidence(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok") // HTTPStateProjector: has "status"
	after, err := stateauth.FixtureRegistry().Project(stateauth.StateArtifact{ScopeHash: e6ScopeHash, Raw: []byte("rawlen-fixture")})
	if err != nil {
		t.Fatalf("Project: %v", err)
	} // RawLenProjector: only "raw_len" — no "status" fact at all
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "200"}, e6AuthoritativeSource())
	rc := resolvedTransitionCase{Transition: tr, Rule: rule}
	assessment, anomalies := analyzeFactTransition(rc)
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("analyzeFactTransition (after fact absent) = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
	if anomalies != nil {
		t.Fatalf("analyzeFactTransition (after fact absent) anomalies = %v, want nil", anomalies)
	}
}

// --- scope-inconsistent / illegal action, with a rule that WOULD otherwise apply

func TestE6ScopeInconsistentTransitionRejected(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	tr.ScopeHash = "a-completely-different-scope" // now self-contradictory, AFTER the rule was keyed on the original action
	if tr.ScopeConsistent() {
		t.Fatal("test setup bug: transition must actually be scope-inconsistent")
	}
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	if got := p.Produce(TransitionCase{Transition: tr}); got != nil {
		t.Fatalf("Produce (scope-inconsistent transition) = %v, want nil", got)
	}
}

// --- Candidate.State is always Hypothesis -----------------------------------

func TestE6ProducedCandidateStateIsAlwaysHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	got := p.Produce(TransitionCase{Transition: tr})
	if len(got) != 1 {
		t.Fatalf("setup: expected exactly 1 candidate, got %d", len(got))
	}
	if got[0].State != Hypothesis {
		t.Fatalf("Candidate.State = %q, want %q", got[0].State, Hypothesis)
	}
}

// --- Candidate.Provenance().RawInputHash == resolved case hash -------------

func TestE6CandidateRawInputHashIsCaseHashNotTransitionArtifactHash(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	got := p.Produce(TransitionCase{Transition: tr})
	if len(got) != 1 {
		t.Fatalf("setup: expected exactly 1 candidate, got %d", len(got))
	}
	wantCaseHash := transitionCaseArtifactHash(resolvedTransitionCase{Transition: tr, Rule: rule})
	rawInputHash := got[0].Provenance().RawInputHash
	if rawInputHash != wantCaseHash {
		t.Fatalf("Provenance().RawInputHash = %q, want the resolved case artifact hash %q", rawInputHash, wantCaseHash)
	}
	if rawInputHash == tr.TransitionArtifactHash {
		t.Fatalf("Provenance().RawInputHash must NEVER equal StateTransition.TransitionArtifactHash alone (it omits the resolved Rule)")
	}
	if got[0].Refs["transition_artifact_hash"] != tr.TransitionArtifactHash {
		t.Fatalf("Refs[transition_artifact_hash] = %q, want %q (still recorded, just not as RawInputHash)",
			got[0].Refs["transition_artifact_hash"], tr.TransitionArtifactHash)
	}
	if got[0].Refs["case_artifact_hash"] != wantCaseHash {
		t.Fatalf("Refs[case_artifact_hash] = %q, want %q", got[0].Refs["case_artifact_hash"], wantCaseHash)
	}
	if got[0].Refs["rule_id"] != rule.RuleID {
		t.Fatalf("Refs[rule_id] = %q, want %q", got[0].Refs["rule_id"], rule.RuleID)
	}
}

// --- E6-C: transitionCaseArtifactHash canonical-DTO coverage ---------------
//
// Each test below constructs two resolvedTransitionCase values differing in
// EXACTLY ONE field and proves the hash differs — direct evidence that
// transitionCaseArtifactHash actually reads through to that field via
// Fingerprint/BoundAction's real accessor methods, rather than silently
// hashing "{}" for an opaque struct it never actually unpacked.

func e6BaseResolvedCase(t *testing.T) resolvedTransitionCase {
	t.Helper()
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"}, e6AuthoritativeSource())
	return resolvedTransitionCase{Transition: tr, Rule: rule}
}

func TestE6CaseArtifactHashStableForIdenticalCase(t *testing.T) {
	rc := e6BaseResolvedCase(t)
	h1 := transitionCaseArtifactHash(rc)
	h2 := transitionCaseArtifactHash(rc)
	if h1 != h2 {
		t.Fatalf("transitionCaseArtifactHash is not stable across calls on the identical case: %q != %q", h1, h2)
	}
}

func TestE6CaseArtifactHashChangesWhenBeforeFingerprintChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	changed := base
	changed.Transition.BeforeFingerprint = e6Fingerprint(t, 201, "different before body")
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ONLY BeforeFingerprint changes")
	}
}

func TestE6CaseArtifactHashChangesWhenAfterFingerprintChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	changed := base
	changed.Transition.AfterFingerprint = e6Fingerprint(t, 404, "different after body")
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ONLY AfterFingerprint changes")
	}
}

func TestE6CaseArtifactHashChangesWhenActionIdentityChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	// A different BoundAction, same scope/state, same projector, but a
	// DIFFERENT registered action key -> a different ActionID.
	otherAction := e6BoundActionForKey(t, "a-different-action-key", e6ScopeHash, base.Transition.BeforeFingerprint)
	changed := base
	changed.Transition.Action = otherAction
	if base.Transition.Action.ID() == changed.Transition.Action.ID() {
		t.Fatal("test setup bug: the two BoundActions must have different ActionIDs")
	}
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ONLY the action identity changes")
	}
}

func TestE6CaseArtifactHashChangesWhenScopeHashChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	changed := base
	changed.Transition.ScopeHash = "a-different-scope-hash-string"
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ONLY Transition.ScopeHash changes")
	}
}

func TestE6CaseArtifactHashChangesWhenExpectationChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	changed := base
	changed.Rule.Expectation.AfterValue = "a-different-after-value" // only the Expectation moved
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when Expectation changes")
	}
}

func TestE6CaseArtifactHashChangesWhenExpectationSourceIDChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	changed := base
	changed.Rule.ExpectationSource.ID = "a-different-config-pointer" // only ExpectationSource.ID moved
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ExpectationSource.ID changes")
	}
}
