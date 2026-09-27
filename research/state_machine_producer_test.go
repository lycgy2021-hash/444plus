package research

import (
	"context"
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

// e6Scope is the real ExplorationScope every fixture below is built under.
// e6ScopeHash is its own Hash() — never an arbitrary literal string — so
// resolvedTransitionCase.validate()'s Scope-consistency check (Scope.Hash()
// == Transition.ScopeHash) genuinely holds for every fixture, exactly as it
// would for a real Explorer session.
var e6Scope = ExplorationScope{TargetID: "e6-target", BuildID: "e6-build", SessionID: "e6-session", Protocol: "http", HarnessID: "e6-harness"}
var e6ScopeHash = e6Scope.Hash()

// e6Case wraps tr with e6Scope — the TransitionCase every "happy path" test
// below passes to Produce/Analyze.
func e6Case(tr StateTransition) TransitionCase {
	return TransitionCase{Transition: tr, Scope: e6Scope}
}

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
	registry := mustActionRegistry(t, actionauth.Registration{
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

// mustActionRegistry builds an actionauth.Registry and fails the test
// immediately if NewRegistry rejects it (e.g. a duplicate Action.Key) — the
// same "happy path assumes successful construction" discipline as
// e6MustRegistry above, for the actionauth-level registry every S10 test in
// this package builds.
func mustActionRegistry(t *testing.T, regs ...actionauth.Registration) *actionauth.Registry {
	t.Helper()
	reg, err := actionauth.NewRegistry(regs...)
	if err != nil {
		t.Fatalf("actionauth.NewRegistry: %v", err)
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
	if got := p.Produce(e6Case(tr)); got != nil {
		t.Fatalf("Produce with no registered rule = %v, want nil", got)
	}
	assessment, _ := p.Analyze(e6Case(tr))
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
		Scope:      e6Scope,
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
	if got := p.Produce(e6Case(trA)); got != nil {
		t.Fatalf("Produce (action-a, satisfied) = %v, want nil", got)
	}

	// action-b's transition, even with a status that WOULD have violated
	// action-a's rule, must produce nothing: no rule is registered for
	// action-b, so action-a's rule must never be reused for it.
	trB := e6TransitionWithAction(before, afterB, actionB)
	if got := p.Produce(e6Case(trB)); got != nil {
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
	if got := p.Produce(e6Case(tr)); got != nil {
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
	got := p.Produce(e6Case(tr)) // after.status=403 != the ORIGINAL rule's AfterValue=200
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
	got := p.Produce(e6Case(tr))
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
	if got := p.Produce(e6Case(tr)); got != nil {
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
	assessment, anomalies := p.Analyze(e6Case(tr))
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("Analyze (missing fact) assessment = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
	if anomalies != nil {
		t.Fatalf("Analyze (missing fact) anomalies = %v, want nil", anomalies)
	}
	if got := p.Produce(e6Case(tr)); got != nil {
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
	if got := p.Produce(e6Case(tr)); got != nil {
		t.Fatalf("Produce (fact_equals satisfied) = %v, want nil", got)
	}
}

func TestE6FactEqualsObservedDiffersFromExpectedProducesOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	got := p.Produce(e6Case(tr))
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
	assessment, _ := p.Analyze(e6Case(tr))
	if assessment != TransitionSatisfied {
		t.Fatalf("Analyze (fact_transition A->B as declared) = %q, want %q", assessment, TransitionSatisfied)
	}
	if got := p.Produce(e6Case(tr)); got != nil {
		t.Fatalf("Produce (fact_transition satisfied, A->B as declared) = %v, want nil", got)
	}
}

func TestE6FactTransitionActuallyGoesToCProducesOneHypothesis(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 500, "error") // declared AfterValue is 403, observed is 500
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "403"}, e6AuthoritativeSource())
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	assessment, _ := p.Analyze(e6Case(tr))
	if assessment != TransitionViolated {
		t.Fatalf("Analyze (fact_transition A->C not A->B) = %q, want %q", assessment, TransitionViolated)
	}
	got := p.Produce(e6Case(tr))
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
	assessment, anomalies := p.Analyze(e6Case(tr))
	if assessment != TransitionNotApplicable {
		t.Fatalf("Analyze (precondition before=200 != declared BeforeValue=999) = %q, want %q", assessment, TransitionNotApplicable)
	}
	if anomalies != nil {
		t.Fatalf("Analyze (not_applicable) anomalies = %v, want nil", anomalies)
	}
	if got := p.Produce(e6Case(tr)); got != nil {
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
	assessment, _ := p.Analyze(e6Case(tr))
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
	rc := resolvedTransitionCase{Transition: tr, Scope: e6Scope, Rule: rule}
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
	if got := p.Produce(e6Case(tr)); got != nil {
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
	got := p.Produce(e6Case(tr))
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
	got := p.Produce(e6Case(tr))
	if len(got) != 1 {
		t.Fatalf("setup: expected exactly 1 candidate, got %d", len(got))
	}
	wantCaseHash := transitionCaseArtifactHash(resolvedTransitionCase{Transition: tr, Scope: e6Scope, Rule: rule})
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
	if got[0].Refs["projector_id"] != string(rule.ProjectorID) {
		t.Fatalf("Refs[projector_id] = %q, want %q", got[0].Refs["projector_id"], rule.ProjectorID)
	}
	wantReplayTargetHash := replayTargetOf(e6Scope).Hash()
	if got[0].Refs["replay_target_hash"] != wantReplayTargetHash {
		t.Fatalf("Refs[replay_target_hash] = %q, want %q", got[0].Refs["replay_target_hash"], wantReplayTargetHash)
	}
}

// --- S10/E7 groundwork: Scope must actually hash to the transition's own
// ScopeHash, and LookupByRuleID resolves what NewTransitionRuleRegistry built.

// TestE6FabricatedScopeRejected proves a caller cannot pair a REAL
// transition with a FABRICATED Scope and have it accepted: without this
// check, a Candidate's Refs["replay_target_hash"] could claim a target the
// transition never actually ran against, since StateTransition itself
// carries no recoverable target identity, only an opaque ScopeHash.
func TestE6FabricatedScopeRejected(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	fabricated := ExplorationScope{TargetID: "not-the-real-target", BuildID: "b", SessionID: "s", Protocol: "http", HarnessID: "h"}
	if fabricated.Hash() == tr.ScopeHash {
		t.Fatal("test setup bug: the fabricated scope must not actually hash to tr.ScopeHash")
	}
	c := TransitionCase{Transition: tr, Scope: fabricated}
	p := NewStateMachineProducer(e6MustRegistry(t, rule))
	if got := p.Produce(c); got != nil {
		t.Fatalf("Produce with a fabricated Scope = %v, want nil", got)
	}
	assessment, _ := p.Analyze(c)
	if assessment != TransitionInsufficientEvidence {
		t.Fatalf("Analyze with a fabricated Scope = %q, want %q", assessment, TransitionInsufficientEvidence)
	}
}

// TestE6LookupByRuleIDResolvesRegisteredRule is S10/E7's entry point:
// resolving a rule by the RuleID a Candidate's own Refs["rule_id"] would
// carry, rather than by (ActionID, ProjectorID).
func TestE6LookupByRuleIDResolvesRegisteredRule(t *testing.T) {
	before := e6Fingerprint(t, 200, "ok")
	after := e6Fingerprint(t, 403, "denied")
	tr := e6Transition(t, before, after)
	rule := e6RuleFor(tr, TransitionExpectation{Kind: ExpectStateUnchanged}, e6AuthoritativeSource())
	registry := e6MustRegistry(t, rule)

	got, ok := registry.LookupByRuleID(rule.RuleID)
	if !ok {
		t.Fatalf("LookupByRuleID(%q) = not found, want the registered rule", rule.RuleID)
	}
	if got.RuleID != rule.RuleID || got.ActionID != rule.ActionID || got.ProjectorID != rule.ProjectorID {
		t.Fatalf("LookupByRuleID(%q) = %+v, want %+v", rule.RuleID, got, rule)
	}
	if _, ok := registry.LookupByRuleID("no-such-rule-id"); ok {
		t.Fatal("LookupByRuleID for an unregistered id must return ok=false")
	}
	var nilRegistry *TransitionRuleRegistry
	if _, ok := nilRegistry.LookupByRuleID(rule.RuleID); ok {
		t.Fatal("LookupByRuleID on a nil registry must fail closed (ok=false), never panic or match")
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
	return resolvedTransitionCase{Transition: tr, Scope: e6Scope, Rule: rule}
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

func TestE6CaseArtifactHashChangesWhenScopeChanges(t *testing.T) {
	base := e6BaseResolvedCase(t)
	changed := base
	changed.Scope = ExplorationScope{TargetID: "different-target", BuildID: "b", SessionID: "s", Protocol: "http", HarnessID: "h"}
	if transitionCaseArtifactHash(base) == transitionCaseArtifactHash(changed) {
		t.Fatal("transitionCaseArtifactHash must change when ONLY the resolved case's Scope changes")
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

// --- StateTransition.OriginID: frozen at the transition's OWN creation,
// from the producing Explorer's OWN trusted origin — S10/E8's final freeze
// blocker. Two earlier designs both proved insufficient:
//  1. A TransitionCase-level constructor that cross-checked a separately-
//     supplied *HTTPProfile against the transition's ScopeHash — but two
//     different HTTPProfiles (different real origins) can share the exact
//     same abstract ExplorationScope, so that check could never rule out
//     "this transition, relabeled under a different origin's profile".
//  2. Freezing origin in Explorer.Step by type-asserting e.collector
//     against an exported, single-method interface (originIdentifiable) —
//     but ANY external Collector implementation could satisfy that
//     interface and simply claim whatever origin it liked, AND the
//     generic NewExplorer still accepted collector/executor as two
//     INDEPENDENTLY supplied values, so a Collector=server-A /
//     Executor=server-B mismatch would still only ever reflect the
//     Collector's (possibly unrelated) claim.
//
// The actual fix: Explorer itself carries a private, untyped originID,
// set to a real value ONLY by NewHTTPExplorer — which takes a single
// *HTTPProfile (never separate collector/executor), so Collector≠Executor
// origin is structurally impossible for any Explorer built this way — and
// NEVER by the generic NewExplorer, regardless of what Collector/Executor
// it is handed. Step (explorer.go) stamps e.originID directly, with no
// interface, no type assertion, and no way for an external Collector to
// influence it at all.

// TestNewHTTPExplorerFreezesOriginIDFromTheProfile drives one real
// Explorer session (baseline -> step), built via NewHTTPExplorer, against
// a real HTTP fixture and proves the StateTransition Step returns carries
// exactly the profile's own OriginID — never empty, never anything else.
func TestNewHTTPExplorerFreezesOriginIDFromTheProfile(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	scope := ExplorationScope{TargetID: "e6-origin-target", SessionID: "s1"}
	profile, err := NewHTTPProfile(scope, ts.URL, "/state", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		mustActionRegistry(t, actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/")}, Requirements: httpReq}),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{MaxStates: 5, MaxTransitions: 5, MaxDepth: 5, MaxRequests: 10, MaxVisitsPerState: 5, MaxBranching: 1, MaxWallTime: 10 * time.Second}
	exp, err := NewHTTPExplorer(profile, stateauth.HTTPFixtureRegistry(), policy, budget, actionauth.RecoveryPlanRef{RegistryKey: "reset"}, 5*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := exp.Baseline(ctx); err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	tr, err := exp.Step(ctx)
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if tr.OriginID() == "" {
		t.Fatal("StateTransition.OriginID() must be non-empty for a real HTTP-backed Step through NewHTTPExplorer")
	}
	if tr.OriginID() != profile.OriginID() {
		t.Fatalf("StateTransition.OriginID() = %q, want the profile's own OriginID() %q", tr.OriginID(), profile.OriginID())
	}
}

// TestGenericNewExplorerNeverGrantsOriginIDEvenWithRealHTTPCollectorAndExecutor
// proves the generic constructor's own fail-closed default: even when a
// caller wires up a REAL, matching *HTTPCollector/*HTTPExecutor pair
// (built from the same baseURL, not mismatched), NewExplorer itself still
// never grants the physical-origin guarantee — only NewHTTPExplorer does.
func TestGenericNewExplorerNeverGrantsOriginIDEvenWithRealHTTPCollectorAndExecutor(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	scope := ExplorationScope{TargetID: "e6-generic-origin-target", SessionID: "s1"}
	collector, err := NewHTTPCollector(ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(ts.URL, map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		mustActionRegistry(t, actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/")}, Requirements: httpReq}),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{MaxStates: 5, MaxTransitions: 5, MaxDepth: 5, MaxRequests: 10, MaxVisitsPerState: 5, MaxBranching: 1, MaxWallTime: 10 * time.Second}
	exp, err := NewExplorer(scope, collector, stateauth.HTTPFixtureRegistry(), policy, executor, budget, actionauth.RecoveryPlanRef{RegistryKey: "reset"}, 5*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := exp.Baseline(ctx); err != nil {
		t.Fatal(err)
	}
	tr, err := exp.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tr.OriginID() != "" {
		t.Fatalf("StateTransition.OriginID() = %q, want \"\" — the generic NewExplorer must never grant the physical-origin guarantee, even with a real, correctly-matched HTTPCollector/HTTPExecutor pair", tr.OriginID())
	}
}

// TestGenericNewExplorerAcceptsMismatchedCollectorAndExecutorOriginsButRecordsNoOriginID
// is the user's exact adversarial scenario: a Collector built against
// server-A wired alongside an Executor built against a GENUINELY DIFFERENT
// server-B, both passed to the generic NewExplorer. This is structurally
// acceptable to NewExplorer (it has no way to know, and does not claim
// to) — but the resulting transition's OriginID must be "", never A's,
// never B's, so a strict-origin-binding replay validator later fails
// closed (ErrReplayMissingOriginBinding) rather than silently trusting a
// mismatched pair.
func TestGenericNewExplorerAcceptsMismatchedCollectorAndExecutorOriginsButRecordsNoOriginID(t *testing.T) {
	serverA := newHTTPFixtureServer(t)
	serverB := newHTTPFixtureServer(t) // a genuinely different real origin

	scope := ExplorationScope{TargetID: "e6-mismatched-origin-target", SessionID: "s1"}
	collectorA, err := NewHTTPCollector(serverA.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executorB, err := NewHTTPExecutor(serverB.URL, map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	// HTTPExecutor exposes no OriginID of its own — a throwaway Collector
	// for the same baseURL is just this test's way of confirming serverB
	// really is a different real origin from serverA, nothing more.
	collectorB, err := NewHTTPCollector(serverB.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	if collectorA.OriginID() == collectorB.OriginID() {
		t.Fatal("setup: collectorA and executorB (via serverB) must have genuinely different real origins")
	}

	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		mustActionRegistry(t, actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/")}, Requirements: httpReq}),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{MaxStates: 5, MaxTransitions: 5, MaxDepth: 5, MaxRequests: 10, MaxVisitsPerState: 5, MaxBranching: 1, MaxWallTime: 10 * time.Second}
	// NewExplorer accepts this mismatched pair — it is not this
	// constructor's job to detect it.
	exp, err := NewExplorer(scope, collectorA, stateauth.HTTPFixtureRegistry(), policy, executorB, budget, actionauth.RecoveryPlanRef{RegistryKey: "reset"}, 5*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := exp.Baseline(ctx); err != nil {
		t.Fatal(err)
	}
	tr, err := exp.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tr.OriginID() != "" {
		t.Fatalf("StateTransition.OriginID() = %q, want \"\" for a mismatched Collector/Executor pair built via the generic NewExplorer — it must never reflect either A's or B's origin", tr.OriginID())
	}
}

// TestOriginIDCannotBeReinterpretedByADifferentProfileSharingTheSameScope
// is the direct adversarial proof: two real HTTPProfiles built against
// TWO GENUINELY DIFFERENT servers (A and B) but the EXACT SAME abstract
// ExplorationScope. A real transition is produced ONLY through A, via
// NewHTTPExplorer(profileA, ...). Nothing in this package accepts
// profileB alongside that already-built transition to "reinterpret" its
// origin — Produce's recorded originalOriginID is proven to be A's,
// unconditionally, regardless of profileB's mere existence.
func TestOriginIDCannotBeReinterpretedByADifferentProfileSharingTheSameScope(t *testing.T) {
	serverA := newHTTPFixtureServer(t)
	serverB := newHTTPFixtureServer(t) // a genuinely different real origin

	sharedScope := ExplorationScope{TargetID: "shared-target", BuildID: "shared-build", SessionID: "shared-session", Protocol: "http", HarnessID: "shared-harness"}
	profileA, err := NewHTTPProfile(sharedScope, serverA.URL, "/state", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	profileB, err := NewHTTPProfile(sharedScope, serverB.URL, "/state", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	if profileA.OriginID() == profileB.OriginID() {
		t.Fatal("setup: profileA and profileB must have genuinely different real origins")
	}

	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		mustActionRegistry(t, actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/")}, Requirements: httpReq}),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{MaxStates: 5, MaxTransitions: 5, MaxDepth: 5, MaxRequests: 10, MaxVisitsPerState: 5, MaxBranching: 1, MaxWallTime: 10 * time.Second}
	// The real transition is produced ONLY through profileA — profileB is
	// never wired into this Explorer at all.
	exp, err := NewHTTPExplorer(profileA, stateauth.HTTPFixtureRegistry(), policy, budget, actionauth.RecoveryPlanRef{RegistryKey: "reset"}, 5*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := exp.Baseline(ctx); err != nil {
		t.Fatal(err)
	}
	tr, err := exp.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}

	rule := TransitionRule{
		RuleID:      "origin-reinterpretation-test-rule",
		ActionID:    tr.Action.ID(),
		ProjectorID: tr.BeforeFingerprint.ProjectorID(),
		// A value the fixture's real status ("200") can never equal —
		// guarantees TransitionViolated deterministically, regardless of
		// whether the read-only GET happened to change anything.
		Expectation:       TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "999"},
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "origin-test-config"},
	}
	registry, err := NewTransitionRuleRegistry(rule)
	if err != nil {
		t.Fatal(err)
	}
	// profileB is deliberately never passed to Produce, or to anything —
	// there is no function signature anywhere that would accept it
	// alongside tr to "reinterpret" its origin. This line exists only to
	// prove profileB was really built against a different real server
	// (the earlier OriginID inequality check), not to influence anything
	// below.
	_ = profileB

	candidates := NewStateMachineProducer(registry).Produce(TransitionCase{Transition: tr, Scope: profileA.Scope()})
	if len(candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate (the rule's AfterValue can never match the fixture's real status), got %d", len(candidates))
	}
	binding, ok := candidates[0].StateMachineBinding()
	if !ok {
		t.Fatal("candidate must carry a StateMachineBinding")
	}
	if binding.OriginalOriginID() != profileA.OriginID() {
		t.Fatalf("StateMachineBinding.OriginalOriginID() = %q, want profileA's own OriginID() %q — it must NEVER be influenced by profileB merely sharing the same abstract Scope",
			binding.OriginalOriginID(), profileA.OriginID())
	}
	if binding.OriginalOriginID() == profileB.OriginID() {
		t.Fatal("StateMachineBinding.OriginalOriginID() must never equal profileB's origin")
	}
}
