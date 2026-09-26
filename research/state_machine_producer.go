package research

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// StateMachineProducer (S10/E6) turns a TransitionCase — one real, already
// recorded StateTransition — into a hypothesis Candidate when it VIOLATES a
// pre-registered, authoritative TransitionRule. It is a deterministic
// PRODUCER, exactly like the diff/fuzz/differential producers: it consumes an
// already-collected StateTransition (Explorer's own output), judges it
// against a rule it never authored, and emits at most one hypothesis per
// violated fact — it never re-executes an action, re-collects state, calls an
// LLM, decides a validator, or promotes anything.
//
// The one rule this file exists to enforce: "State A != State B" is NEVER
// itself an anomaly. Only a transition that violates an ALREADY-AUTHORIZED
// contract — one that existed before exploration ran, authored by
// ExpectationSource (S9's frozen whitelist, reused unchanged) — produces a
// candidate. E6 invents no second "who may define correct behavior" system,
// and it never lets exploration retroactively invent the expectation it is
// then judged against (that would be hindsight bias, not detection): a
// TransitionRule must be registered BEFORE running the Explorer session that
// produces the StateTransition it will be checked against.
//
// v1 is deliberately narrow (mirroring S9's own v1 scope note): four
// declarative expectation kinds, no callback, no free-form rule language. E6
// stops at Candidate — no replay validator, no LLM judgment, and no new
// execution capability live here; those are explicitly out of scope for this
// pass.
type StateMachineProducer struct {
	rules *TransitionRuleRegistry
	newID func() string
}

// NewStateMachineProducer builds a producer bound to exactly one
// TransitionRuleRegistry — see that type's own doc for why the registry,
// not the caller of Produce/Analyze, decides which Expectation applies to a
// given transition.
func NewStateMachineProducer(rules *TransitionRuleRegistry) *StateMachineProducer {
	return &StateMachineProducer{rules: rules, newID: SequentialIDs(time.Now().UTC().Year())}
}

func (p *StateMachineProducer) WithIDFunc(fn func() string) *StateMachineProducer {
	p.newID = fn
	return p
}

// TransitionExpectationKind is the closed, declarative set of contracts v1
// can judge a StateTransition against. There is deliberately no callback
// shape (no `func(before, after Fingerprint) bool`) — the same
// declarative-data-not-closure discipline actionauth.Registration.Requirements
// already established: a closure can silently capture anything (a candidate,
// an AI-authored predicate, a live network reference); a fixed, auditable data
// shape cannot.
type TransitionExpectationKind string

const (
	// ExpectStateUnchanged: the whole state fingerprint must be identical
	// before and after — the action was expected to be a no-op on state.
	ExpectStateUnchanged TransitionExpectationKind = "state_unchanged"
	// ExpectFactUnchanged: one named fact must hold the same value before and
	// after — narrower than ExpectStateUnchanged, for when only one fact
	// matters and the rest of the state is expected to move freely.
	ExpectFactUnchanged TransitionExpectationKind = "fact_unchanged"
	// ExpectFactEquals: one named fact must equal a declared value AFTER the
	// transition, regardless of what it was before.
	ExpectFactEquals TransitionExpectationKind = "fact_equals"
	// ExpectFactTransition: one named fact must move from a declared
	// BeforeValue to a declared AfterValue — the only kind that judges both
	// sides of the transition against declared values, and the only kind with
	// a PRECONDITION (see analyzeFactTransition: a before value that does not
	// match BeforeValue means the rule never applied to this transition at
	// all — TransitionNotApplicable, never a violation).
	ExpectFactTransition TransitionExpectationKind = "fact_transition"
)

// TransitionExpectation is PLAIN DATA — never a closure. Fact is required for
// every kind except ExpectStateUnchanged (which judges the whole fingerprint,
// not one named fact). BeforeValue is used only by ExpectFactTransition;
// AfterValue is used by ExpectFactEquals and ExpectFactTransition.
type TransitionExpectation struct {
	Kind TransitionExpectationKind

	Fact string

	BeforeValue string
	AfterValue  string
}

// TransitionRule pairs the ONE (ActionID, ProjectorID) combination it applies
// to with the Expectation to judge and the ExpectationSource that authored
// it. This is the fix for a gap the v1-without-a-registry design had: judging
// a TransitionCase only against an ExpectationSource's AUTHORITY (is this
// kind of source allowed to define correct behavior at all) is not the same
// as judging it against the RIGHT expectation for the actual action that
// ran — a caller could otherwise take a legitimately spec-authored
// Expectation written for action A and (by mistake or by construction) pair
// it, at the call site, with a transition whose Action was actually B. A
// TransitionRule fixes WHICH action and WHICH state-authority (projector) it
// applies to at REGISTRATION time, not at judgment time.
type TransitionRule struct {
	// RuleID is an opaque, human-assigned identity for this rule — recorded on
	// any Candidate it produces (Refs["rule_id"]) so a rule can be found and
	// audited independently of the ActionID/ProjectorID it happens to key on.
	RuleID string

	ActionID    actionauth.ActionID
	ProjectorID stateauth.ProjectorID

	Expectation       TransitionExpectation
	ExpectationSource ExpectationSource

	// ReadOnlyAction is the rule AUTHOR's own explicit attestation that
	// ActionID's action needs no compensating recovery — either because it
	// has no observable side effect at all, or because any side effect it
	// does have has been reviewed and is acceptable to leave in place. S10/
	// E7's replay validator v1 REFUSES to replay any rule for which this is
	// not exactly true (ErrReplayActionNotReadOnly): v1 implements no
	// verified-recovery flow (Execute -> collect -> BoundRecovery ->
	// ExecuteRecovery -> collect -> stateauth.Recovered()), so replaying a
	// rule that needed one would risk leaving a real target parked in a
	// changed state purely to reproduce a hypothesis. A future version that
	// wants to replay actions needing real recovery must implement and
	// prove that flow FIRST, as its own explicit, separately reviewed
	// design — never by silently trusting this flag beyond what it
	// declares. NewTransitionRuleRegistry does NOT require this to be true
	// — E6's own producer judges transitions regardless of whether the
	// action was read-only; only E7's Replay method checks it.
	ReadOnlyAction bool
}

// StateMachineBinding is the immutable, tamper-proof identity a
// state-machine Candidate carries for S10/E7's replay validator to resolve
// against — see Candidate.stateMachineBinding's own doc for why this exists
// instead of trusting Candidate.Refs (an ordinary, mutable map). Every
// field here is a plain value (a string or an actionauth.ActionID) with no
// exported constructor and no exported mutator; the only way to obtain one
// is Candidate.StateMachineBinding(), which returns a copy.
type StateMachineBinding struct {
	ruleID           string
	actionID         actionauth.ActionID
	projectorID      stateauth.ProjectorID
	replayTargetHash string
	caseArtifactHash string
}

func (b StateMachineBinding) RuleID() string                     { return b.ruleID }
func (b StateMachineBinding) ActionID() actionauth.ActionID      { return b.actionID }
func (b StateMachineBinding) ProjectorID() stateauth.ProjectorID { return b.projectorID }
func (b StateMachineBinding) ReplayTargetHash() string           { return b.replayTargetHash }
func (b StateMachineBinding) CaseArtifactHash() string           { return b.caseArtifactHash }

// ReplayTarget identifies WHAT is being explored/replayed against: the same
// target/build/protocol/harness dimensions as ExplorationScope, but
// DELIBERATELY WITHOUT SessionID. S10/E7's replay validator uses this to
// prove a hypothesis holds under a genuinely INDEPENDENT session — not
// merely "the same recorded session run twice" — while still requiring the
// SAME real-world target/build/protocol/harness, never a substituted one.
type ReplayTarget struct {
	TargetID  string
	BuildID   string
	Protocol  string
	HarnessID string
}

// Hash is a pure, deterministic, SESSION-INDEPENDENT identity for the
// target. This is the value Produce records as Refs["replay_target_hash"]
// (see transitionCaseArtifactHash and Produce below), and the value a
// replay validator recomputes for its OWN configured target to confirm it
// is replaying against the SAME target/build/protocol/harness the original
// candidate came from.
func (rt ReplayTarget) Hash() string {
	return RawInputHash([]byte(rt.TargetID + "|" + rt.BuildID + "|" + rt.Protocol + "|" + rt.HarnessID))
}

// Scope builds the full ExplorationScope for a fresh session against rt:
// rt's own identity fields, plus sessionID as the (deliberately fresh,
// INDEPENDENT of the original) SessionID.
func (rt ReplayTarget) Scope(sessionID string) ExplorationScope {
	return ExplorationScope{TargetID: rt.TargetID, BuildID: rt.BuildID, SessionID: sessionID, Protocol: rt.Protocol, HarnessID: rt.HarnessID}
}

// replayTargetOf derives the SessionID-independent ReplayTarget identity
// from a full ExplorationScope.
func replayTargetOf(s ExplorationScope) ReplayTarget {
	return ReplayTarget{TargetID: s.TargetID, BuildID: s.BuildID, Protocol: s.Protocol, HarnessID: s.HarnessID}
}

// transitionRuleKey is the exact (ActionID, ProjectorID) tuple a
// TransitionRuleRegistry keys on. ActionID is two fields (RegistryKey,
// VariantID), so both are part of the key — a rule for one VariantID of a
// registered action never silently matches another.
type transitionRuleKey struct {
	registryKey string
	variantID   string
	projectorID stateauth.ProjectorID
}

// TransitionRuleRegistry is a compile-time-only, closed set of
// TransitionRules — the S10/E6 analogue of actionauth.Registry and S5's
// Validator registry: built once, from a fixed list, with no method to add
// an entry afterward. lookup is keyed by the (ActionID, ProjectorID) a REAL
// StateTransition actually carries — never by a RuleID or an Expectation a
// caller of Produce/Analyze supplies directly. This is what makes "which
// rule applies" a function of the transition's own recorded facts, not a
// choice made at the call site.
//
// A *TransitionRuleRegistry successfully built by NewTransitionRuleRegistry
// is itself the proof that "(ActionID, ProjectorID) -> exactly one rule"
// holds for every entry it contains — lookup never has to break a tie
// between two candidates by slice order, map iteration order, or any other
// incidental detail, because NewTransitionRuleRegistry refuses to build a
// registry where a tie could ever arise.
type TransitionRuleRegistry struct {
	rules    map[transitionRuleKey]TransitionRule
	byRuleID map[string]TransitionRule
}

// NewTransitionRuleRegistry builds a closed registry from a fixed list of
// rules, or reports an error and returns nil if the list is not
// unambiguous. Every rule is copied BY VALUE into the registry's own map
// (TransitionRule holds no pointers/slices, so this is a real, independent
// copy) — mutating the caller's original rules slice afterward has no
// effect on anything a built registry ever resolves; see
// TestE6RuleRegistryUnaffectedByMutatingCallersSliceAfterConstruction.
//
// Rejected, so a successfully built registry is itself the guarantee, not
// merely a convention callers are expected to follow:
//   - an empty RuleID (nothing to point an audit at),
//   - a RuleID reused by more than one rule,
//   - a non-authoritative ExpectationSource (S9's whitelist, reused
//     unchanged — see ExpectationSource.authoritative),
//   - a TransitionExpectation with an unknown Kind, or with an empty Fact
//     for a Kind that requires one, and
//   - MOST IMPORTANTLY: two rules registered for the SAME (ActionID,
//     ProjectorID) pair. Without this, which rule "wins" for that pair would
//     depend on slice order / map iteration order / an implementation
//     detail — never a deterministic authority. Rejecting the ambiguity at
//     construction time is what makes lookup's "exactly one match" real
//     rather than "whichever happened to be inserted last".
func NewTransitionRuleRegistry(rules ...TransitionRule) (*TransitionRuleRegistry, error) {
	m := make(map[transitionRuleKey]TransitionRule, len(rules))
	byRuleID := make(map[string]TransitionRule, len(rules))
	for _, r := range rules {
		if r.RuleID == "" {
			return nil, fmt.Errorf("research: TransitionRule has an empty RuleID (action=%+v, projector=%q)", r.ActionID, r.ProjectorID)
		}
		if _, dup := byRuleID[r.RuleID]; dup {
			return nil, fmt.Errorf("research: duplicate TransitionRule.RuleID %q", r.RuleID)
		}
		if !r.ExpectationSource.authoritative() {
			return nil, fmt.Errorf("research: TransitionRule %q has a non-authoritative ExpectationSource.Kind %q", r.RuleID, r.ExpectationSource.Kind)
		}
		if !r.Expectation.valid() {
			return nil, fmt.Errorf("research: TransitionRule %q has an invalid TransitionExpectation (kind=%q, fact=%q)", r.RuleID, r.Expectation.Kind, r.Expectation.Fact)
		}
		key := transitionRuleKey{r.ActionID.RegistryKey, r.ActionID.VariantID, r.ProjectorID}
		if existing, dup := m[key]; dup {
			return nil, fmt.Errorf("research: duplicate TransitionRule for (ActionID=%+v, ProjectorID=%q): %q and %q both claim it",
				r.ActionID, r.ProjectorID, existing.RuleID, r.RuleID)
		}
		m[key] = r
		byRuleID[r.RuleID] = r
	}
	return &TransitionRuleRegistry{rules: m, byRuleID: byRuleID}, nil
}

// valid reports whether e is a well-formed TransitionExpectation: a known
// Kind, and (for every Kind except ExpectStateUnchanged, which judges the
// whole fingerprint rather than one named fact) a non-empty Fact.
func (e TransitionExpectation) valid() bool {
	switch e.Kind {
	case ExpectStateUnchanged:
		return true
	case ExpectFactUnchanged, ExpectFactEquals, ExpectFactTransition:
		return e.Fact != ""
	default:
		return false
	}
}

// lookup returns the ONE rule registered for exactly this (actionID,
// projectorID) pair. A nil registry (or no match) fails closed: no rule, no
// judgment, zero candidates — never "judge against whatever expectation
// happens to be lying around".
func (r *TransitionRuleRegistry) lookup(actionID actionauth.ActionID, projectorID stateauth.ProjectorID) (TransitionRule, bool) {
	if r == nil {
		return TransitionRule{}, false
	}
	rule, ok := r.rules[transitionRuleKey{actionID.RegistryKey, actionID.VariantID, projectorID}]
	return rule, ok
}

// LookupByRuleID returns the ONE rule registered under ruleID, if any. This
// is S10/E7's entry point into an ALREADY-TRUSTED registry: given a
// Candidate's own Refs["rule_id"], resolve the rule it claims to come from
// — never trusting any OTHER field the Candidate carries (its recorded
// action/projector identity) as authoritative in itself; a caller must
// cross-check those against the resolved rule's own ActionID/ProjectorID,
// never use the Candidate's copies directly.
func (r *TransitionRuleRegistry) LookupByRuleID(ruleID string) (TransitionRule, bool) {
	if r == nil {
		return TransitionRule{}, false
	}
	rule, ok := r.byRuleID[ruleID]
	return rule, ok
}

// TransitionCase is the E6 producer's per-observation input: one observed
// StateTransition (Explorer's own recorded output), plus the exact
// ExplorationScope it was collected under. It carries NO Expectation or
// ExpectationSource of its own — what a transition is judged against is
// resolved internally, by the producer's own TransitionRuleRegistry, from the
// transition's actual Action and BeforeFingerprint.ProjectorID(). See
// TransitionRule's own doc for the mismatch this closes.
//
// Scope is required (not merely a convenience) because StateTransition
// itself carries only ScopeHash — an opaque, one-way hash with no
// TargetID/BuildID/Protocol/HarnessID a later S10/E7 replay validator could
// recover from it alone. validate() (below) verifies Scope actually IS the
// scope that produced this ScopeHash — a caller cannot claim an arbitrary
// Scope for a real transition and have it accepted.
type TransitionCase struct {
	Transition StateTransition
	Scope      ExplorationScope
}

// resolvedTransitionCase pairs a TransitionCase with the ONE TransitionRule
// the registry resolved for it. It is unexported: nothing outside this file
// constructs the (transition, rule) pairing that validate/Analyze/the hash
// function actually judge — Produce/Analyze's only public parameter remains
// the bare TransitionCase.
type resolvedTransitionCase struct {
	Transition StateTransition
	Scope      ExplorationScope
	Rule       TransitionRule
}

// resolve looks up the ONE rule registered for c's actual (ActionID,
// ProjectorID) pair. ok is false if nothing is registered for it — including
// the common case of a transition whose action has no declared Expectation
// at all, which must never be silently treated as "nothing to judge, so
// anything goes"; it means exactly that: zero candidates.
func (p *StateMachineProducer) resolve(c TransitionCase) (resolvedTransitionCase, bool) {
	before := c.Transition.BeforeFingerprint
	rule, ok := p.rules.lookup(c.Transition.Action.ID(), before.ProjectorID())
	if !ok {
		return resolvedTransitionCase{}, false
	}
	return resolvedTransitionCase{Transition: c.Transition, Scope: c.Scope, Rule: rule}, true
}

// validate reports whether rc is well-formed and authorized enough to judge
// AT ALL. An invalid case is never judged — it yields
// TransitionInsufficientEvidence and zero candidates, exactly like S9's
// DifferentialCase.validate: this is the structural guard against an
// unauthorized ExpectationSource, a self-contradictory (scope-inconsistent)
// transition, a transition whose Action was never actually authorized for
// the state it claims to have started from (a zero-value or replayed
// actionauth.BoundAction always fails ValidFor and so always fails here,
// EVEN IF some rule happens to be registered under a matching ActionID), or
// a transition whose two fingerprints were not produced by the SAME
// projector the rule was registered against, or a claimed Scope that does
// not actually hash to the transition's own ScopeHash (closing the gap S10/
// E7 would otherwise open: StateTransition itself carries no recoverable
// TargetID/BuildID/Protocol/HarnessID, only an opaque ScopeHash — without
// this check, a caller could pair a REAL transition with a FABRICATED Scope
// and have Produce record a replay_target_hash for a target the transition
// never actually ran against). Every one of these is ALSO already enforced
// at registration time by NewTransitionRuleRegistry for any rule that
// actually came from one — this re-checks them anyway, independently,
// rather than trusting that every resolvedTransitionCase in existence was
// necessarily built from a validated registry.
func (rc resolvedTransitionCase) validate() bool {
	if !rc.Rule.ExpectationSource.authoritative() {
		return false
	}
	t := rc.Transition
	if !t.ScopeConsistent() {
		return false
	}
	if rc.Scope.Hash() != t.ScopeHash {
		return false
	}
	if !t.Action.ValidFor(t.ScopeHash, t.BeforeFingerprint.StateFingerprintHash()) {
		return false
	}
	if t.Action.ID() != rc.Rule.ActionID {
		return false // defensive: resolve's own lookup key should already guarantee this
	}
	if t.BeforeFingerprint.ProjectorID() != rc.Rule.ProjectorID || t.AfterFingerprint.ProjectorID() != rc.Rule.ProjectorID {
		return false // both sides of the transition must share the rule's own projector
	}
	return rc.Rule.Expectation.valid()
}

// TransitionAssessment is a FOUR-STATE result, never a bool — the same
// discipline that keeps "no evidence" (and, for fact_transition, "this rule's
// own precondition never held") from ever collapsing into "violated".
type TransitionAssessment string

const (
	// TransitionSatisfied: the declared expectation held. Zero candidates.
	TransitionSatisfied TransitionAssessment = "satisfied"
	// TransitionViolated: the declared expectation demonstrably did not hold.
	// The only assessment that ever produces a candidate.
	TransitionViolated TransitionAssessment = "violated"
	// TransitionInsufficientEvidence: the case is invalid/unauthorized, no
	// rule is registered for it at all, or a fact the rule needs was simply
	// ABSENT (not present-with-empty-string — see the ok-check discipline in
	// the analyze* helpers below). Zero candidates: absence of evidence is
	// never itself a violation.
	TransitionInsufficientEvidence TransitionAssessment = "insufficient_evidence"
	// TransitionNotApplicable: ExpectFactTransition ONLY — the rule's own
	// declared precondition (before.Facts[key] == BeforeValue) did not hold,
	// so the rule never applied to this transition in the first place. This
	// is NOT a violation: "if before==A then after must==B" imposes no
	// constraint on a transition that didn't start at A. Zero candidates.
	TransitionNotApplicable TransitionAssessment = "not_applicable"
)

// TransitionAnomaly is FACTS ONLY — no Severity/Confidence/Exploitability/
// Vulnerable/Confirmed/State field, and deliberately not called "Finding": it
// is what the deterministic Analyzer found, nothing about what it means. The
// StateMachineProducer is the only thing that wraps it into a hypothesis
// Candidate.
type TransitionAnomaly struct {
	Type string

	RuleKind TransitionExpectationKind

	Fact string

	ExpectedBefore string
	ExpectedAfter  string

	ObservedBefore string
	ObservedAfter  string

	EvidenceRefs []string
}

// AnomalyStateTransitionExpectationViolation is the sole TransitionAnomaly.Type
// / Candidate.Type value E6 v1 ever produces.
const AnomalyStateTransitionExpectationViolation = "state_transition_expectation_violation"

// Analyze judges c deterministically and with no I/O, returning a four-state
// assessment plus (only when TransitionViolated) the anomaly it found. This is
// the E6 analogue of DifferentialProducer.Analyze: it never guesses "what
// should have happened" from the observed transition itself (that would be
// hindsight bias) — it only ever compares the observed transition against a
// TransitionRule that was registered before this method ever ran, resolved
// strictly by the transition's own (ActionID, ProjectorID) — never by
// anything the caller of Analyze supplies alongside c.
func (p *StateMachineProducer) Analyze(c TransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	rc, ok := p.resolve(c)
	if !ok || !rc.validate() {
		return TransitionInsufficientEvidence, nil
	}
	return analyzeExpectation(rc)
}

// analyzeExpectation dispatches to the per-Kind analyzer for an ALREADY
// RESOLVED and ALREADY VALIDATED case. It is a package-level function (not
// a StateMachineProducer method) specifically so S10/E7's replay validator
// can call it directly on a FRESH resolvedTransitionCase it built itself
// (its own fresh Fingerprints, paired with the SAME trusted TransitionRule
// the original Candidate resolved to) — without needing a
// StateMachineProducer instance, and without re-running resolve() against a
// registry a second time for a rule it already has in hand.
func analyzeExpectation(rc resolvedTransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	switch rc.Rule.Expectation.Kind {
	case ExpectStateUnchanged:
		return analyzeStateUnchanged(rc)
	case ExpectFactUnchanged:
		return analyzeFactUnchanged(rc)
	case ExpectFactEquals:
		return analyzeFactEquals(rc)
	case ExpectFactTransition:
		return analyzeFactTransition(rc)
	default:
		return TransitionInsufficientEvidence, nil
	}
}

func analyzeStateUnchanged(rc resolvedTransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	before := rc.Transition.BeforeFingerprint.StateFingerprintHash()
	after := rc.Transition.AfterFingerprint.StateFingerprintHash()
	if before == after {
		return TransitionSatisfied, nil
	}
	return TransitionViolated, []TransitionAnomaly{{
		Type:           AnomalyStateTransitionExpectationViolation,
		RuleKind:       ExpectStateUnchanged,
		ExpectedBefore: before,
		ExpectedAfter:  before,
		ObservedBefore: before,
		ObservedAfter:  after,
		EvidenceRefs:   rc.Transition.EvidenceRefs,
	}}
}

// analyzeFactUnchanged distinguishes "fact present with the same value",
// "fact present with a different value", and "fact absent" — absence maps to
// TransitionInsufficientEvidence, never to a violation, via the ok-check
// (value, ok := facts[key]) rather than treating a missing key as "".
func analyzeFactUnchanged(rc resolvedTransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	key := rc.Rule.Expectation.Fact
	beforeVal, beforeOK := rc.Transition.BeforeFingerprint.Facts()[key]
	afterVal, afterOK := rc.Transition.AfterFingerprint.Facts()[key]
	if !beforeOK || !afterOK {
		return TransitionInsufficientEvidence, nil
	}
	if beforeVal == afterVal {
		return TransitionSatisfied, nil
	}
	return TransitionViolated, []TransitionAnomaly{{
		Type:           AnomalyStateTransitionExpectationViolation,
		RuleKind:       ExpectFactUnchanged,
		Fact:           key,
		ExpectedBefore: beforeVal,
		ExpectedAfter:  beforeVal,
		ObservedBefore: beforeVal,
		ObservedAfter:  afterVal,
		EvidenceRefs:   rc.Transition.EvidenceRefs,
	}}
}

func analyzeFactEquals(rc resolvedTransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	key := rc.Rule.Expectation.Fact
	afterVal, ok := rc.Transition.AfterFingerprint.Facts()[key]
	if !ok {
		return TransitionInsufficientEvidence, nil
	}
	if afterVal == rc.Rule.Expectation.AfterValue {
		return TransitionSatisfied, nil
	}
	return TransitionViolated, []TransitionAnomaly{{
		Type:          AnomalyStateTransitionExpectationViolation,
		RuleKind:      ExpectFactEquals,
		Fact:          key,
		ExpectedAfter: rc.Rule.Expectation.AfterValue,
		ObservedAfter: afterVal,
		EvidenceRefs:  rc.Transition.EvidenceRefs,
	}}
}

// analyzeFactTransition judges a rule with an explicit PRECONDITION: it only
// ever imposes a constraint on a transition that actually started at the
// declared BeforeValue.
//
//	before fact absent                      -> insufficient_evidence
//	before present, != BeforeValue           -> not_applicable (precondition never held)
//	before == BeforeValue, after fact absent -> insufficient_evidence
//	before == BeforeValue, after != AfterValue -> violated
//	before == BeforeValue, after == AfterValue -> satisfied
//
// Checking the precondition BEFORE requiring the after-fact to be present
// means a transition that never matched BeforeValue is correctly
// not_applicable even if the after-fact happens to be absent for an unrelated
// reason — the precondition failing is decisive on its own.
func analyzeFactTransition(rc resolvedTransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	key := rc.Rule.Expectation.Fact
	beforeVal, beforeOK := rc.Transition.BeforeFingerprint.Facts()[key]
	if !beforeOK {
		return TransitionInsufficientEvidence, nil
	}
	if beforeVal != rc.Rule.Expectation.BeforeValue {
		return TransitionNotApplicable, nil
	}
	afterVal, afterOK := rc.Transition.AfterFingerprint.Facts()[key]
	if !afterOK {
		return TransitionInsufficientEvidence, nil
	}
	if afterVal == rc.Rule.Expectation.AfterValue {
		return TransitionSatisfied, nil
	}
	return TransitionViolated, []TransitionAnomaly{{
		Type:           AnomalyStateTransitionExpectationViolation,
		RuleKind:       ExpectFactTransition,
		Fact:           key,
		ExpectedBefore: rc.Rule.Expectation.BeforeValue,
		ExpectedAfter:  rc.Rule.Expectation.AfterValue,
		ObservedBefore: beforeVal,
		ObservedAfter:  afterVal,
		EvidenceRefs:   rc.Transition.EvidenceRefs,
	}}
}

// Produce judges c and emits a hypothesis Candidate per violated anomaly,
// tagged Origin{Kind: OriginStateMachine} — a SOURCE label, never a confidence
// signal. Internally it is deliberately boring: resolve the ONE registered
// rule for this transition's actual (ActionID, ProjectorID), validate
// authority, hash the raw case artifact, analyze deterministically, take only
// TransitionViolated, call NewHypothesis. It never re-executes the action,
// re-collects state, calls an LLM, decides a validator, or promotes anything
// — a Validator (not yet built in this pass) and the Engine own everything
// past this point.
//
// Two distinct hashes, never mixed (the S8/S9 discipline again):
//   - c.Transition.TransitionArtifactHash is Explorer's OWN record of the
//     transition it observed — it does not cover the Rule's Expectation/
//     ExpectationSource at all, so it is never what
//     Candidate.Provenance.RawInputHash points at.
//   - transitionCaseArtifactHash is the LOSSLESS canonical serialization of
//     the full resolved case this producer actually judged (Transition +
//     the resolved Rule) — THIS is what Provenance.RawInputHash points at,
//     keeping RawInputHash's frozen, cross-producer meaning: "hash of the
//     raw input the producer ingested". TransitionArtifactHash is still
//     recorded, in Refs, alongside it — never in place of it.
func (p *StateMachineProducer) Produce(c TransitionCase) []*Candidate {
	assessment, anomalies := p.Analyze(c)
	if assessment != TransitionViolated || len(anomalies) == 0 {
		return nil
	}
	rc, ok := p.resolve(c)
	if !ok {
		return nil // Analyze already proved this resolves; never trust that silently
	}

	artifactHash := transitionCaseArtifactHash(rc)
	origin := Origin{Kind: OriginStateMachine, ID: rc.Transition.ScopeHash}
	prov := newProvenance(string(OriginStateMachine), rc.Transition.ScopeHash, "state_machine", artifactHash)
	action := rc.Transition.Action.ID()

	var candidates []*Candidate
	for _, a := range anomalies {
		factDesc := "the overall state"
		if a.Fact != "" {
			factDesc = fmt.Sprintf("fact %q", a.Fact)
		}
		title := fmt.Sprintf("state transition violated %s expectation for %s", a.RuleKind, factDesc)
		rationale := fmt.Sprintf(
			"Observed state transition violated the authorized %s expectation for %s: expected before=%q after=%q, observed before=%q after=%q.",
			a.RuleKind, factDesc, a.ExpectedBefore, a.ExpectedAfter, a.ObservedBefore, a.ObservedAfter,
		)
		cand := NewHypothesis(p.newID(), AnomalyStateTransitionExpectationViolation, title, rc.Transition.ScopeHash, rationale,
			origin, []string{"state_transition", "authorized_expectation"}, prov)
		// The immutable binding is what S10/E7's replay validator actually
		// resolves against — see Candidate.stateMachineBinding's own doc for
		// why Refs (below) is never trusted for that.
		cand.stateMachineBinding = &StateMachineBinding{
			ruleID:           rc.Rule.RuleID,
			actionID:         action,
			projectorID:      rc.Rule.ProjectorID,
			replayTargetHash: replayTargetOf(rc.Scope).Hash(),
			caseArtifactHash: artifactHash,
		}
		cand.Refs = map[string]string{
			"transition_artifact_hash": rc.Transition.TransitionArtifactHash,
			"case_artifact_hash":       artifactHash,
			"rule_id":                  rc.Rule.RuleID,
			"expectation_source_kind":  string(rc.Rule.ExpectationSource.Kind),
			"expectation_source_id":    rc.Rule.ExpectationSource.ID,
			"expectation_kind":         string(rc.Rule.Expectation.Kind),
			"action_registry_key":      action.RegistryKey,
			"action_variant_id":        action.VariantID,
			// projector_id and replay_target_hash exist for S10/E7's replay
			// validator: it cross-checks these against the ActionID/ProjectorID
			// of whatever rule it resolves from Refs["rule_id"] itself, and
			// against its OWN configured ReplayTarget — never trusting these
			// Candidate-carried copies as authoritative on their own.
			"projector_id":       string(rc.Rule.ProjectorID),
			"replay_target_hash": replayTargetOf(rc.Scope).Hash(),
		}
		candidates = append(candidates, cand)
	}
	return candidates
}

// transitionCaseArtifactHash is the LOSSLESS canonical serialization hash of
// the full resolved case (Transition + the resolved Rule) — every field, no
// denoising, and NEVER a bare json.Marshal of an opaque type: stateauth.
// Fingerprint and actionauth.BoundAction both keep their real fields
// unexported specifically so no outside package can construct or serialize
// them directly, and json.Marshal on either would silently produce "{}" (no
// exported fields), which would make this hash blind to everything that
// actually identifies the observed state or the executed action. Every value
// below is therefore read through that type's own exported ACCESSOR methods
// (Fingerprint.ScopeHash/RawStateArtifactHash/StateFingerprintHash/
// ProjectorID/Facts; BoundAction.ID) and written into the hash input
// explicitly, field by field — see canonicalTransitionFingerprint.
// TestE6CaseArtifactHash* proves each of BeforeFingerprint, AfterFingerprint,
// the action identity, ScopeHash, the Rule's Expectation, and the Rule's
// ExpectationSource independently moves this hash. Map keys (a Fingerprint's
// Facts) are sorted only because Go maps have no defined iteration order;
// that sort discards no information (a changed fact value still changes this
// hash).
func transitionCaseArtifactHash(rc resolvedTransitionCase) string {
	var b strings.Builder
	t := rc.Transition
	b.WriteString("scope_hash=" + t.ScopeHash + "\n")
	b.WriteString("scope_target_id=" + rc.Scope.TargetID + "\n")
	b.WriteString("scope_build_id=" + rc.Scope.BuildID + "\n")
	b.WriteString("scope_session_id=" + rc.Scope.SessionID + "\n")
	b.WriteString("scope_protocol=" + rc.Scope.Protocol + "\n")
	b.WriteString("scope_harness_id=" + rc.Scope.HarnessID + "\n")
	b.WriteString("before=" + canonicalTransitionFingerprint(t.BeforeFingerprint) + "\n")
	b.WriteString("action_registry_key=" + t.Action.ID().RegistryKey + "\n")
	b.WriteString("action_variant_id=" + t.Action.ID().VariantID + "\n")
	b.WriteString("after=" + canonicalTransitionFingerprint(t.AfterFingerprint) + "\n")
	b.WriteString("evidence_refs=" + strings.Join(t.EvidenceRefs, ",") + "\n")
	b.WriteString("transition_artifact_hash=" + t.TransitionArtifactHash + "\n")
	b.WriteString("timestamp=" + t.Timestamp.UTC().Format(time.RFC3339Nano) + "\n")
	b.WriteString("rule_id=" + rc.Rule.RuleID + "\n")
	b.WriteString("rule_action_registry_key=" + rc.Rule.ActionID.RegistryKey + "\n")
	b.WriteString("rule_action_variant_id=" + rc.Rule.ActionID.VariantID + "\n")
	b.WriteString("rule_projector_id=" + string(rc.Rule.ProjectorID) + "\n")
	b.WriteString("expectation_kind=" + string(rc.Rule.Expectation.Kind) + "\n")
	b.WriteString("expectation_fact=" + rc.Rule.Expectation.Fact + "\n")
	b.WriteString("expectation_before_value=" + rc.Rule.Expectation.BeforeValue + "\n")
	b.WriteString("expectation_after_value=" + rc.Rule.Expectation.AfterValue + "\n")
	b.WriteString("expectation_source=" + string(rc.Rule.ExpectationSource.Kind) + ":" + rc.Rule.ExpectationSource.ID + "\n")
	return RawInputHash([]byte(b.String()))
}

// canonicalTransitionFingerprint renders every exported facet of a
// stateauth.Fingerprint (its own hashes, its ProjectorID, and its full Facts
// map — read through Fingerprint's own accessor methods, never a struct
// literal or json.Marshal, since its fields are unexported) into one
// canonical, lossless line — Facts keys sorted for determinism only, never
// filtered or normalized away.
func canonicalTransitionFingerprint(fp stateauth.Fingerprint) string {
	facts := fp.Facts()
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("scope_hash=" + fp.ScopeHash())
	b.WriteString("|raw_state_artifact_hash=" + fp.RawStateArtifactHash())
	b.WriteString("|state_fingerprint_hash=" + fp.StateFingerprintHash())
	b.WriteString("|projector_id=" + string(fp.ProjectorID()))
	for _, k := range keys {
		b.WriteString("|fact:" + k + "=" + facts[k])
	}
	return b.String()
}
