package research

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopoc/internal/stateauth"
)

// StateMachineProducer (S10/E6) turns a TransitionCase — one real, already
// recorded StateTransition paired with an explicit, pre-declared, authoritative
// TransitionExpectation — into a hypothesis Candidate when the observed
// transition VIOLATES that expectation. It is a deterministic PRODUCER, exactly
// like the diff/fuzz/differential producers: it consumes an already-collected
// StateTransition (Explorer's own output), judges it against a rule it never
// authored, and emits at most one hypothesis per violated fact — it never
// re-executes an action, re-collects state, calls an LLM, decides a validator,
// or promotes anything.
//
// The one rule this file exists to enforce: "State A != State B" is NEVER
// itself an anomaly. Only a transition that violates an ALREADY-AUTHORIZED
// contract — one that existed before exploration ran, authored by
// ExpectationSource (S9's frozen whitelist, reused unchanged) — produces a
// candidate. E6 invents no second "who may define correct behavior" system,
// and it never lets exploration retroactively invent the expectation it is
// then judged against (that would be hindsight bias, not detection): a future
// caller must register/declare Expectation BEFORE running the Explorer
// session that produces the StateTransition it will be checked against.
//
// v1 is deliberately narrow (mirroring S9's own v1 scope note): four
// declarative expectation kinds, no callback, no free-form rule language. E6
// stops at Candidate — no replay validator, no LLM judgment, and no new
// execution capability live here; those are explicitly out of scope for this
// pass.
type StateMachineProducer struct {
	newID func() string
}

func NewStateMachineProducer() *StateMachineProducer {
	return &StateMachineProducer{newID: SequentialIDs(time.Now().UTC().Year())}
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
	// sides of the transition against declared values.
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

// TransitionCase is the E6 producer's ONLY input: one observed StateTransition
// (Explorer's own recorded output), paired with the explicit expectation it is
// judged against and who authored that expectation. ExpectationSource reuses
// S9's frozen whitelist UNCHANGED — E6 invents no second "who may define
// correct behavior" system, and "ai"/"llm"/"candidate"/"proposal"/"fuzz"/
// "diff"/even "state_machine" itself all remain non-authoritative here exactly
// as they are for S9's differential engine.
type TransitionCase struct {
	Transition StateTransition

	Expectation       TransitionExpectation
	ExpectationSource ExpectationSource
}

// validate reports whether c is well-formed and authorized enough to judge AT
// ALL. An invalid case is never judged — it yields TransitionInsufficientEvidence
// and zero candidates, exactly like S9's DifferentialCase.validate: this is the
// structural guard against an unauthorized ExpectationSource, a self-
// contradictory (scope-inconsistent) transition, or a transition whose Action
// was never actually authorized for the state it claims to have started from
// (a zero-value or replayed actionauth.BoundAction always fails ValidFor and so
// always fails here).
func (c TransitionCase) validate() bool {
	if !c.ExpectationSource.authoritative() {
		return false
	}
	if !c.Transition.ScopeConsistent() {
		return false
	}
	if !c.Transition.Action.ValidFor(c.Transition.ScopeHash, c.Transition.BeforeFingerprint.StateFingerprintHash()) {
		return false
	}
	switch c.Expectation.Kind {
	case ExpectStateUnchanged:
		return true
	case ExpectFactUnchanged, ExpectFactEquals, ExpectFactTransition:
		return c.Expectation.Fact != ""
	default:
		return false
	}
}

// TransitionAssessment is a THREE-STATE result, never a bool — the same
// discipline that keeps "no evidence" from ever collapsing into "violated".
type TransitionAssessment string

const (
	// TransitionSatisfied: the declared expectation held. Zero candidates.
	TransitionSatisfied TransitionAssessment = "satisfied"
	// TransitionViolated: the declared expectation demonstrably did not hold.
	// The only assessment that ever produces a candidate.
	TransitionViolated TransitionAssessment = "violated"
	// TransitionInsufficientEvidence: the case is invalid/unauthorized, or a
	// fact the rule needs was simply ABSENT (not present-with-empty-string —
	// see the ok-check discipline in the analyze* helpers below). Zero
	// candidates: absence of evidence is never itself a violation.
	TransitionInsufficientEvidence TransitionAssessment = "insufficient_evidence"
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

// Analyze judges c deterministically and with no I/O, returning a three-state
// assessment plus (only when TransitionViolated) the anomaly it found. An
// invalid/unauthorized case, or one whose rule needs a fact that is simply
// ABSENT, is TransitionInsufficientEvidence — never TransitionViolated. This
// is the E6 analogue of DifferentialProducer.Analyze: it never guesses "what
// should have happened" from the observed transition itself (that would be
// hindsight bias) — it only ever compares the observed transition against an
// expectation that was declared before this method ever ran.
func (p *StateMachineProducer) Analyze(c TransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	if !c.validate() {
		return TransitionInsufficientEvidence, nil
	}
	switch c.Expectation.Kind {
	case ExpectStateUnchanged:
		return analyzeStateUnchanged(c)
	case ExpectFactUnchanged:
		return analyzeFactUnchanged(c)
	case ExpectFactEquals:
		return analyzeFactEquals(c)
	case ExpectFactTransition:
		return analyzeFactTransition(c)
	default:
		return TransitionInsufficientEvidence, nil
	}
}

func analyzeStateUnchanged(c TransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	before := c.Transition.BeforeFingerprint.StateFingerprintHash()
	after := c.Transition.AfterFingerprint.StateFingerprintHash()
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
		EvidenceRefs:   c.Transition.EvidenceRefs,
	}}
}

// analyzeFactUnchanged distinguishes "fact present with the same value",
// "fact present with a different value", and "fact absent" — absence maps to
// TransitionInsufficientEvidence, never to a violation, via the ok-check
// (value, ok := facts[key]) rather than treating a missing key as "".
func analyzeFactUnchanged(c TransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	key := c.Expectation.Fact
	beforeVal, beforeOK := c.Transition.BeforeFingerprint.Facts()[key]
	afterVal, afterOK := c.Transition.AfterFingerprint.Facts()[key]
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
		EvidenceRefs:   c.Transition.EvidenceRefs,
	}}
}

func analyzeFactEquals(c TransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	key := c.Expectation.Fact
	afterVal, ok := c.Transition.AfterFingerprint.Facts()[key]
	if !ok {
		return TransitionInsufficientEvidence, nil
	}
	if afterVal == c.Expectation.AfterValue {
		return TransitionSatisfied, nil
	}
	return TransitionViolated, []TransitionAnomaly{{
		Type:          AnomalyStateTransitionExpectationViolation,
		RuleKind:      ExpectFactEquals,
		Fact:          key,
		ExpectedAfter: c.Expectation.AfterValue,
		ObservedAfter: afterVal,
		EvidenceRefs:  c.Transition.EvidenceRefs,
	}}
}

// analyzeFactTransition judges BOTH sides against their declared values (per
// the E6 contract's own stated semantics: before==BeforeValue AND
// after==AfterValue). Either fact being ABSENT (not merely mismatched) is
// insufficient evidence, never a violation.
func analyzeFactTransition(c TransitionCase) (TransitionAssessment, []TransitionAnomaly) {
	key := c.Expectation.Fact
	beforeVal, beforeOK := c.Transition.BeforeFingerprint.Facts()[key]
	afterVal, afterOK := c.Transition.AfterFingerprint.Facts()[key]
	if !beforeOK || !afterOK {
		return TransitionInsufficientEvidence, nil
	}
	if beforeVal == c.Expectation.BeforeValue && afterVal == c.Expectation.AfterValue {
		return TransitionSatisfied, nil
	}
	return TransitionViolated, []TransitionAnomaly{{
		Type:           AnomalyStateTransitionExpectationViolation,
		RuleKind:       ExpectFactTransition,
		Fact:           key,
		ExpectedBefore: c.Expectation.BeforeValue,
		ExpectedAfter:  c.Expectation.AfterValue,
		ObservedBefore: beforeVal,
		ObservedAfter:  afterVal,
		EvidenceRefs:   c.Transition.EvidenceRefs,
	}}
}

// Produce judges c and emits a hypothesis Candidate per violated anomaly,
// tagged Origin{Kind: OriginStateMachine} — a SOURCE label, never a confidence
// signal. Internally it is deliberately boring: validate authority, hash the
// raw case artifact, analyze deterministically, take only TransitionViolated,
// call NewHypothesis. It never re-executes the action, re-collects state,
// calls an LLM, decides a validator, or promotes anything — a Validator (not
// yet built in this pass) and the Engine own everything past this point.
//
// Two distinct hashes, never mixed (the S8/S9 discipline again):
//   - c.Transition.TransitionArtifactHash is Explorer's OWN record of the
//     transition it observed — it does not cover Expectation/ExpectationSource
//     at all, so it is never what Candidate.Provenance.RawInputHash points at.
//   - transitionCaseArtifactHash is the LOSSLESS canonical serialization of
//     the full TransitionCase this producer actually consumed (Transition +
//     Expectation + ExpectationSource) — THIS is what Provenance.RawInputHash
//     points at, keeping RawInputHash's frozen, cross-producer meaning: "hash
//     of the raw input the producer ingested". TransitionArtifactHash is still
//     recorded, in Refs, alongside it — never in place of it.
func (p *StateMachineProducer) Produce(c TransitionCase) []*Candidate {
	assessment, anomalies := p.Analyze(c)
	if assessment != TransitionViolated || len(anomalies) == 0 {
		return nil
	}

	artifactHash := transitionCaseArtifactHash(c)
	origin := Origin{Kind: OriginStateMachine, ID: c.Transition.ScopeHash}
	prov := newProvenance(string(OriginStateMachine), c.Transition.ScopeHash, "state_machine", artifactHash)
	action := c.Transition.Action.ID()

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
		cand := NewHypothesis(p.newID(), AnomalyStateTransitionExpectationViolation, title, c.Transition.ScopeHash, rationale,
			origin, []string{"state_transition", "authorized_expectation"}, prov)
		cand.Refs = map[string]string{
			"transition_artifact_hash": c.Transition.TransitionArtifactHash,
			"case_artifact_hash":       artifactHash,
			"expectation_source_kind":  string(c.ExpectationSource.Kind),
			"expectation_source_id":    c.ExpectationSource.ID,
			"expectation_kind":         string(c.Expectation.Kind),
			"action_registry_key":      action.RegistryKey,
			"action_variant_id":        action.VariantID,
		}
		candidates = append(candidates, cand)
	}
	return candidates
}

// transitionCaseArtifactHash is the LOSSLESS canonical serialization hash of
// the full TransitionCase (Transition + Expectation + ExpectationSource) —
// every field, no denoising. Map keys (a Fingerprint's Facts) are sorted only
// because Go maps have no defined iteration order; that sort discards no
// information (a changed fact value still changes this hash).
func transitionCaseArtifactHash(c TransitionCase) string {
	var b strings.Builder
	t := c.Transition
	b.WriteString("scope_hash=" + t.ScopeHash + "\n")
	b.WriteString("before=" + canonicalTransitionFingerprint(t.BeforeFingerprint) + "\n")
	b.WriteString("action_registry_key=" + t.Action.ID().RegistryKey + "\n")
	b.WriteString("action_variant_id=" + t.Action.ID().VariantID + "\n")
	b.WriteString("after=" + canonicalTransitionFingerprint(t.AfterFingerprint) + "\n")
	b.WriteString("evidence_refs=" + strings.Join(t.EvidenceRefs, ",") + "\n")
	b.WriteString("transition_artifact_hash=" + t.TransitionArtifactHash + "\n")
	b.WriteString("timestamp=" + t.Timestamp.UTC().Format(time.RFC3339Nano) + "\n")
	b.WriteString("expectation_kind=" + string(c.Expectation.Kind) + "\n")
	b.WriteString("expectation_fact=" + c.Expectation.Fact + "\n")
	b.WriteString("expectation_before_value=" + c.Expectation.BeforeValue + "\n")
	b.WriteString("expectation_after_value=" + c.Expectation.AfterValue + "\n")
	b.WriteString("expectation_source=" + string(c.ExpectationSource.Kind) + ":" + c.ExpectationSource.ID + "\n")
	return RawInputHash([]byte(b.String()))
}

// canonicalTransitionFingerprint renders every exported facet of a
// stateauth.Fingerprint (its own hashes, its ProjectorID, and its full Facts
// map) into one canonical, lossless line — Facts keys sorted for determinism
// only, never filtered or normalized away.
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
