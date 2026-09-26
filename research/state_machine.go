package research

import "time"

// S10 DESIGN CONTRACT ONLY — no explorer, no execution engine, no registry, and
// no transition logic exists in this file or anywhere else in this package. It
// defines the vocabulary for a future state-machine explorer so the contract can
// be reviewed and frozen BEFORE any exploration code is written (the same
// discipline S6/S8/S9 followed: contract first, implementation after audit). Do
// not add an Explorer type, a Step/Run method, a registry map, an ActionPolicy,
// or any code that takes an action, until this contract itself has been
// reviewed and frozen.
//
// Eight boundaries are enforced by the TYPE SHAPES below, not merely by
// comment, because a boundary a bad actor (or an over-eager future implementer)
// can route around by adding one field is not a boundary:
//
//  1. No type in this file can carry executable content. There is no Method,
//     URL, Headers, Body, or Command field anywhere below. ActionID and
//     RecoveryPlanRef are opaque registry lookups; what an action or a recovery
//     procedure actually DOES exists only in a future compile-time registry
//     (the S10 analogue of S5's Validator registry).
//  2. An AI-supplied (or candidate-supplied) ActionID is NEVER itself an
//     execution credential — this is the same "AI is not authority" bypass as
//     S9's ExpectationSource, moved from judgment to execution: letting AI pick
//     WHICH pre-registered action runs is functionally the same as letting it
//     write the request, just one indirection removed. ActionSuggestion is the
//     ADVISORY shape AI output may take ("try this ActionID, because..."); it
//     authorizes nothing. Only a BoundAction may ever be executed, and nothing
//     — no AI output, no candidate, no code anywhere yet — can construct one
//     with a real identity (see BoundAction's own doc). The eventual
//     ActionPolicy alone selects a BoundAction from a registry's
//     AllowedActions(scope, state) for the CURRENT scope and state, and may take
//     an ActionSuggestion at most as advisory input to weigh — never as the
//     value it binds. Recovery gets the identical split (RecoveryPlanRef /
//     BoundRecovery), for the same reason.
//  3. Raw state evidence and state identity are two different hashes, never
//     one — the same discipline as S8's GroupArtifactHash/SignatureHash split
//     and S9's caseArtifactHash/comparisonHash split — AND every
//     StateFingerprint carries its OWN ScopeHash, so a fingerprint is
//     self-describing wherever it travels (to disk, through a replay, across a
//     worker) rather than depending on external context to know which
//     target/build/session/protocol/harness produced it.
//  4. Recovery is registry-backed (boundary 2) AND RecoveryOutcome is FACTS
//     ONLY — there is no Verified/conclusion field a recovery implementation
//     could simply set to true. A separate, deterministic Recovered() function
//     decides from the recorded fingerprints; v1's rule is exact match against
//     baseline, the same "no arbitrary conclusion field" discipline as S9's
//     Outcome/Engine split (a Validator reports facts, the Engine decides).
//  5. StateTransition carries FACTS ONLY. There is no Unexpected, Vulnerable,
//     Severity, or State field — exactly like Observation/DiffAnomaly elsewhere
//     in this package. Whether a transition is worth a hypothesis Candidate is
//     a judgment for a future producer to make against an authoritative
//     ExpectationSource (S9's, reused verbatim — boundary 8), never a property
//     the transition record carries about itself.
//  6. ExplorationBudget has NO "0 = unlimited" escape hatch (unlike ai.Budget,
//     where unlimited is a cost tradeoff for a free local model). Every bound
//     must be a strictly positive value or the budget is INVALID.
//  7. Within one ExplorationScope, v1 exploration is SINGLE SESSION and SERIAL
//     — at most one in-flight action at a time. This has no corresponding type
//     (it constrains execution behavior, not data shape) so it is recorded here
//     for the future Explorer to honor: concurrent actions racing against the
//     same session state would make "which action produced this
//     AfterFingerprint" unanswerable, corrupting the evidence StateTransition
//     exists to record.
//  8. S10 invents no second "who may define correct behavior" system. Whatever
//     future producer judges a StateTransition worth a hypothesis reuses S9's
//     ExpectationSource unchanged.

// ExplorationScope bounds "same state, comparable?" to one
// target+build+session+protocol+harness — the S10 analogue of S9's FuzzScope.
type ExplorationScope struct {
	TargetID  string
	BuildID   string
	SessionID string
	Protocol  string
	HarnessID string
}

// Hash is a pure, deterministic identity for the scope — not exploration logic.
func (s ExplorationScope) Hash() string {
	return RawInputHash([]byte(s.TargetID + "|" + s.BuildID + "|" + s.SessionID + "|" + s.Protocol + "|" + s.HarnessID))
}

// StateFingerprint separates the raw collected evidence from the denoised
// identity used for state comparison (boundary 3), and carries its OWN
// ScopeHash so a fingerprint remains self-describing no matter where it travels
// — it never depends on surrounding context to know which scope produced it.
type StateFingerprint struct {
	ScopeHash string
	// RawStateArtifactHash is the hash of the actual, uncondensed state artifact
	// as collected — before any denoising. The eventual raw-input-artifact
	// evidence, same frozen meaning as RawInputHash elsewhere in this package.
	RawStateArtifactHash string
	// StateFingerprintHash is the hash of the DENOISED, canonical projection —
	// dynamic tokens/timestamps/request-ids removed — that state equality and
	// dedup are judged on. Never used as a stand-in for RawStateArtifactHash.
	StateFingerprintHash string
	// Facts names what StateFingerprintHash was computed over (e.g.
	// "auth_state", "session_stage") — for provenance/debugging, never raw bytes.
	Facts map[string]string
}

// ActionID identifies a registered action WITHOUT authorizing its execution. It
// is safe to appear anywhere — including inside an AI suggestion or a
// candidate's advisory Refs — because on its own it grants nothing: there is no
// path from an ActionID to execution that does not pass through a BoundAction.
type ActionID struct {
	RegistryKey string
	// VariantID selects among a registered action's own pre-declared safe
	// parameter variants (also registry-defined) — never a free-form value.
	VariantID string
}

// ActionSuggestion is what an AI (or any other advisory producer) may offer:
// "this action, for this reason, might be worth trying." It is ADVISORY ONLY —
// see boundary 2. No future Executor may accept an ActionSuggestion, or a bare
// ActionID, as authorization to run anything.
type ActionSuggestion struct {
	ActionID  ActionID
	Rationale string
}

// BoundAction is the ONLY value a future Executor may run (boundary 2). Its
// identity is unexported, so no data unmarshaled from AI output, a Candidate, or
// any other advisory source can give it a meaningful identity — and no
// constructor exists anywhere yet (not in this file, not elsewhere in this
// package), so only a zero-value BoundAction (which resolves to nothing in any
// future registry) can be produced today. The future ActionPolicy is the ONLY
// place a constructor will ever be added: it alone selects a BoundAction from a
// registry's AllowedActions(scope, state) for the CURRENT scope/state, taking an
// ActionSuggestion at most as advisory input to weigh — never as the value it
// binds. When ActionPolicy is implemented, strongly prefer moving it to its own
// package, so this privacy is enforced by the Go compiler across a real package
// boundary rather than merely by there being one constructor within one package.
type BoundAction struct {
	id ActionID // deliberately unexported and unconstructed; see doc above
}

// RegisteredAction is the fixed, compile-time metadata an ActionID's
// RegistryKey resolves to. Reversible is REGISTRY METADATA, declared once by the
// code that registers the action — it is not a field on ActionID,
// ActionSuggestion, BoundAction, StateTransition, or any candidate, so nothing
// read at run time can override or forge it. No registry (no map from
// RegistryKey to a RegisteredAction, no concrete action implementation, no
// ActionPolicy) exists yet.
type RegisteredAction struct {
	Key        string
	Reversible bool
}

// RecoveryPlanRef references a compile-time REGISTERED recovery procedure by
// key — advisory/descriptive, exactly like ActionID; it authorizes nothing by
// itself.
type RecoveryPlanRef struct {
	RegistryKey string
}

// BoundRecovery is the ONLY value a future Executor may run to recover state —
// the recovery analogue of BoundAction, with the identical guarantee: unexported
// identity, no constructor exists yet, and the future policy component is the
// sole place one will be added.
type BoundRecovery struct {
	ref RecoveryPlanRef // deliberately unexported and unconstructed; see BoundAction
}

// RecoveryPlan is what a future explorer must hold BEFORE taking its first
// action: a baseline to return to, and the advisory identity of a registered
// (never ad hoc) way back. Executing it requires binding Recovery to a
// BoundRecovery first (boundary 2) — RecoveryPlanRef alone authorizes nothing.
type RecoveryPlan struct {
	Baseline StateFingerprint
	Recovery RecoveryPlanRef
}

// RecoveryOutcome is FACTS ONLY (boundary 4) — there is no Verified/conclusion
// field a recovery implementation could simply set to true. Recovered (below) is
// the separate, deterministic function that decides from these facts.
type RecoveryOutcome struct {
	ScopeHash           string
	BaselineFingerprint string // StateFingerprint.StateFingerprintHash
	ResultFingerprint   string // StateFingerprint.StateFingerprintHash, recollected after running the recovery
	EvidenceRefs        []string
}

// Recovered is the ONLY thing that may declare a recovery successful, and it is
// a pure function of recorded facts, never a stored, independently-settable
// field. v1's rule is exact match against baseline: if a future version ever
// allows semantically-equivalent-but-not-identical recovery, that must be
// decided by a registered comparison rule authorized through ExpectationSource
// (boundary 8) — never by loosening this function ad hoc. Verified=false (i.e.
// Recovered==false) means exploration STOPS; it is never continued on the
// assumption that a rollback worked.
func Recovered(o RecoveryOutcome) bool {
	return o.BaselineFingerprint != "" && o.BaselineFingerprint == o.ResultFingerprint
}

// StateTransition records one observed (before, action, after) step as FACTS
// ONLY (boundary 5). Action is a BoundAction — a transition can only ever
// reference something that WAS actually authorized and executed, never a bare
// ActionID or an AI's ActionSuggestion. A future producer combines a
// StateTransition with an authoritative ExpectationSource-backed rule (boundary
// 8) to decide whether it is worth a hypothesis Candidate; this type never
// carries that conclusion itself. A different AfterFingerprint from
// BeforeFingerprint is a FACT to hand that future producer/rule — never itself
// an anomaly.
type StateTransition struct {
	ScopeHash string

	BeforeFingerprint StateFingerprint
	Action            BoundAction
	AfterFingerprint  StateFingerprint

	EvidenceRefs []string

	// TransitionArtifactHash is the LOSSLESS hash of this transition's own raw
	// record (scope + before + action + after + evidence refs, in the order
	// observed) — the S10 analogue of S9's caseArtifactHash. Never the denoised
	// StateFingerprintHash, and never conflated with it.
	TransitionArtifactHash string

	Timestamp time.Time
}

// ScopeConsistent reports whether t's own ScopeHash agrees with both
// fingerprints it references. A transition whose scope disagrees with either
// fingerprint is self-contradictory and must never be trusted as evidence — this
// is a recomputed check, not a settable field, so nothing can mark an
// inconsistent transition "consistent".
func (t StateTransition) ScopeConsistent() bool {
	return t.ScopeHash != "" && t.ScopeHash == t.BeforeFingerprint.ScopeHash && t.ScopeHash == t.AfterFingerprint.ScopeHash
}

// ExplorationBudget bounds a walk of the state space. UNLIKE ai.Budget (where 0
// means "unlimited" because a local model call is merely a cost tradeoff), every
// field here must be a STRICTLY POSITIVE value: unbounded state-space
// exploration is a live-system risk (state explosion, runaway probing against a
// real target), not a cost concern, so there is no unlimited mode in v1
// (boundary 6).
type ExplorationBudget struct {
	MaxStates         int
	MaxTransitions    int
	MaxDepth          int
	MaxRequests       int
	MaxVisitsPerState int
	MaxBranching      int
	MaxWallTime       time.Duration
}

// Valid reports whether every bound is strictly positive. A budget that fails
// this must never drive exploration — it is INVALID, not permissive; there is no
// "0 means unlimited" reading anywhere in this type.
func (b ExplorationBudget) Valid() bool {
	return b.MaxStates > 0 && b.MaxTransitions > 0 && b.MaxDepth > 0 &&
		b.MaxRequests > 0 && b.MaxVisitsPerState > 0 && b.MaxBranching > 0 &&
		b.MaxWallTime > 0
}
