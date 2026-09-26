package research

import (
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// S10 DESIGN CONTRACT ONLY — no explorer, no registry, no ActionPolicy, and no
// execution logic exists in this file, in internal/actionauth, in
// internal/stateauth, or anywhere else. This defines the vocabulary for a
// future state-machine explorer so the contract can be reviewed and frozen
// BEFORE any exploration code is written (the same discipline S6/S8/S9
// followed: contract first, implementation after audit). Do not add an
// Explorer type, a Step/Run method, a registry map, an ActionPolicy, or any
// code that takes an action, until this contract itself has been reviewed and
// frozen.
//
// Twelve boundaries are enforced by the TYPE SHAPES below (and, for the two
// authority-bearing ones, by an actual PACKAGE boundary and constructor-only
// hashing — not merely by comment), because a boundary a bad actor (or an
// over-eager future implementer) can route around by adding one field, or one
// file to the same package, or one caller-supplied hash or fact, is not a
// boundary:
//
//  1. No type in this file, in internal/actionauth, or in internal/stateauth,
//     can carry executable content. There is no Method, URL, Headers, Body,
//     or Command field anywhere. What an action or recovery procedure
//     actually DOES exists only in a future compile-time registry (the S10
//     analogue of S5's Validator registry), which is IMMUTABLE for the
//     lifetime of a process in v1 — no hot reload, a deliberate scope
//     decision (see actionauth.BoundAction's doc): a half-implemented
//     revision concept that ValidFor doesn't actually check would look like
//     protection that isn't enforced, which is worse than no such field at
//     all.
//  2. An AI-supplied (or candidate-supplied) ActionID is NEVER itself an
//     execution credential — the same "AI is not authority" bypass as S9's
//     ExpectationSource, moved from judgment to execution. ActionSuggestion
//     (below) is the ADVISORY shape AI output may take; it authorizes
//     nothing. Only an actionauth.BoundAction may ever be executed.
//  3. BOTH authority boundaries this contract needs — who may authorize an
//     ACTION, and who may declare an authoritative STATE — are PACKAGE
//     boundaries, not merely an unexported field in this package, and they
//     are enforced at the SAME level. actionauth.BoundAction/BoundRecovery
//     live in internal/actionauth; stateauth.Fingerprint lives in
//     internal/stateauth. Both are separate from research specifically so
//     Go's compiler — not convention — stops any file this package will ever
//     contain (a future Explorer, AI-glue code, a candidate producer) from
//     constructing either one with a real identity. An unexported field (or
//     an unexported constructor) inside package research alone would not
//     survive research itself growing an Explorer in a sibling file; a
//     separate package does. The future ActionPolicy (in actionauth) and the
//     future concrete StateProjector (in stateauth) are the sole places their
//     respective constructors are ever added — and, for the identical reason,
//     both must be implemented inside their own authority package rather than
//     in research, even though their logic needs scope/state/target-specific
//     knowledge that might otherwise seem to belong "closer to" research.
//  4. A BoundAction/BoundRecovery is bound to the scope AND state it was
//     authorized for, not just to an action identity — closing a
//     stale-capability / cross-state-replay gap: without this, a capability
//     issued while the system was in "Scope X, State A" would be a bare
//     ActionID with no record of that context, and could be replayed after the
//     scope changed or the state moved to "State B", since nothing about the
//     value itself would say it had gone stale. actionauth.BoundAction.ValidFor
//     (and BoundRecovery.ValidFor) is how a future Executor is REQUIRED to
//     re-verify this immediately before running anything — never trusting that
//     a capability obtained earlier is still good for the CURRENT scope/state.
//  5. Raw state evidence and state identity are two different hashes, never
//     one — the S8/S9 discipline again — AND every stateauth.Fingerprint
//     carries its own ScopeHash, so a fingerprint is self-describing wherever
//     it travels (disk, replay, a different worker).
//  6. stateauth.Fingerprint is IMMUTABLE **and internally consistent**, which
//     are NOT the same guarantee: immutable only means nothing can edit it
//     AFTER construction; internally consistent means it could never be BORN
//     wrong in the first place. All fields are unexported, AND stateauth's
//     newFingerprint computes BOTH RawStateArtifactHash and
//     StateFingerprintHash itself, from the actual rawArtifact bytes and facts
//     given — a caller can never supply a hash directly, so a Fingerprint can
//     never be constructed with Facts describing one thing while its hash was
//     computed over another.
//  7. Internally consistent is STILL not the same guarantee as AUTHORITATIVE —
//     a Fingerprint could be self-consistent and still describe FABRICATED
//     facts, if whatever called the constructor was free to invent the facts
//     map, and a fabricated fingerprint feeding a future ActionPolicy's
//     AllowedActions(scope, state) decision would let whoever fabricated it
//     indirectly control action authorization — the same class of bypass as
//     boundaries 2 and 4, moved one step further upstream (to defining the
//     STATE itself, not just the action or the judgment). Closed COMPLETELY
//     (not merely by review discipline) by moving Fingerprint, StateArtifact,
//     ProjectorID, StateProjector, and their constructor into
//     internal/stateauth (boundary 3): nothing in this package, or any
//     package research will ever contain, can call stateauth's unexported
//     constructor or write a Fingerprint struct literal, because neither is
//     visible outside internal/stateauth. This upgrades what an earlier round
//     of this contract had to leave as an honestly-documented residual caveat
//     ("a future file added to research itself could still call
//     newStateFingerprint directly") into the same compiler-enforced guarantee
//     boundary 3 already gives actionauth.BoundAction — the two authority
//     boundaries are now at parity.
//  8. Recovery is registry-backed (boundary 3/4, via actionauth.BoundRecovery)
//     AND stateauth.RecoveryOutcome is FACTS ONLY — no Verified/conclusion
//     field. It holds the full Baseline/Result Fingerprint (not bare hash
//     strings), and the separate, deterministic stateauth.Recovered function
//     checks BOTH that baseline and result share the outcome's own declared
//     ScopeHash AND that their StateFingerprintHash values match — proving
//     "same scope AND same state", not merely "two strings happened to be
//     equal" (which two fingerprints from different scopes could satisfy by
//     coincidence, especially after crossing disk/replay/worker boundaries).
//     RecoveryOutcome and Recovered live in internal/stateauth, not here,
//     because recovery verification is fundamentally a state-authority
//     question — it never touches an actionauth.BoundAction.
//  9. StateTransition carries FACTS ONLY — no Unexpected/Vulnerable/Severity/
//     State field. Action is an actionauth.BoundAction: a transition can only
//     ever reference something that WAS actually authorized and executed.
//  10. ExplorationBudget has NO "0 = unlimited" escape hatch. Every bound must
//     be strictly positive or the budget is INVALID.
//  11. S10 invents no second "who may define correct behavior" system —
//     whatever future producer judges a StateTransition worth a hypothesis
//     reuses S9's ExpectationSource unchanged.
//  12. Also recorded here (no corresponding type; it constrains execution
//     behavior, not data shape): within one ExplorationScope, v1 exploration
//     is SINGLE SESSION and SERIAL — at most one in-flight action at a time.

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

// ActionSuggestion is what an AI (or any other advisory producer) may offer:
// "this action, for this reason, might be worth trying." It is ADVISORY
// ONLY (boundary 2) — freely constructible, and it grants nothing: no future
// Executor may accept an ActionSuggestion, or a bare actionauth.ActionID, as
// authorization to run anything. Only an actionauth.BoundAction may be
// executed, and — per actionauth's own doc — nothing in this package, or any
// package, can construct one with a real identity.
type ActionSuggestion struct {
	ActionID  actionauth.ActionID
	Rationale string
}

// RecoveryPlan is what a future explorer must hold BEFORE taking its first
// action: a baseline to return to, and the advisory identity of a registered
// (never ad hoc) way back. Executing it requires binding Recovery to an
// actionauth.BoundRecovery first — the advisory reference alone authorizes
// nothing.
type RecoveryPlan struct {
	Baseline stateauth.Fingerprint
	Recovery actionauth.RecoveryPlanRef
}

// StateTransition records one observed (before, action, after) step as FACTS
// ONLY (boundary 9). Action is an actionauth.BoundAction — a transition can
// only ever reference something that WAS actually authorized and executed,
// never a bare ActionID or an ActionSuggestion. A future producer combines a
// StateTransition with an authoritative ExpectationSource-backed rule
// (boundary 11) to decide whether it is worth a hypothesis Candidate; this
// type never carries that conclusion itself. It is the one type that
// legitimately spans both authority packages (stateauth.Fingerprint +
// actionauth.BoundAction) — it is a pure coordination record, not itself an
// authority.
type StateTransition struct {
	ScopeHash string

	BeforeFingerprint stateauth.Fingerprint
	Action            actionauth.BoundAction
	AfterFingerprint  stateauth.Fingerprint

	EvidenceRefs []string

	// TransitionArtifactHash is the LOSSLESS hash of this transition's own raw
	// record — the S10 analogue of S9's caseArtifactHash. Never the denoised
	// StateFingerprintHash, and never conflated with it.
	TransitionArtifactHash string

	Timestamp time.Time
}

// ScopeConsistent reports whether t's own ScopeHash agrees with both
// fingerprints it references. A transition whose scope disagrees with either
// fingerprint is self-contradictory and must never be trusted as evidence —
// this is a recomputed check, not a settable field.
func (t StateTransition) ScopeConsistent() bool {
	return t.ScopeHash != "" && t.ScopeHash == t.BeforeFingerprint.ScopeHash() && t.ScopeHash == t.AfterFingerprint.ScopeHash()
}

// ExplorationBudget bounds a walk of the state space. UNLIKE ai.Budget (where 0
// means "unlimited" because a local model call is merely a cost tradeoff),
// every field here must be a STRICTLY POSITIVE value (boundary 10).
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
// this must never drive exploration — it is INVALID, not permissive.
func (b ExplorationBudget) Valid() bool {
	return b.MaxStates > 0 && b.MaxTransitions > 0 && b.MaxDepth > 0 &&
		b.MaxRequests > 0 && b.MaxVisitsPerState > 0 && b.MaxBranching > 0 &&
		b.MaxWallTime > 0
}
