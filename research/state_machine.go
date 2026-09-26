package research

import "time"

// S10 DESIGN CONTRACT ONLY — no explorer, no execution engine, no registry, and
// no transition logic exists in this file or anywhere else in this package. It
// defines the vocabulary for a future state-machine explorer so the contract can
// be reviewed and frozen BEFORE any exploration code is written (the same
// discipline S6/S8/S9 followed: contract first, implementation after audit). Do
// not add an Explorer type, a Step/Run method, a registry map, or any code that
// takes an action, until this contract itself has been reviewed and frozen.
//
// Five boundaries are enforced by the TYPE SHAPES below, not merely by comment,
// because a boundary a bad actor (or an over-eager future implementer) can route
// around by adding one field is not a boundary:
//
//  1. No type in this file can carry executable content. There is no Method,
//     URL, Headers, Body, or Command field anywhere below. ActionRef and
//     RecoveryPlanRef are opaque registry lookups; what an action or a recovery
//     procedure actually DOES exists only in a future compile-time registry
//     (the S10 analogue of S5's Validator registry), never in a value that a
//     Candidate, an AI proposal, or anything read at run time could populate.
//  2. Raw state evidence and state identity are two different hashes, never
//     one: RawStateArtifactHash (the actual collected artifact, before any
//     denoising) vs StateFingerprintHash (the denoised projection state
//     equality is judged on) — the same discipline as S8's
//     GroupArtifactHash/SignatureHash split and S9's
//     caseArtifactHash/comparisonHash split. A third hash, ExplorationScope.Hash,
//     bounds WHICH fingerprints may even be compared (same target+build+
//     session+protocol+harness) — comparing across scopes is meaningless and
//     this contract provides no method to do it.
//  3. Recovery is registry-backed (RecoveryPlanRef, never AI-authored) AND must
//     be VERIFIED, never assumed: RecoveryOutcome is a fact — did the
//     post-recovery fingerprint actually match the baseline — and an
//     implementation that cannot produce a verified RecoveryOutcome must stop
//     exploring, not continue on faith that a rollback worked.
//  4. StateTransition carries FACTS ONLY. There is no Unexpected, Vulnerable,
//     Severity, or State field — exactly like Observation/DiffAnomaly elsewhere
//     in this package. Whether a transition is worth a hypothesis Candidate is a
//     judgment for a future producer to make against an authoritative
//     ExpectationSource (S9's, reused verbatim — S10 invents no second "who may
//     define correct behavior" system), never a property the transition record
//     carries about itself.
//  5. ExplorationBudget has NO "0 = unlimited" escape hatch (unlike ai.Budget,
//     where unlimited is a cost tradeoff for a free local model). Unbounded
//     state-space exploration is a live-system risk — state explosion, runaway
//     probing — not a cost concern, so every bound must be a strictly positive
//     value or the budget is INVALID and exploration must not start.
//
// One further v1 rule that has no corresponding type (it is a constraint on
// execution behavior, not on data shape, so it is recorded here for the future
// Explorer to honor): within one ExplorationScope, v1 exploration is SINGLE
// SESSION and SERIAL — at most one in-flight action at a time. Concurrent
// actions racing against the same session state would make "which action
// produced this AfterFingerprint" unanswerable, corrupting the very evidence
// StateTransition exists to record.

// ExplorationScope bounds "same state, comparable?" to one
// target+build+session+protocol+harness — the S10 analogue of S9's FuzzScope. A
// StateFingerprint is only ever meaningful when compared to another within the
// SAME scope.
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
// identity used for state comparison — never conflated (boundary 2 above).
type StateFingerprint struct {
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

// ActionRef references a compile-time REGISTERED action by key. It carries NO
// executable content — no Method/URL/Headers/Body/Command field exists here or
// anywhere in this file. AI or candidate text may at most name which
// RegistryKey/VariantID looks worth trying; it can never supply what that action
// does, because there is no field for it to fill in.
type ActionRef struct {
	RegistryKey string
	// VariantID selects among a registered action's own pre-declared safe
	// parameter variants (also registry-defined) — never a free-form value.
	VariantID string
}

// RegisteredAction is the fixed, compile-time metadata an ActionRef resolves to.
// Reversible is REGISTRY METADATA, declared once by the code that registers the
// action — it is not a field on ActionRef, StateTransition, or any candidate, so
// nothing read at run time can override or forge it. No registry (no map from
// RegistryKey to a RegisteredAction, no concrete action implementation) exists
// yet; that arrives alongside the first real registered action, itself subject
// to the same review this contract is undergoing now.
type RegisteredAction struct {
	Key        string
	Reversible bool
}

// RecoveryPlanRef references a compile-time REGISTERED recovery procedure — like
// ActionRef, it carries no executable content. Recovery is never AI-authored or
// candidate-text-authored for the same reason an action isn't: no field exists
// through which either could supply what recovery does.
type RecoveryPlanRef struct {
	RegistryKey string
}

// RecoveryPlan is what a future explorer must hold BEFORE taking its first
// action: a baseline to return to, and a registered (never ad hoc) way back.
type RecoveryPlan struct {
	Baseline StateFingerprint
	Recovery RecoveryPlanRef
}

// RecoveryOutcome is the FACT of whether recovery actually worked — never
// assumed. A future explorer must recollect state after running the registered
// recovery and compare the resulting fingerprint against Baseline; only a match
// is "recovered". Verified=false means exploration STOPS; it is never continued
// on the assumption that a rollback succeeded.
type RecoveryOutcome struct {
	Baseline          StateFingerprint
	ResultFingerprint StateFingerprint
	Verified          bool
}

// StateTransition records one observed (before, action, after) step as FACTS
// ONLY — there is deliberately no Unexpected/Vulnerable/Severity/State field
// here, exactly like Observation/DiffAnomaly elsewhere in this package. A future
// producer combines a StateTransition with an authoritative
// ExpectationSource-backed rule (S9's ExpectationSource, reused — not a second
// authority system) to decide whether it is worth a hypothesis Candidate; this
// type never carries that conclusion itself. A different AfterFingerprint from
// BeforeFingerprint is a FACT to hand a future producer/rule — never itself an
// anomaly, and never grounds to skip an authoritative check.
type StateTransition struct {
	ScopeHash string

	BeforeFingerprint string // StateFingerprint.StateFingerprintHash
	Action            ActionRef
	AfterFingerprint  string // StateFingerprint.StateFingerprintHash

	EvidenceRefs []string

	// TransitionArtifactHash is the LOSSLESS hash of this transition's own raw
	// record (scope + before + action + after + evidence refs, in the order
	// observed) — the S10 analogue of S9's caseArtifactHash: what a future
	// Candidate's Provenance.RawInputHash would point at. Never the denoised
	// StateFingerprintHash, and never conflated with it.
	TransitionArtifactHash string

	Timestamp time.Time
}

// ExplorationBudget bounds a walk of the state space. UNLIKE ai.Budget (where 0
// means "unlimited" because a local model call is merely a cost tradeoff), every
// field here must be a STRICTLY POSITIVE value: unbounded state-space
// exploration is a live-system risk (state explosion, runaway probing against a
// real target), not a cost concern, so there is no unlimited mode in v1.
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
