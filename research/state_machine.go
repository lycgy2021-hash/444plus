package research

import (
	"sort"
	"strings"
	"time"

	"gopoc/internal/actionauth"
)

// S10 DESIGN CONTRACT ONLY — no explorer, no registry, no ActionPolicy, and no
// execution logic exists in this file, in internal/actionauth, or anywhere else.
// This defines the vocabulary for a future state-machine explorer so the
// contract can be reviewed and frozen BEFORE any exploration code is written
// (the same discipline S6/S8/S9 followed: contract first, implementation after
// audit). Do not add an Explorer type, a Step/Run method, a registry map, an
// ActionPolicy, or any code that takes an action, until this contract itself
// has been reviewed and frozen.
//
// Eleven boundaries are enforced by the TYPE SHAPES below (and, for the most
// important ones, by a PACKAGE boundary and constructor-only hashing), not
// merely by comment, because a boundary a bad actor (or an over-eager future
// implementer) can route around by adding one field — or one file to the same
// package, or one caller-supplied hash — is not a boundary:
//
//  1. No type in this file, or in internal/actionauth, can carry executable
//     content. There is no Method, URL, Headers, Body, or Command field
//     anywhere. What an action or recovery procedure actually DOES exists only
//     in a future compile-time registry (the S10 analogue of S5's Validator
//     registry).
//  2. An AI-supplied (or candidate-supplied) ActionID is NEVER itself an
//     execution credential — the same "AI is not authority" bypass as S9's
//     ExpectationSource, moved from judgment to execution. ActionSuggestion
//     (below) is the ADVISORY shape AI output may take; it authorizes nothing.
//     Only an actionauth.BoundAction may ever be executed.
//  3. The capability boundary is a PACKAGE boundary, not merely an unexported
//     field in this package. BoundAction/BoundRecovery live in
//     internal/actionauth, a package separate from research, specifically so
//     Go's compiler — not convention — stops any file this package will ever
//     contain (a future Explorer, AI-glue code, a candidate producer) from
//     constructing one with a real identity. An unexported field inside
//     package research alone would not survive research itself growing an
//     Explorer in a sibling file; a separate package does.
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
//     one — the S8/S9 discipline again — AND every StateFingerprint carries
//     its own ScopeHash, so a fingerprint is self-describing wherever it
//     travels (disk, replay, a different worker).
//  6. StateFingerprint is IMMUTABLE **and internally consistent**, which are
//     NOT the same guarantee: immutable only means nothing can edit it AFTER
//     construction; internally consistent means it could never be BORN wrong
//     in the first place. All fields are unexported (immutability, mirroring
//     Candidate/Evidence's Provenance privacy elsewhere in this package), AND
//     NewStateFingerprint computes BOTH RawStateArtifactHash and
//     StateFingerprintHash itself, from the actual rawArtifact bytes and facts
//     given — a caller can never supply a hash directly, so a StateFingerprint
//     can never be constructed with Facts describing one thing while its hash
//     was computed over another.
//  7. Recovery is registry-backed (boundary 3/4, via actionauth.BoundRecovery)
//     AND RecoveryOutcome is FACTS ONLY — no Verified/conclusion field. It
//     holds the full Baseline/Result StateFingerprint (not bare hash strings),
//     and the separate, deterministic Recovered() function checks BOTH that
//     baseline and result share the outcome's own declared ScopeHash AND that
//     their StateFingerprintHash values match — proving "same scope AND same
//     state", not merely "two strings happened to be equal" (which two
//     fingerprints from different scopes could satisfy by coincidence,
//     especially after crossing disk/replay/worker boundaries).
//  8. StateTransition carries FACTS ONLY — no Unexpected/Vulnerable/Severity/
//     State field. Action is an actionauth.BoundAction: a transition can only
//     ever reference something that WAS actually authorized and executed.
//  9. ExplorationBudget has NO "0 = unlimited" escape hatch. Every bound must
//     be strictly positive or the budget is INVALID.
//  10. S10 invents no second "who may define correct behavior" system —
//     whatever future producer judges a StateTransition worth a hypothesis
//     reuses S9's ExpectationSource unchanged.
//  11. Also recorded here (no corresponding type; it constrains execution
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

// StateFingerprint separates raw collected evidence from denoised identity
// (boundary 4) and is itself immutable AND internally consistent (boundary 5):
// every field is unexported, and — critically — NewStateFingerprint computes
// BOTH hashes itself; a caller can never supply a hash directly. Immutable is
// not the same guarantee as internally consistent: a constructor that accepted
// a caller-supplied StateFingerprintHash alongside a separate Facts argument
// could still be handed a hash that was computed over different facts than the
// ones stored — "born inconsistent" — even though nothing could edit either one
// afterward. Computing both hashes from the actual inputs, inside the
// constructor, closes that: the same discipline as S6/S8/S9's "artifact bytes →
// a deterministic canonicalizing function → a hash", never "caller asserts this
// is the hash".
type StateFingerprint struct {
	scopeHash            string
	rawStateArtifactHash string
	stateFingerprintHash string
	facts                map[string]string
}

// NewStateFingerprint constructs an immutable, internally-consistent
// StateFingerprint. rawArtifact is the actual raw state artifact bytes (hashed
// here, never accepted as a pre-computed hash string); facts is the canonical
// projection of that artifact used for state-equality (also copied, then hashed
// here via a deterministic, map-order-independent canonicalization — see
// canonicalFactsHash). If a future producer's canonical projection is not
// simply this key→value shape, it must canonicalize into this shape (or a
// documented successor) before calling this constructor — the invariant that
// must never be broken is that ONLY this constructor computes
// StateFingerprintHash, from the SAME facts stored alongside it.
func NewStateFingerprint(scopeHash string, rawArtifact []byte, facts map[string]string) StateFingerprint {
	copied := make(map[string]string, len(facts))
	for k, v := range facts {
		copied[k] = v
	}
	return StateFingerprint{
		scopeHash:            scopeHash,
		rawStateArtifactHash: RawInputHash(rawArtifact),
		stateFingerprintHash: canonicalFactsHash(copied),
		facts:                copied,
	}
}

// canonicalFactsHash deterministically hashes a facts map: keys sorted (Go maps
// have no defined order, so sorting is lossless — the same discipline as S9's
// caseArtifactHash header-key sorting), joined canonically, then hashed. The
// same facts always hash the same regardless of map iteration order; a single
// changed value always changes the hash.
func canonicalFactsHash(facts map[string]string) string {
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(facts[k])
		b.WriteString("\n")
	}
	return RawInputHash([]byte(b.String()))
}

func (f StateFingerprint) ScopeHash() string            { return f.scopeHash }
func (f StateFingerprint) RawStateArtifactHash() string { return f.rawStateArtifactHash }
func (f StateFingerprint) StateFingerprintHash() string { return f.stateFingerprintHash }

// Facts returns a copy of the facts this fingerprint was computed over — for
// provenance/debugging, never raw bytes, and never a handle the caller could
// use to mutate the fingerprint's own internal state.
func (f StateFingerprint) Facts() map[string]string {
	copied := make(map[string]string, len(f.facts))
	for k, v := range f.facts {
		copied[k] = v
	}
	return copied
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
	Baseline StateFingerprint
	Recovery actionauth.RecoveryPlanRef
}

// RecoveryOutcome is FACTS ONLY (boundary 6) — there is no Verified/conclusion
// field a recovery implementation could simply set to true. It holds the FULL
// Baseline/Result fingerprints (not bare hash strings) so Recovered can prove
// "same scope AND same state", not merely "two strings happened to match".
type RecoveryOutcome struct {
	ScopeHash    string
	Baseline     StateFingerprint
	Result       StateFingerprint
	EvidenceRefs []string
}

// Recovered is the ONLY thing that may declare a recovery successful, and it is
// a pure function of recorded facts, never a stored, independently-settable
// field. It requires BOTH fingerprints to actually belong to the outcome's own
// declared scope AND to share a (non-empty) StateFingerprintHash — proving same
// scope and same state, not a coincidental string match between two
// fingerprints that could, after crossing a disk/replay/worker boundary, have
// come from different scopes entirely. v1's rule is exact match against
// baseline; if a future version ever allows semantically-equivalent-but-not-
// identical recovery, that must be decided by a registered comparison rule
// authorized through ExpectationSource (boundary 9) — never by loosening this
// function ad hoc. Recovered==false means exploration STOPS; it is never
// continued on the assumption that a rollback worked.
func Recovered(o RecoveryOutcome) bool {
	return o.ScopeHash != "" &&
		o.Baseline.ScopeHash() == o.ScopeHash &&
		o.Result.ScopeHash() == o.ScopeHash &&
		o.Baseline.StateFingerprintHash() != "" &&
		o.Baseline.StateFingerprintHash() == o.Result.StateFingerprintHash()
}

// StateTransition records one observed (before, action, after) step as FACTS
// ONLY (boundary 7). Action is an actionauth.BoundAction — a transition can
// only ever reference something that WAS actually authorized and executed,
// never a bare ActionID or an ActionSuggestion. A future producer combines a
// StateTransition with an authoritative ExpectationSource-backed rule
// (boundary 9) to decide whether it is worth a hypothesis Candidate; this type
// never carries that conclusion itself.
type StateTransition struct {
	ScopeHash string

	BeforeFingerprint StateFingerprint
	Action            actionauth.BoundAction
	AfterFingerprint  StateFingerprint

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
// every field here must be a STRICTLY POSITIVE value (boundary 8).
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
