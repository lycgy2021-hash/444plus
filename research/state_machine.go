package research

import "time"

// S10 DESIGN CONTRACT ONLY — no explorer, no execution engine, no transition
// logic exists in this file or anywhere else in this package. It defines the
// vocabulary for a future state-machine explorer so the contract can be reviewed
// and frozen BEFORE any exploration code is written (the same discipline S6/S8/S9
// followed: contract first, implementation after audit). Do not add an Explorer
// type, a Step/Run method, or any code that takes an action, until this contract
// itself has been reviewed.
//
// Hard boundaries the EVENTUAL implementation must respect (recorded here now,
// enforced in code only once that code exists):
//
//   - Only a ReadOnlyAction with Reversible=true may be taken automatically by an
//     explorer. Anything else requires the same explicit, registered,
//     human-authorized path S5's Validator requires for a state-changing action —
//     it is never synthesized from AI or candidate text and never auto-executed.
//     "Read-only" is a property the implementation must PROVE (e.g. idempotence:
//     repeating the action from the same state yields the same StateFingerprint),
//     not merely assert on the struct literal.
//   - AI may explain why two StateFingerprints differ, or suggest a region of the
//     state space is worth exploring. It may NEVER generate an action that gets
//     executed directly (the same "AI proposes, a registered Validator/Action
//     decides what is safe to run" split as S5), and it may NEVER decide that a
//     different fingerprint constitutes a vulnerability. A different
//     StateFingerprint is a FACT for a Validator to investigate — like a
//     CrashSignature or a DiffAnomaly — never itself an anomaly.
//   - Exploration is budget-bounded (ExplorationBudget, modeled on ai.Budget) and
//     MUST detect and stop on cycles (MaxRevisits) — no unbounded state-space
//     walk, ever.
//   - Every exploration must hold a RecoveryPlan back to a known-good baseline
//     BEFORE taking its first action. A target/protocol for which recovery is not
//     achievable is simply not explorable in v1 — this is a hard precondition to
//     starting, not a best-effort cleanup step to attempt afterward.
//   - Expectation/authority discipline carries over unchanged from S9: whatever
//     eventually decides "this state transition is expected" vs "this is
//     surprising" must trace to an ExpectationSource-equivalent authority, not to
//     AI or candidate text. S10 will reuse ExpectationSource itself rather than
//     invent a parallel authority concept.

// StateFingerprint is a stable, content-addressed identity for an observed
// system state — the S10 analogue of CrashSignature (S8) / caseArtifactHash (S9):
// a hash over the FACTS that define "same state", never raw output. Its concrete
// construction is target/protocol specific and is deliberately left abstract
// here; it is designed alongside the first real Action that produces one, not
// invented speculatively before any real protocol needs it.
type StateFingerprint struct {
	Hash string
	// Facts names what the fingerprint is actually computed over (e.g.
	// "auth_state", "session_stage"), for provenance/debugging — never raw bytes.
	Facts map[string]string
}

// ReadOnlyAction is a named, CODE-REGISTERED, side-effect-free probe an explorer
// may take from a state — the S10 analogue of S5's Validator: the action's
// behavior is defined in this codebase, never synthesized from AI or candidate
// text at run time.
type ReadOnlyAction struct {
	Name string
	// Reversible must be true for any action a v1 explorer takes automatically;
	// false requires the same explicit authorization path as a state-changing S5
	// Validator action.
	Reversible bool
}

// StateTransition records one observed (State, Action) -> State step, as a FACT
// only — no verdict, no severity, exactly like Observation elsewhere in this
// package.
type StateTransition struct {
	From      StateFingerprint
	Action    ReadOnlyAction
	To        StateFingerprint
	Timestamp time.Time
}

// ExplorationBudget bounds a walk of the state space, modeled on ai.Budget: a
// zero field means unlimited for that dimension, but any real v1 exploration
// must set MaxSteps, MaxWallClock and MaxRevisits to guarantee termination.
type ExplorationBudget struct {
	MaxSteps     int
	MaxWallClock time.Duration
	// MaxRevisits caps how many times the SAME StateFingerprint may be reached
	// before an explorer treats that region as covered and stops — the
	// cycle-detection mechanism required before any exploration code is written.
	MaxRevisits int
}

// RecoveryPlan is how an explorer gets back to a known-good baseline state. An
// explorer must hold one before its first action.
type RecoveryPlan struct {
	Baseline StateFingerprint
	// Reset, once implemented, must itself be a ReadOnlyAction-shaped, registered,
	// idempotent operation — never ad hoc probing code.
	Reset ReadOnlyAction
}
