// Package actionauth is the S10 CAPABILITY BOUNDARY — still contract only. No
// ActionPolicy, no registry, and no execution logic exists here or anywhere
// else yet. It exists as its OWN PACKAGE, separate from research, specifically
// so the authority boundary is enforced by the Go compiler across a real
// package boundary, not merely by an unexported field within one package.
//
// The gap this closes: an unexported field on a type living IN package research
// only stops OTHER packages from forging it — it does nothing to stop code
// added later to research ITSELF (a future Explorer, AI-glue code, a candidate
// producer) from writing a struct literal with that field, since Go visibility
// is package-scoped, not file-scoped. Moving BoundAction/BoundRecovery here
// means research (which will eventually hold the Explorer, AI glue, and
// candidate producers) can only ever see the OPAQUE types below — it has no
// way, from any file it will ever contain, to construct one with a real
// identity, because the identity field is unexported HERE and this package is
// the only place a constructor will ever be added (the future ActionPolicy's
// constructor belongs in this package, never in research).
package actionauth

// ActionID identifies a registered action. Holding one grants nothing — it is
// safe to pass around freely, including as advisory input from an AI
// suggestion elsewhere in the Research Plane (see research.ActionSuggestion),
// because there is no path from an ActionID alone to execution.
type ActionID struct {
	RegistryKey string
	// VariantID selects among a registered action's own pre-declared safe
	// parameter variants (also registry-defined) — never a free-form value.
	VariantID string
}

// RegisteredAction is registry metadata: what a RegistryKey actually resolves
// to, including whether it is safe to run automatically. Reversible is
// declared once by this package's own (not yet implemented) registration
// code — nothing outside actionauth can populate one and have it mean
// anything, since there is no registry yet to look one up in.
type RegisteredAction struct {
	Key        string
	Reversible bool
}

// BoundAction is the ONLY value a future Executor may run. Its identity is
// unexported and NO CONSTRUCTOR EXISTS YET anywhere, including in this
// package — so only a zero-value (inert, resolves to nothing) BoundAction can
// be produced today, by anyone, including code in package research. The
// future ActionPolicy, implemented IN THIS PACKAGE, is the sole place a
// constructor will ever be added: it alone selects a BoundAction from a
// registry's AllowedActions(scope, state) for the current scope/state, taking
// an ActionID (or a research.ActionSuggestion carrying one) at most as
// advisory input to weigh — never as the value it binds.
//
// Critically, a BoundAction is not JUST an authorized ActionID: it also binds
// the scope and state fingerprint it was authorized FOR. Without this, a
// capability issued while the system was in "Scope X, State A" would remain a
// bare ActionID with no record of that context — and could then be replayed
// after the scope changed, or after the state moved to "State B", since
// nothing about the value itself would say it had gone stale. That is a
// stale-capability / cross-state-replay bug, not a hypothetical one: "the
// policy allowed this action when the state was A" must never silently become
// "this action may run no matter the current state". ValidFor is how a future
// Executor is required to re-verify this immediately before running the
// action — never trusting that a BoundAction obtained earlier is still good.
// The v1 registry (once implemented) is IMMUTABLE for the lifetime of a
// process — no hot reload. This is a deliberate scope decision, not an
// oversight: a revision-tagged capability (so a stale binding can't resolve to
// a *different* action after a hot-reloaded registry changes what a
// RegistryKey means) is real future work, but ValidFor below does not check
// one, and a field that isn't checked would be worse than no field at all — it
// would look like protection that isn't actually enforced. If the registry
// ever needs to support revisions, ValidFor's signature must grow a revision
// parameter AT THAT TIME, not before.
type BoundAction struct {
	id ActionID
	// scopeHash and authorizedStateHash are the ExplorationScope.Hash() and
	// StateFingerprint.StateFingerprintHash() the future ActionPolicy observed
	// at the moment of binding.
	scopeHash           string
	authorizedStateHash string
}

// ID returns the action identity this capability was bound to. Safe to expose:
// an ActionID alone grants nothing (see ActionID's doc); the authorization proof
// is ValidFor, not the identity.
func (a BoundAction) ID() ActionID { return a.id }

// ValidFor reports whether this BoundAction was authorized for EXACTLY this
// scope and state fingerprint. A future Executor MUST call this immediately
// before running the action and refuse to execute if it returns false: an
// action authorized when the state was `authorizedStateHash` does not remain
// valid once the state has moved on, or the scope has changed, even though the
// BoundAction value itself still exists and could otherwise be replayed. On the
// current zero-value BoundAction (no constructor exists yet) this always
// returns false, since there is nothing to match.
func (a BoundAction) ValidFor(scopeHash, stateFingerprintHash string) bool {
	return a.scopeHash != "" && a.scopeHash == scopeHash &&
		a.authorizedStateHash != "" && a.authorizedStateHash == stateFingerprintHash
}

// RecoveryPlanRef references a registered recovery procedure — advisory,
// exactly like ActionID; it grants nothing by itself.
type RecoveryPlanRef struct {
	RegistryKey string
}

// BoundRecovery is the ONLY value a future Executor may run to recover state —
// the recovery analogue of BoundAction, with the identical guarantee, bound to
// the scope it was authorized for (so a recovery capability issued in one
// ExplorationScope can never be replayed against a different one) and to the
// baseline fingerprint it is meant to restore (so a caller can cross-check it
// against the RecoveryPlan.Baseline it is about to use).
type BoundRecovery struct {
	ref                     RecoveryPlanRef
	scopeHash               string
	baselineFingerprintHash string
}

// Ref returns the recovery identity this capability was bound to. Safe to
// expose, for the same reason ActionID is.
func (r BoundRecovery) Ref() RecoveryPlanRef { return r.ref }

// BaselineFingerprintHash returns the fingerprint hash this recovery is
// authorized to restore to.
func (r BoundRecovery) BaselineFingerprintHash() string { return r.baselineFingerprintHash }

// ValidFor reports whether this BoundRecovery was authorized for exactly this
// scope. A future Executor must call this before running the recovery.
func (r BoundRecovery) ValidFor(scopeHash string) bool {
	return r.scopeHash != "" && r.scopeHash == scopeHash
}
