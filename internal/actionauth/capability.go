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
type BoundAction struct {
	id ActionID
}

// RecoveryPlanRef references a registered recovery procedure — advisory,
// exactly like ActionID; it grants nothing by itself.
type RecoveryPlanRef struct {
	RegistryKey string
}

// BoundRecovery is the ONLY value a future Executor may run to recover state —
// the recovery analogue of BoundAction, with the identical guarantee.
type BoundRecovery struct {
	ref RecoveryPlanRef
}
