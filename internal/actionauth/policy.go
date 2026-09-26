package actionauth

import (
	"sort"

	"gopoc/internal/stateauth"
)

// Registration pairs a RegisteredAction with the deterministic, COMPILE-TIME
// applicability predicate that decides whether it applies to a given
// authoritative state. Supports is Go code written by whoever builds the
// registry — literal, compiled-in logic, never data — so "does this action
// apply here" can never come from an AI proposal, a candidate, or any other
// caller-supplied value. This is what makes "Registered != Allowed" real
// rather than a slogan: being in the registry only means the key exists;
// Supports is what makes it APPLICABLE to a specific stateauth.Fingerprint.
type Registration struct {
	Action   RegisteredAction
	Supports func(stateauth.Fingerprint) bool
}

// Registry is a compile-time-only, closed set of registered actions, each
// with its own deterministic applicability predicate — the S10 analogue of
// research.Registry (S5's Validator registry): built once, from a fixed
// list, with no method to add an entry afterward. Combined with
// BoundAction's own doc (the v1 registry is immutable for the lifetime of a
// process — no hot reload), a Registry value, once constructed, never
// changes what any RegistryKey means, or what it applies to, for as long as
// it exists.
type Registry struct {
	entries map[string]Registration
}

// NewRegistry builds a closed registry from a fixed list of registrations.
// Later calls cannot add to it — there is no exported method that does, on
// purpose: dynamic registration would let anything holding a *Registry grow
// what it authorizes at runtime, which is exactly the "authority that isn't
// pinned down in the type/construction itself" this package exists to
// avoid. A Registration with a nil Supports is treated as supporting
// NOTHING — fail-closed, never fail-open by silently defaulting to "always
// applicable".
func NewRegistry(regs ...Registration) *Registry {
	m := make(map[string]Registration, len(regs))
	for _, r := range regs {
		if r.Supports == nil {
			r.Supports = func(stateauth.Fingerprint) bool { return false }
		}
		m[r.Action.Key] = r
	}
	return &Registry{entries: m}
}

// applicable returns the RegistryKeys whose Supports(fp) is true, in a
// FIXED, deterministic order (lexically sorted) — so the same (registry, fp)
// always produces the same candidate list, in the same order, for
// ActionPolicy.Select to walk. This is never exposed directly: only Select
// (below) may turn one of these keys into a credential.
func (r *Registry) applicable(fp stateauth.Fingerprint) []string {
	if r == nil {
		return nil
	}
	keys := make([]string, 0, len(r.entries))
	for key, reg := range r.entries {
		if reg.Supports(fp) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// RecoveryRegistry is the recovery analogue of Registry: a closed, fixed set
// of registered recovery procedure keys. It carries no Reversible-style
// metadata of its own — a recovery IS the reversal, not a thing that has one
// — and, unlike Registry, has no state-dependent applicability: a recovery's
// job is always "restore the baseline", never "pick a recovery for this
// state".
type RecoveryRegistry struct {
	keys map[string]struct{}
}

// NewRecoveryRegistry builds a closed registry from a fixed list of recovery
// keys, exactly like NewRegistry.
func NewRecoveryRegistry(keys ...string) *RecoveryRegistry {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return &RecoveryRegistry{keys: m}
}

func (r *RecoveryRegistry) has(key string) bool {
	if r == nil {
		return false
	}
	_, ok := r.keys[key]
	return ok
}

// ActionPolicy is the SOLE constructor for BoundAction and BoundRecovery —
// the only place, in this package or any package, either type is ever built
// with a real (non-zero) identity — AND, critically, the SOLE decision-maker
// for WHICH action runs. There is no Bind(id)-style entry point that lets a
// caller (a human, a research.Explorer, or indirectly an AI-authored
// research.ActionSuggestion) NAME the action to run and have that name
// alone produce a credential: Select (below) itself walks the registry's
// applicable, deterministically sorted candidates for the caller's current
// Fingerprint and picks the first one not already excluded. The same
// (scope, state, registry, exclude set) therefore always selects the same
// action — this is what "ActionPolicy = Action Authority" means in
// practice, not just in a doc comment. A caller supplies FACTS (the current
// scope, the current authoritative state, which action keys have already
// been tried from this exact state) — never a decision. v1 deliberately does
// not wire any AI-authored suggestion into Select at all, even as a
// tie-breaking hint — the cleanest way to keep AI strictly out of action
// selection.
type ActionPolicy struct {
	registry         *Registry
	recoveryRegistry *RecoveryRegistry
}

// NewActionPolicy constructs a policy backed by a fixed action registry and a
// fixed recovery registry. Both are already closed by the time they arrive
// here (Registry/RecoveryRegistry have no way to grow after construction);
// ActionPolicy adds no further mutability of its own.
func NewActionPolicy(registry *Registry, recoveryRegistry *RecoveryRegistry) *ActionPolicy {
	return &ActionPolicy{registry: registry, recoveryRegistry: recoveryRegistry}
}

// Select deterministically picks exactly one registered action that is BOTH
// applicable to fp (per the registry's own compiled-in Supports predicates)
// AND not already a key in exclude, and returns it bound to scopeHash and
// fp's own StateFingerprintHash. ok is false if no such action exists —
// either nothing in the registry supports this state, or everything that
// does has already been excluded (e.g. already tried from this exact
// state). The returned ActionID always carries an empty VariantID — v1
// selects among registered actions only, never among a registered action's
// own parameter variants.
func (p *ActionPolicy) Select(scopeHash string, fp stateauth.Fingerprint, exclude map[string]bool) (BoundAction, bool) {
	stateFingerprintHash := fp.StateFingerprintHash()
	if p == nil || scopeHash == "" || stateFingerprintHash == "" {
		return BoundAction{}, false
	}
	for _, key := range p.registry.applicable(fp) {
		if exclude != nil && exclude[key] {
			continue
		}
		return BoundAction{id: ActionID{RegistryKey: key}, scopeHash: scopeHash, authorizedStateHash: stateFingerprintHash}, true
	}
	return BoundAction{}, false
}

// BindRecovery returns a BoundRecovery authorizing ref, stamped to scopeHash
// and the baseline fingerprint hash the recovery is meant to restore, if and
// only if ref.RegistryKey is registered and both are non-empty. Unlike
// Select, this remains a direct lookup rather than a state-dependent
// decision: recovery has no "which one applies to this state" question in
// v1 — a recovery plan names, once, the single registered way back to
// baseline, and BindRecovery only proves that name is real.
func (p *ActionPolicy) BindRecovery(ref RecoveryPlanRef, scopeHash, baselineFingerprintHash string) (BoundRecovery, bool) {
	if p == nil || scopeHash == "" || baselineFingerprintHash == "" {
		return BoundRecovery{}, false
	}
	if !p.recoveryRegistry.has(ref.RegistryKey) {
		return BoundRecovery{}, false
	}
	return BoundRecovery{ref: ref, scopeHash: scopeHash, baselineFingerprintHash: baselineFingerprintHash}, true
}
