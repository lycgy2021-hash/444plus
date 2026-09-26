package actionauth

// Registry is a compile-time-only, closed set of registered actions — the
// S10 analogue of research.Registry (S5's Validator registry): built once,
// from a fixed list, with no method to add an entry afterward. Combined with
// BoundAction's own doc (the v1 registry is immutable for the lifetime of a
// process — no hot reload), a Registry value, once constructed, never changes
// what any RegistryKey means for as long as it exists.
type Registry struct {
	actions map[string]RegisteredAction
}

// NewRegistry builds a closed registry from a fixed list of actions. Later
// calls cannot add to it — there is no exported method that does, on
// purpose: dynamic registration would let anything holding a *Registry grow
// what it authorizes at runtime, which is exactly the "authority that isn't
// pinned down in the type/construction itself" this package exists to avoid.
func NewRegistry(actions ...RegisteredAction) *Registry {
	m := make(map[string]RegisteredAction, len(actions))
	for _, a := range actions {
		m[a.Key] = a
	}
	return &Registry{actions: m}
}

func (r *Registry) lookup(key string) (RegisteredAction, bool) {
	if r == nil {
		return RegisteredAction{}, false
	}
	a, ok := r.actions[key]
	return a, ok
}

// RecoveryRegistry is the recovery analogue of Registry: a closed, fixed set
// of registered recovery procedure keys. It carries no Reversible-style
// metadata of its own — a recovery IS the reversal, not a thing that has one.
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
// with a real (non-zero) identity. This is the "future ActionPolicy" every
// doc comment in this package and in research/state_machine.go has been
// pointing at since S10's contract was first drafted.
//
// ActionPolicy is deliberately NOT a judgment about which action is
// "correct" or "safe" to run in a given state — v1 has no state-dependent
// selection logic. What it enforces is narrower and non-negotiable: (1) the
// requested action/recovery is a REGISTERED one, from the fixed set given at
// construction, and (2) the resulting capability is stamped to EXACTLY the
// scope and state hash the caller observed at the moment of the call — never
// to a scope/state the caller merely claims. An ActionID or RecoveryPlanRef
// may come from anywhere, including an AI-authored research.ActionSuggestion
// (boundary 2 of the S10 contract) — that never matters here, because
// holding one never implies Bind/BindRecovery will succeed, and the bind
// call itself — never the identity it was asked to bind — is what produces a
// credential.
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

// Bind returns a BoundAction authorizing id, stamped to scopeHash and
// stateFingerprintHash, if and only if id.RegistryKey is registered and both
// hashes are non-empty. A caller (a future Explorer) MUST pass the scope and
// state hash it just actually observed — never a cached or assumed one — or
// the resulting capability's ValidFor check (boundary 4) would be validating
// against the wrong facts from the moment of construction.
func (p *ActionPolicy) Bind(id ActionID, scopeHash, stateFingerprintHash string) (BoundAction, bool) {
	if p == nil || scopeHash == "" || stateFingerprintHash == "" {
		return BoundAction{}, false
	}
	if _, ok := p.registry.lookup(id.RegistryKey); !ok {
		return BoundAction{}, false
	}
	return BoundAction{id: id, scopeHash: scopeHash, authorizedStateHash: stateFingerprintHash}, true
}

// BindRecovery is Bind's recovery analogue: it returns a BoundRecovery
// authorizing ref, stamped to scopeHash and the baseline fingerprint hash the
// recovery is meant to restore, if and only if ref.RegistryKey is registered
// and both are non-empty.
func (p *ActionPolicy) BindRecovery(ref RecoveryPlanRef, scopeHash, baselineFingerprintHash string) (BoundRecovery, bool) {
	if p == nil || scopeHash == "" || baselineFingerprintHash == "" {
		return BoundRecovery{}, false
	}
	if !p.recoveryRegistry.has(ref.RegistryKey) {
		return BoundRecovery{}, false
	}
	return BoundRecovery{ref: ref, scopeHash: scopeHash, baselineFingerprintHash: baselineFingerprintHash}, true
}
