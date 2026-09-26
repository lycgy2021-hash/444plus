package actionauth

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"gopoc/internal/stateauth"
)

// StateRequirements is a DECLARATIVE, purely-data description of which
// states a registered action applies to — deliberately not a callback. An
// earlier version of this file used `Supports func(stateauth.Fingerprint)
// bool`: from the type system's point of view that looked like a
// deterministic predicate, but a Go closure can read the wall clock, a
// global, an environment variable, a feature flag, a random source, or do
// I/O — nothing in the type stops it, so "Registered != Allowed" would still
// have rested on an arbitrary function body rather than on something that
// can be read and matched. StateRequirements has no such escape hatch: it is
// plain data, matched by matches (below) with a pure struct comparison — no
// callback, no hidden input, nothing to audit beyond the struct's own
// fields.
//
// ProjectorID pins WHICH state semantics this requirement is written
// against — required, and matched exactly against
// stateauth.Fingerprint.ProjectorID(). Different StateProjector
// implementations may produce similarly-shaped Facts for entirely different
// meanings; without pinning ProjectorID, a Registration could accidentally
// (or be crafted to) match a state it was never actually written for. Facts
// lists the exact key/value pairs a Fingerprint's own Facts() must contain
// (a subset match: any fact NOT listed here is a "don't care" — Facts being
// empty means "any facts, as long as the ProjectorID matches").
type StateRequirements struct {
	ProjectorID stateauth.ProjectorID
	Facts       map[string]string
}

// matches reports whether fp satisfies req: fp must have been produced by
// EXACTLY the ProjectorID req names, and every key/value pair in req.Facts
// must be present, with an exact value match, in fp.Facts(). A zero-value
// StateRequirements (empty ProjectorID) matches NOTHING — fail-closed, never
// fail-open by silently treating an unset requirement as "matches anything".
func matches(req StateRequirements, fp stateauth.Fingerprint) bool {
	if req.ProjectorID == "" {
		return false
	}
	if fp.ProjectorID() != req.ProjectorID {
		return false
	}
	facts := fp.Facts()
	for k, want := range req.Facts {
		if got, ok := facts[k]; !ok || got != want {
			return false
		}
	}
	return true
}

// Registration pairs a RegisteredAction with the declarative
// StateRequirements that decide whether it applies to a given authoritative
// state. This is Go DATA written by whoever builds the registry — never a
// callback — so "does this action apply here" can never come from an AI
// proposal, a candidate, or any other caller-supplied value, and can never
// depend on anything outside the Fingerprint being matched. This is what
// makes "Registered != Allowed" real rather than a slogan: being in the
// registry only means the key exists; Requirements is what makes it
// APPLICABLE to a specific stateauth.Fingerprint.
type Registration struct {
	Action       RegisteredAction
	Requirements StateRequirements
}

// Registry is a compile-time-only, closed set of registered actions, each
// with its own declarative applicability requirement — the S10 analogue of
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
// avoid. A Registration with a zero-value Requirements (no ProjectorID)
// matches nothing — fail-closed, never fail-open.
//
// Every Registration is rebuilt here field-by-field, and Requirements.Facts
// is deep-copied into a fresh map — never stored by the caller's own
// reference. Without this, "the registry is immutable" would be true only
// of the Registry TYPE (no add/remove method) while a caller holding the
// original StateRequirements.Facts map (or the regs slice passed in) could
// still mutate it after construction and silently change what
// ActionPolicy.Select considers applicable — an "immutable registry" that
// can still be edited through a live reference is not actually immutable.
// Mutating the caller's own copies after this call has NO effect on
// anything Select ever returns.
func NewRegistry(regs ...Registration) *Registry {
	m := make(map[string]Registration, len(regs))
	for _, r := range regs {
		m[r.Action.Key] = Registration{
			Action: r.Action,
			Requirements: StateRequirements{
				ProjectorID: r.Requirements.ProjectorID,
				Facts:       copyFacts(r.Requirements.Facts),
			},
		}
	}
	return &Registry{entries: m}
}

// copyFacts returns a fresh map with the same contents as facts, severing
// any reference back to the caller's original map. A nil input stays nil
// (a Registration with no Facts constraints means "any facts", not "an
// empty map of constraints" — the distinction matches's own doc explains).
func copyFacts(facts map[string]string) map[string]string {
	if facts == nil {
		return nil
	}
	copied := make(map[string]string, len(facts))
	for k, v := range facts {
		copied[k] = v
	}
	return copied
}

// applicable returns the RegistryKeys whose Requirements match(es) fp, in a
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
		if matches(reg.Requirements, fp) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// canonicalHash is a pure, deterministic identity for r's own immutable
// content — every registered action's Key, its Safety, and its
// Requirements (ProjectorID plus every Facts key/value, sorted), in a
// fixed canonical order. Two Registry values built from identically-shaped
// registration lists always hash the same; any change to what is
// registered, its safety class, or its requirements changes it. This is
// what ActionPolicy.PolicyID exposes — see that method's own doc for why
// it exists.
func (r *Registry) canonicalHash() string {
	if r == nil {
		return ""
	}
	keys := make([]string, 0, len(r.entries))
	for k := range r.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		reg := r.entries[k]
		b.WriteString("action=" + k + "\n")
		b.WriteString("safety=" + string(reg.Action.Safety) + "\n")
		b.WriteString("projector=" + string(reg.Requirements.ProjectorID) + "\n")
		factKeys := make([]string, 0, len(reg.Requirements.Facts))
		for fk := range reg.Requirements.Facts {
			factKeys = append(factKeys, fk)
		}
		sort.Strings(factKeys)
		for _, fk := range factKeys {
			b.WriteString("fact:" + fk + "=" + reg.Requirements.Facts[fk] + "\n")
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
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
// with a real (non-zero) identity — AND the SOLE decision-maker for WHICH
// action runs. There is no Bind(id)-style entry point that lets a caller (a
// human, a research.Explorer, or indirectly an AI-authored
// research.ActionSuggestion) NAME the action to run and have that name
// alone produce a credential: Select (below) itself walks the registry's
// applicable, deterministically sorted candidates for the caller's current
// Fingerprint — matched by pure declarative StateRequirements comparison,
// never a callback — and picks the first one not already excluded. The same
// (scope, state, registry, exclude set) therefore always selects the same
// action. A caller supplies FACTS (the current scope, the current
// authoritative state, which action keys have already been tried from this
// exact state) — never a decision. v1 deliberately does not wire any
// AI-authored suggestion into Select at all, even as a tie-breaking hint —
// the cleanest way to keep AI strictly out of action selection.
type ActionPolicy struct {
	registry         *Registry
	recoveryRegistry *RecoveryRegistry
	// policyID is computed once, at construction, from registry's own
	// canonicalHash — see PolicyID's own doc.
	policyID string
}

// NewActionPolicy constructs a policy backed by a fixed action registry and a
// fixed recovery registry. Both are already closed by the time they arrive
// here (Registry/RecoveryRegistry have no way to grow after construction);
// ActionPolicy adds no further mutability of its own.
func NewActionPolicy(registry *Registry, recoveryRegistry *RecoveryRegistry) *ActionPolicy {
	return &ActionPolicy{registry: registry, recoveryRegistry: recoveryRegistry, policyID: registry.canonicalHash()}
}

// PolicyID returns a deterministic identity for THIS policy's own action
// registry content (every registered action's Key/Safety/StateRequirements
// — never the recovery registry, which is orthogonal to "what may execute
// and how safely"). It exists so a caller holding a BoundAction produced by
// SOME ActionPolicy can prove it came from a policy with the SAME
// authorized content as another — e.g. S10/E7's replay validator proving
// its own configured ActionPolicy is the same one (by canonical content,
// not merely "someone wired the same pointer through") that authorized a
// Candidate's original action, rather than trusting "same ActionID" alone,
// which two DIFFERENT policies (one permissive, one strict) could still
// agree on by coincidence. Computed once, at construction; two policies
// built from identically-shaped registries always share a PolicyID.
func (p *ActionPolicy) PolicyID() string {
	if p == nil {
		return ""
	}
	return p.policyID
}

// Select deterministically picks exactly one registered action whose
// StateRequirements match fp AND whose key is not already in exclude, and
// returns it bound to scopeHash and fp's own StateFingerprintHash — stamped
// with that action's own registered Safety and this policy's own PolicyID,
// read directly from the matched Registration/Registry, never supplied by
// the caller. ok is false if no such action exists — either nothing in the
// registry matches this state, or everything that does has already been
// excluded (e.g. already tried from this exact state). The returned
// ActionID always carries an empty VariantID — v1 selects among registered
// actions only, never among a registered action's own parameter variants.
func (p *ActionPolicy) Select(scopeHash string, fp stateauth.Fingerprint, exclude map[string]bool) (BoundAction, bool) {
	stateFingerprintHash := fp.StateFingerprintHash()
	if p == nil || scopeHash == "" || stateFingerprintHash == "" {
		return BoundAction{}, false
	}
	for _, key := range p.registry.applicable(fp) {
		if exclude != nil && exclude[key] {
			continue
		}
		reg := p.registry.entries[key]
		return BoundAction{
			id:                  ActionID{RegistryKey: key},
			scopeHash:           scopeHash,
			authorizedStateHash: stateFingerprintHash,
			safety:              reg.Action.Safety,
			policyID:            p.policyID,
		}, true
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
