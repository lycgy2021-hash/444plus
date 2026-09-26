package stateauth

import (
	"errors"
	"fmt"
)

// Registry is a compile-time-only, closed set of registered StateProjector
// implementations — the state-authority analogue of actionauth.Registry.
// Unlike actionauth.Registry (which legitimately accepts caller-supplied
// RegisteredAction/StateRequirements DATA — advisory, non-authoritative),
// this Registry's constructor is UNEXPORTED: the only StateProjector values
// it will ever hold are the concrete ones this package itself defines.
//
// The gap this closes: StateProjector being an exported interface means any
// package can write a type that satisfies its method signatures. Such a type
// can never call newFingerprint (unexported to this package), so it can
// never forge a Fingerprint out of nothing — but nothing stops it from
// CAPTURING and REPLAYING a Fingerprint obtained from a genuinely earlier,
// legitimate Project call, ignoring the StateArtifact it is actually asked
// to project on a later call:
//
//	type evilProjector struct{ cached Fingerprint }
//	func (p *evilProjector) Project(a StateArtifact) (Fingerprint, error) {
//		return p.cached, nil // ignores a entirely
//	}
//
// If research held a bare StateProjector value directly (as an earlier
// version of this package's Explorer integration did), that replay would be
// indistinguishable from a real, fresh projection: even Explorer's own
// "fresh-before" drift check (S10-E4d) would see a self-consistent
// Fingerprint and never suspect it was minted for different bytes — the
// state-authority analogue of the exact TOCTOU that fix closed for actions.
//
// Registry closes this the same way actionauth closes action selection:
// research (or any other package) holds a *Registry and a ProjectorID —
// never a StateProjector value directly — and DefaultRegistry (below) is the
// ONLY exported way to obtain one. Its projectors are always this package's
// own, referenced directly from Go code within this package; there is no
// exported constructor an external package could ever hand a fake or
// replaying projector to.
type Registry struct {
	projectors map[ProjectorID]StateProjector
}

// newRegistry is unexported: only code inside this package can ever build a
// Registry from arbitrary StateProjector values — and today, only
// DefaultRegistry does, with this package's own concrete projectors.
func newRegistry(projectors ...StateProjector) *Registry {
	m := make(map[ProjectorID]StateProjector, len(projectors))
	for _, p := range projectors {
		m[p.ID()] = p
	}
	return &Registry{projectors: m}
}

// DefaultRegistry returns the fixed set of projectors this package ships —
// today, only RawLenProjector. It is the ONLY exported way to obtain a
// *Registry: there is no exported constructor that accepts caller-supplied
// StateProjector values, so no external package can ever get a fake or
// replaying projector into a Registry an Explorer could reference.
func DefaultRegistry() *Registry {
	return newRegistry(RawLenProjector{})
}

// Project runs the registered projector for id against a — the ONLY way any
// other package can ever turn a StateArtifact into a Fingerprint. A caller
// holds a *Registry and a ProjectorID, never a StateProjector value.
func (r *Registry) Project(id ProjectorID, a StateArtifact) (Fingerprint, error) {
	if r == nil {
		return Fingerprint{}, errors.New("stateauth: nil registry")
	}
	p, ok := r.projectors[id]
	if !ok {
		return Fingerprint{}, fmt.Errorf("stateauth: no projector registered for %q", id)
	}
	return p.Project(a)
}
