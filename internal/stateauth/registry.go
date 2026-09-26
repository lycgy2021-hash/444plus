package stateauth

import (
	"errors"
	"fmt"
)

// registry is a compile-time-only, closed set of registered StateProjector
// implementations. It is entirely UNEXPORTED — the only way any other
// package can ever reach one is through a BoundRegistry (below), which also
// fixes WHICH single ProjectorID that package is authorized to use. There is
// no way, from outside this package, to pair an arbitrary ProjectorID with
// an arbitrary registry — see BoundRegistry's own doc for why that matters.
type registry struct {
	projectors map[ProjectorID]StateProjector
}

// newRegistry builds a closed registry from a fixed list of projectors —
// only code inside this package can ever call it, and today, only
// FixtureRegistry (and, in the future, other named profile constructors)
// does, with this package's own concrete projectors.
func newRegistry(projectors ...StateProjector) *registry {
	m := make(map[ProjectorID]StateProjector, len(projectors))
	for _, p := range projectors {
		m[p.ID()] = p
	}
	return &registry{projectors: m}
}

// project runs the registered projector for id against a. It is
// unexported: only BoundRegistry.Project may call it, and only with the ONE
// id that BoundRegistry itself was built with — never a caller-supplied one.
func (r *registry) project(id ProjectorID, a StateArtifact) (Fingerprint, error) {
	if r == nil {
		return Fingerprint{}, errors.New("stateauth: nil registry")
	}
	p, ok := r.projectors[id]
	if !ok {
		return Fingerprint{}, fmt.Errorf("stateauth: no projector registered for %q", id)
	}
	return p.Project(a)
}

// BoundRegistry pairs a registry with the ONE ProjectorID a given profile is
// authorized to use. A caller (research.Explorer) holds a *BoundRegistry —
// never a bare ProjectorID string, and never the underlying registry type at
// all — so it has no way to ask for a DIFFERENT projector than the one its
// profile was built with, and no way to pair a projector from one profile
// with a registry from another.
//
// The gap this closes: even after moving projector implementations behind
// an unexported constructor (which stops external fake/replay injection —
// see StateProjector's own doc), an Explorer that held a *registry PLUS a
// caller-supplied ProjectorID could still let its caller choose WHICH
// registered projector interprets the same raw evidence — the
// state-authority analogue of the "caller picks ActionID" bypass S10-E1
// closed for actions. If a registry ever holds both a minimal fixture
// projector and a real protocol-specific one, a caller choosing the weaker
// one could turn "authoritative state" into "whichever state semantics the
// caller finds convenient" — e.g. mapping {"authenticated":"false"} and
// {"authenticated":"true"} onto the identical Fingerprint via a length-only
// projector, while a real HTTP-state projector would have told them apart.
// BoundRegistry removes that choice entirely: a profile is built ONCE,
// inside this package, naming both the registry and the projector together
// — see FixtureRegistry's own doc — and nothing outside this package can
// construct one with different contents.
type BoundRegistry struct {
	registry *registry
	id       ProjectorID
}

// Project runs this BoundRegistry's one fixed projector against a. There is
// no parameter through which a caller could ask it to use a different one.
func (b *BoundRegistry) Project(a StateArtifact) (Fingerprint, error) {
	if b == nil {
		return Fingerprint{}, errors.New("stateauth: nil BoundRegistry")
	}
	return b.registry.project(b.id, a)
}

// FixtureRegistry returns a BoundRegistry using RawLenProjector — explicitly
// a TEST/FIXTURE profile, never a real security-research state model (see
// RawLenProjector's own doc: two responses of identical length can differ
// completely, e.g. an admin=false/admin=true flip). It exists so research's
// own tests (and future fixture-backed integration tests) have something to
// construct an Explorer with, WITHOUT this package ever offering a
// generically named "default" that production code might reach for out of
// habit — there is deliberately no DefaultRegistry(). A future real profile
// (e.g. for an HTTP target) gets its own equally explicit, equally named
// constructor here, built the same way — never a parameter a caller fills
// in.
func FixtureRegistry() *BoundRegistry {
	return &BoundRegistry{registry: newRegistry(RawLenProjector{}), id: RawLenProjector{}.ID()}
}
