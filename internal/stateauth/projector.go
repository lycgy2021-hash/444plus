package stateauth

// StateProjector is the ONLY authoritative source of a Fingerprint's Facts —
// the state-authority analogue of a future ActionPolicy. Raw evidence
// (StateArtifact) becomes an authoritative Fingerprint only by passing
// through a registered, deterministic StateProjector — never by a caller
// directly asserting "these are the facts".
//
// A concrete implementation, once written, MUST live inside this package
// (see newFingerprint's doc for why: Project has to call newFingerprint,
// which is unexported here, so an implementation written anywhere else could
// satisfy this interface's method shape but could never return anything but
// the zero-value Fingerprint from its own Project method). This mirrors
// actionauth's own future ActionPolicy, which for the identical reason must
// be implemented inside actionauth despite needing scope/state knowledge that
// might otherwise seem to belong to a "higher" package.
//
// No concrete StateProjector exists yet — this is a contract-only interface.
// A registry of them (the analogue of a future action registry) is future
// work, alongside the ActionPolicy that will consume the fingerprints a
// StateProjector produces.
type StateProjector interface {
	ID() ProjectorID
	// Project deterministically derives a Fingerprint from a's raw bytes.
	// Two calls with byte-identical a.Raw must yield fingerprints whose
	// StateFingerprintHash is identical — determinism is the whole point: the
	// same underlying state must always project to the same fingerprint.
	Project(a StateArtifact) (Fingerprint, error)
}
