package stateauth

import "strconv"

// RawLenProjector is the first CONCRETE StateProjector — deliberately
// minimal and generic: its only projected fact is "raw_len", the decimal
// length of the raw artifact bytes. It exists to prove the StateProjector
// contract end-to-end (something a research.Explorer can actually call), not
// to model any real protocol's state. It lives here, inside stateauth, not in
// research, for exactly the reason StateProjector's own doc requires: its
// Project method must call newFingerprint, which is unexported to this
// package.
//
// A real, protocol-specific projector (HTTP session state, a gRPC health
// check, an application's own status endpoint) is future work, and per the
// same doc, must also be implemented inside this package.
type RawLenProjector struct{}

// ID identifies this projector.
func (RawLenProjector) ID() ProjectorID { return "rawlen-v1" }

// Project deterministically derives a Fingerprint whose only fact is the raw
// byte length. Identical raw bytes always yield an identical
// StateFingerprintHash; any change in length changes it.
func (p RawLenProjector) Project(a StateArtifact) (Fingerprint, error) {
	return newFingerprint(a.ScopeHash, a.Raw, p.ID(), map[string]string{
		"raw_len": strconv.Itoa(len(a.Raw)),
	}), nil
}
