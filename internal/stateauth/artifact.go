// Package stateauth is the S10 STATE AUTHORITY BOUNDARY — still contract
// only. No registry, no concrete StateProjector implementation, and no
// Explorer glue exists here or anywhere else yet. It exists as its OWN
// PACKAGE, separate from research, for exactly the reason internal/actionauth
// exists as its own package for BoundAction/BoundRecovery: an unexported
// field (or an unexported constructor) on a type living IN package research
// only stops OTHER packages from forging it — it does nothing to stop code
// added LATER to research ITSELF (a future Explorer, AI-glue code, a
// candidate producer) from calling that same unexported constructor, since Go
// visibility is package-scoped, not file-scoped. Moving Fingerprint here means
// research (and everything it will ever contain) can only ever see the OPAQUE
// Fingerprint type below — it has no way, from any file it will ever contain,
// to construct one describing real state, because the identity-bearing
// constructor is unexported HERE, in a package research does not control.
//
// This closes the one residual caveat the previous (research-internal)
// version of this contract had to document honestly: "unexported only fully
// stops OTHER packages; a future file added to research itself could still
// call newStateFingerprint directly." That caveat no longer applies to
// Fingerprint — the same way it never applied to actionauth.BoundAction. Both
// authority boundaries are now enforced at the same level: by the Go
// compiler, across a real package boundary, not by review discipline alone.
package stateauth

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashBytes is the same "byte-for-byte SHA-256 of the raw input" discipline as
// research.RawInputHash (S2's frozen Provenance contract). It is duplicated
// here rather than imported: research depends on this package, so importing
// research from here would be circular.
func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ProjectorID identifies a registered StateProjector.
type ProjectorID string

// StateArtifact is the raw, scope-tagged state observation a StateProjector
// consumes. It is RAW material, before any canonicalization — never itself a
// Fingerprint, and never a substitute for one.
type StateArtifact struct {
	ScopeHash string
	Raw       []byte
}
