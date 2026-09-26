package stateauth

import (
	"sort"
	"strings"
)

// Fingerprint is the ONLY authoritative description of collected state — the
// state-authority analogue of actionauth.BoundAction. It separates raw
// collected evidence from denoised identity (RawStateArtifactHash vs
// StateFingerprintHash — the S8/S9 hash discipline again), carries its own
// ScopeHash so it is self-describing wherever it travels (disk, replay, a
// different worker), and records WHICH registered ProjectorID produced it, so
// evidence can always answer "who projected this state".
//
// A Fingerprint is immutable (all fields unexported; Facts returns a copy),
// internally consistent (its hashes are always computed from its own raw
// bytes/facts by newFingerprint, never accepted as separate caller-supplied
// values — see newFingerprint's doc), AND — the reason this type lives in its
// own package rather than in research — AUTHORITATIVE: nothing outside this
// package can construct a non-zero Fingerprint, full stop. That is strictly
// stronger than "review discipline can catch it": a Go compiler error, not a
// reviewer's attention, is what stops a future research file, AI-glue file,
// candidate producer, or Explorer from writing `Fingerprint{scopeHash: ...}`
// or calling `newFingerprint(...)` — those identifiers are simply not visible
// outside this package.
type Fingerprint struct {
	scopeHash            string
	rawStateArtifactHash string
	stateFingerprintHash string
	projectorID          ProjectorID
	facts                map[string]string
}

// newFingerprint constructs an immutable, internally-consistent, and (by
// virtue of living in this package) authoritative Fingerprint. rawArtifact is
// the actual raw state artifact bytes (hashed here, never accepted as a
// pre-computed hash string); facts is the canonical projection of that
// artifact used for state-equality (copied, then hashed here via a
// deterministic, map-order-independent canonicalization — see
// canonicalFactsHash).
//
// This function is UNEXPORTED and is the ONLY place a Fingerprint is ever
// built, in any package. Today nothing calls it — no concrete StateProjector
// exists yet — so no code anywhere can currently obtain a Fingerprint
// claiming to describe real collected state. Once a concrete StateProjector
// is written, it MUST live inside this package, never in research, for
// exactly the reason a future ActionPolicy must live inside actionauth rather
// than research: only code inside this package can call newFingerprint, so a
// type implementing StateProjector anywhere else could satisfy the
// interface's method signatures but could only ever return the zero-value
// Fingerprint from its own Project method — never one describing real state.
// A projector's need for target/protocol-specific collection logic does not
// change that; the same tension exists for actionauth's future ActionPolicy
// (which also needs scope/state-specific knowledge) and is resolved the same
// way there.
func newFingerprint(scopeHash string, rawArtifact []byte, projectorID ProjectorID, facts map[string]string) Fingerprint {
	copied := make(map[string]string, len(facts))
	for k, v := range facts {
		copied[k] = v
	}
	return Fingerprint{
		scopeHash:            scopeHash,
		rawStateArtifactHash: hashBytes(rawArtifact),
		stateFingerprintHash: canonicalFactsHash(copied),
		projectorID:          projectorID,
		facts:                copied,
	}
}

// canonicalFactsHash deterministically hashes a facts map: keys sorted (Go
// maps have no defined order, so sorting is lossless — the same discipline as
// S9's caseArtifactHash header-key sorting), joined canonically, then hashed.
// The same facts always hash the same regardless of map iteration order; a
// single changed value always changes the hash.
func canonicalFactsHash(facts map[string]string) string {
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(facts[k])
		b.WriteString("\n")
	}
	return hashBytes([]byte(b.String()))
}

func (f Fingerprint) ScopeHash() string            { return f.scopeHash }
func (f Fingerprint) RawStateArtifactHash() string { return f.rawStateArtifactHash }
func (f Fingerprint) StateFingerprintHash() string { return f.stateFingerprintHash }
func (f Fingerprint) ProjectorID() ProjectorID     { return f.projectorID }

// Facts returns a copy of the facts this fingerprint was computed over — for
// provenance/debugging, never raw bytes, and never a handle the caller could
// use to mutate the fingerprint's own internal state.
func (f Fingerprint) Facts() map[string]string {
	copied := make(map[string]string, len(f.facts))
	for k, v := range f.facts {
		copied[k] = v
	}
	return copied
}

// RecoveryOutcome is FACTS ONLY — there is no Verified/conclusion field a
// recovery implementation could simply set to true. It holds the FULL
// Baseline/Result Fingerprint values (not bare hash strings) so Recovered can
// prove "same scope AND same state", not merely "two strings happened to
// match". It lives here, beside Fingerprint, because recovery verification is
// fundamentally a state-authority question — it never touches an
// actionauth.BoundAction.
type RecoveryOutcome struct {
	ScopeHash    string
	Baseline     Fingerprint
	Result       Fingerprint
	EvidenceRefs []string
}

// Recovered is the ONLY thing that may declare a recovery successful, and it
// is a pure function of recorded facts, never a stored, independently
// settable field. It requires BOTH fingerprints to actually belong to the
// outcome's own declared scope AND to share a (non-empty) StateFingerprintHash
// — proving same scope and same state, not a coincidental string match
// between two fingerprints that could, after crossing a disk/replay/worker
// boundary, have come from different scopes entirely. v1's rule is exact
// match against baseline; if a future version ever allows
// semantically-equivalent-but-not-identical recovery, that must be decided by
// a registered comparison rule authorized through research's
// ExpectationSource (S9) — never by loosening this function ad hoc.
// Recovered==false means exploration STOPS; it is never continued on the
// assumption that a rollback worked.
func Recovered(o RecoveryOutcome) bool {
	return o.ScopeHash != "" &&
		o.Baseline.ScopeHash() == o.ScopeHash &&
		o.Result.ScopeHash() == o.ScopeHash &&
		o.Baseline.StateFingerprintHash() != "" &&
		o.Baseline.StateFingerprintHash() == o.Result.StateFingerprintHash()
}
