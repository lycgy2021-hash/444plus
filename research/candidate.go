package research

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is a research candidate's position on its own ladder — deliberately
// separate from the detection plane's Verdict (not_found/detected/likely/
// confirmed). A candidate is a lead being worked, not a finding about a target,
// so the two vocabularies never mix and an AI-born lead can never appear as a
// detection verdict.
type State string

const (
	// Hypothesis is the ONLY state an AI-suggested candidate may enter at. It
	// means "worth a deterministic look", nothing more.
	Hypothesis State = "hypothesis"
	// Reproducible: a deterministic validator reproduced the behavior.
	Reproducible State = "reproducible"
	// ImpactConfirmed: a validator demonstrated security impact (safely).
	ImpactConfirmed State = "impact_confirmed"
	// VendorConfirmed: the vendor acknowledged it.
	VendorConfirmed State = "vendor_confirmed"
	// CVEAssigned: a CVE id was issued.
	CVEAssigned State = "cve_assigned"
)

// ladder is the fixed order; a candidate advances one rung at a time.
var ladder = []State{Hypothesis, Reproducible, ImpactConfirmed, VendorConfirmed, CVEAssigned}

func rung(s State) int {
	for i, v := range ladder {
		if v == s {
			return i
		}
	}
	return -1
}

// OriginKind names the producer that raised a candidate. The Research Plane is
// the core; a local LLM is only ONE producer among many. Making this an explicit
// kind keeps AI provenance visible and never mistaken for a validated fact, while
// leaving room for the non-AI producers (fuzz, diff, source audit, passive
// anomaly, a human researcher) that S6+ will add.
type OriginKind string

const (
	OriginAI           OriginKind = "ai"
	OriginFuzz         OriginKind = "fuzz"
	OriginDiff         OriginKind = "diff"
	OriginDifferential OriginKind = "differential"
	// OriginStateMachine (S10/E6): a candidate raised from an observed
	// StateTransition (a real Explorer session) that violated an explicit,
	// pre-declared, authoritative TransitionExpectation. This is a SOURCE
	// label, exactly like OriginDiff/OriginFuzz/OriginDifferential — never a
	// higher-confidence marker. "State A != State B" is never itself an
	// anomaly; only a transition that violates an ALREADY-AUTHORIZED
	// contract is.
	OriginStateMachine OriginKind = "state_machine"
	OriginSourceAudit  OriginKind = "source_audit"
	OriginPassive      OriginKind = "passive"
	OriginHuman        OriginKind = "human"
)

// Origin records where a candidate came from. Kind is the producer type; ID is
// that producer's identity (e.g. an ai.Provider name, a fuzzer id, a diff ref).
type Origin struct {
	Kind OriginKind `json:"kind"`
	ID   string     `json:"id,omitempty"`
}

// IsAI reports whether a (non-authoritative) model produced this candidate.
func (o Origin) IsAI() bool { return o.Kind == OriginAI }

// Transition is one recorded state advance, always attributed to the
// deterministic validator that made it and the evidence that justified it.
type Transition struct {
	From         State     `json:"from"`
	To           State     `json:"to"`
	At           time.Time `json:"at"`
	By           string    `json:"by"`
	EvidenceRefs []string  `json:"evidence_refs"`
}

// Candidate is a research lead. It can be born only at Hypothesis (see
// NewHypothesis) and advanced only via Promote by a named validator with
// evidence — there is no method anywhere that turns a Candidate into a detection
// Verdict, and none that lets a Provider raise its state.
type Candidate struct {
	ID               string        `json:"id"`
	Type             string        `json:"candidate_type"`
	Title            string        `json:"title"`
	Target           string        `json:"target,omitempty"`
	Rationale        string        `json:"rationale,omitempty"`
	State            State         `json:"state"`
	Origin           Origin        `json:"origin"`
	RequiredEvidence []string      `json:"required_evidence,omitempty"`
	Evidence         []Observation `json:"evidence,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
	// Refs are producer-specific structured references (not free text), so a
	// candidate can be queried/aggregated/correlated without parsing the rationale
	// — e.g. a fuzz candidate carries scope_hash/signature_hash/group_hash/count.
	// They are descriptive metadata for humans, never authority: Refs is an
	// ordinary, exported, MUTABLE map — any caller holding *Candidate can rewrite
	// it after construction. Nothing may gate a decision on it. S10/E7's replay
	// validator specifically must not (see stateMachineBinding below for the
	// authoritative alternative it actually uses).
	Refs    map[string]string `json:"refs,omitempty"`
	History []Transition      `json:"history,omitempty"`

	// provenance is the immutable origin record set once at birth: which producer,
	// which exact raw input (RawInputHash). It is unexported so no other package
	// can rewrite where a candidate came from; read it via Provenance() (a copy)
	// and it is included in JSON through MarshalJSON. Combined with History
	// (append-only, each step naming its validator + content-hashed evidence), it
	// gives the full, tamper-evident lineage of any conclusion.
	provenance Provenance

	// stateMachineBinding is S10/E6's own immutable, tamper-proof identity for a
	// state-machine Candidate — set ONLY by StateMachineProducer.Produce (this
	// package's own S10/E6 code; there is no exported setter), never nil-checked
	// or reachable from any other producer or external caller. Unlike Refs, a
	// caller cannot rewrite it: StateMachineBinding() returns a VALUE COPY of an
	// already-immutable, pointer/slice/map-free value type, so nothing the
	// caller does with the copy can affect this Candidate's own identity. This
	// exists specifically because S10/E7's replay validator must resolve WHICH
	// rule/action/projector/target to replay from something a caller cannot have
	// silently swapped out after E6 produced it — trusting the mutable Refs map
	// for that would let a caller retarget a replay to a different (still
	// trusted) rule after the fact. nil for every Candidate not produced by
	// StateMachineProducer.
	stateMachineBinding *StateMachineBinding

	// mu guards the read-modify-write in Promote so concurrent promotions cannot
	// skip a rung (one wins hypothesis→reproducible; the rest see the advanced
	// state and are rejected). A Candidate is always held by pointer, never copied.
	mu sync.Mutex
}

// StateMachineBinding returns a copy of c's immutable S10/E6 replay
// identity, if c was produced by StateMachineProducer (ok=false otherwise).
// The returned value is a copy of an already-immutable value type (plain
// strings and an actionauth.ActionID — no pointers, slices, or maps), so it
// can never be used to mutate c's own binding.
func (c *Candidate) StateMachineBinding() (StateMachineBinding, bool) {
	if c.stateMachineBinding == nil {
		return StateMachineBinding{}, false
	}
	return *c.stateMachineBinding, true
}

// NewHypothesis constructs a candidate at Hypothesis — the only entry point for
// AI-derived or analysis-derived leads. Whatever a model claimed, what enters the
// system is a hypothesis.
func NewHypothesis(id, candidateType, title, target, rationale string, origin Origin, required []string, prov Provenance) *Candidate {
	return &Candidate{
		ID:               id,
		Type:             candidateType,
		Title:            title,
		Target:           target,
		Rationale:        rationale,
		State:            Hypothesis,
		Origin:           origin,
		RequiredEvidence: required,
		CreatedAt:        time.Now().UTC(),
		provenance:       prov,
	}
}

// Provenance returns a copy of the candidate's immutable origin record. Callers
// cannot mutate the candidate's provenance through the returned value.
func (c *Candidate) Provenance() Provenance { return c.provenance }

// MarshalJSON includes the unexported, immutable provenance in the candidate's
// JSON (the sync.Mutex and the raw provenance field are otherwise skipped).
func (c *Candidate) MarshalJSON() ([]byte, error) {
	type alias Candidate
	return json.Marshal(&struct {
		*alias
		Provenance Provenance `json:"provenance"`
	}{alias: (*alias)(c), Provenance: c.provenance})
}

// ErrIllegalTransition is returned when a promotion would skip a rung, go
// backward, lack a validator identity, or lack justifying evidence.
var ErrIllegalTransition = errors.New("research: illegal state transition")

// Promote advances the candidate by exactly one rung. Only a deterministic
// validator calls this, and it must identify itself (by) and cite the evidence
// (evidenceRefs) that justifies the advance. This is where "AI is not authority"
// is enforced structurally: a Provider produces hypotheses; it cannot supply a
// validator identity or real evidence refs, so it cannot move a candidate past
// Hypothesis. Advancing more than one rung, backward, without a validator, or
// without evidence all fail.
func (c *Candidate) Promote(to State, by string, evidenceRefs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := rung(c.State)
	next := rung(to)
	if cur < 0 || next < 0 {
		return fmt.Errorf("%w: unknown state %q->%q", ErrIllegalTransition, c.State, to)
	}
	if next != cur+1 {
		return fmt.Errorf("%w: must advance exactly one rung (%s->%s)", ErrIllegalTransition, c.State, to)
	}
	if by == "" {
		return fmt.Errorf("%w: a validator identity is required to advance", ErrIllegalTransition)
	}
	if len(evidenceRefs) == 0 {
		return fmt.Errorf("%w: advancing beyond hypothesis requires evidence", ErrIllegalTransition)
	}
	c.History = append(c.History, Transition{From: c.State, To: to, At: time.Now().UTC(), By: by, EvidenceRefs: evidenceRefs})
	c.State = to
	return nil
}

// attachEvidence retains validator-collected observations on the candidate so the
// content-hash refs recorded in History point at evidence that is actually kept.
// Guarded by the same mutex as Promote.
func (c *Candidate) attachEvidence(obs []Observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Evidence = append(c.Evidence, obs...)
}

// FormatID renders a candidate id, e.g. FormatID(2026, 18) == "RC-2026-000018".
func FormatID(year, seq int) string {
	return fmt.Sprintf("RC-%04d-%06d", year, seq)
}
