package research

import (
	"errors"
	"fmt"
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

// Origin records where a candidate came from — and, critically, whether a
// non-authoritative AI provider suggested it. This provenance is permanent so an
// AI origin is never lost or mistaken for a validated fact.
type Origin struct {
	// Source is the research source, e.g. "finding_analyst", "diff", "fuzz".
	Source string `json:"source"`
	// AISuggested is true when an ai.Provider proposed this candidate.
	AISuggested bool `json:"ai_suggested"`
	// Provider/Model identify the backend, when AISuggested.
	Provider string `json:"provider,omitempty"`
}

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
	History          []Transition  `json:"history,omitempty"`
}

// NewHypothesis constructs a candidate at Hypothesis — the only entry point for
// AI-derived or analysis-derived leads. Whatever a model claimed, what enters the
// system is a hypothesis.
func NewHypothesis(id, candidateType, title, target, rationale string, origin Origin, required []string) *Candidate {
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
	}
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

// FormatID renders a candidate id, e.g. FormatID(2026, 18) == "RC-2026-000018".
func FormatID(year, seq int) string {
	return fmt.Sprintf("RC-%04d-%06d", year, seq)
}
