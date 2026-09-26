package research

import (
	"context"
	"fmt"

	"gopoc/internal/model"
)

// Outcome is a validator's factual finding — never a state, never a verdict. The
// separate promotion Engine, not the validator, decides what an outcome means for
// a candidate's state. This split is deliberate: Validator ≠ state machine, and
// AI ≠ validator, so a misbehaving validator cannot mint a state any more than a
// model can.
type Outcome string

const (
	// OutcomeNoSignal: the validator ran and found nothing supporting the lead.
	OutcomeNoSignal Outcome = "no_signal"
	// OutcomeObserved: relevant behavior was observed but not a clean reproduction.
	OutcomeObserved Outcome = "observed"
	// OutcomeReproduced: the validator deterministically reproduced the behavior.
	OutcomeReproduced Outcome = "reproduced"
)

// ValidationResult is what a Validator returns: facts (Evidence) plus an Outcome.
// There is deliberately NO State field — a validator cannot say "impact_confirmed";
// it can only report what it observed. Promotion is the Engine's job.
type ValidationResult struct {
	Validator string        `json:"validator"`
	Outcome   Outcome       `json:"outcome"`
	Evidence  []Observation `json:"evidence,omitempty"`
}

// Validator is a registered, deterministic, safe check. Crucially, it exposes no
// "execute these actions" entry point: the program picks a Validator by
// Supports(), and the Validator itself owns and bounds what it does in Validate().
// A model proposes WHAT is suspicious; a Validator decides HOW (and whether) to
// safely test it. AI-supplied text never becomes an executed action.
type Validator interface {
	Name() string
	// Supports reports whether this validator knows how to test the candidate
	// (typically by its Type). It must not perform I/O.
	Supports(c *Candidate) bool
	// Validate runs the validator's own safe, deterministic probe against target
	// and reports facts + an outcome. It must honor context cancellation and must
	// never perform a state-changing or exploitative action.
	Validate(ctx context.Context, target model.Target, c *Candidate) (ValidationResult, error)
}

// Registry is a fixed, compile-time set of validators. S5 deliberately has no
// dynamic registration: a model proposing an exotic hypothesis can never cause
// new attack logic to exist — at most it matches an already-vetted validator, or
// nothing (and the candidate stays a hypothesis).
type Registry struct {
	validators []Validator
}

// NewRegistry builds a registry from a fixed validator list.
func NewRegistry(vs ...Validator) *Registry { return &Registry{validators: vs} }

// Match returns the registered validators that support the candidate, in
// registration order. Zero → the caller keeps the candidate at hypothesis; one →
// validate; several → the Engine's scheduler runs them in order.
func (r *Registry) Match(c *Candidate) []Validator {
	var out []Validator
	for _, v := range r.validators {
		if v.Supports(c) {
			out = append(out, v)
		}
	}
	return out
}

// Engine is the ONLY component that advances a candidate's state. It runs matched
// validators and, purely from their factual outcomes, decides promotion. It is
// separate from both the validators (which produce facts) and the AI (which
// produces hypotheses), so the authority to change state lives in exactly one
// deterministic place.
type Engine struct {
	registry *Registry
}

func NewEngine(r *Registry) *Engine { return &Engine{registry: r} }

// Validate runs the matched validators against target for candidate c and
// promotes c at most one rung, only when a validator deterministically
// reproduced the lead AND the candidate's required evidence is satisfied by that
// validator's evidence. It returns every result gathered. With no matching
// validator it is a no-op and c stays at hypothesis. It is idempotent: a
// candidate already past hypothesis is never advanced again here (S5 handles only
// hypothesis→reproducible), and concurrent calls cannot skip a rung because
// Promote itself enforces single-rung, single-writer advancement.
func (e *Engine) Validate(ctx context.Context, target model.Target, c *Candidate) ([]ValidationResult, error) {
	matched := e.registry.Match(c)
	var results []ValidationResult
	for _, v := range matched {
		res, err := v.Validate(ctx, target, c)
		if err != nil {
			continue // a validator that errors contributes no facts; try the next
		}
		if res.Validator == "" {
			res.Validator = v.Name()
		}
		results = append(results, res)
		if e.shouldPromote(c, res) {
			// Retain the exact evidence on the candidate and reference each piece by
			// its content hash, so the history↔evidence link is tamper-evident: a
			// later substitution changes the hash and no longer matches. Only
			// hypothesis→reproducible in S5. Ignore an illegal-transition error:
			// under concurrency another caller may have already advanced it.
			c.attachEvidence(res.Evidence)
			_ = c.Promote(Reproducible, res.Validator, evidenceRefs(res))
			break
		}
	}
	return results, nil
}

// shouldPromote encodes the promotion rule: a reproduced outcome whose evidence
// satisfies the candidate's required-evidence list, and only from hypothesis.
func (e *Engine) shouldPromote(c *Candidate, res ValidationResult) bool {
	if c.State != Hypothesis || res.Outcome != OutcomeReproduced {
		return false
	}
	return requirementsSatisfied(c.RequiredEvidence, res.Evidence)
}

// requirementsSatisfied reports whether every required-evidence token is covered
// by an observation (by Kind or Tag). With no explicit requirements, at least one
// piece of evidence must exist — a reproduction with no evidence never promotes.
func requirementsSatisfied(required []string, evidence []Observation) bool {
	if len(evidence) == 0 {
		return false
	}
	if len(required) == 0 {
		return true
	}
	covered := func(tok string) bool {
		for _, o := range evidence {
			if o.Kind == tok {
				return true
			}
			for _, t := range o.Tags {
				if t == tok {
					return true
				}
			}
		}
		return false
	}
	for _, tok := range required {
		if !covered(tok) {
			return false
		}
	}
	return true
}

// evidenceRefs renders content-hash references for the promotion record: each ref
// is validator:kind:<observation content hash>, so a Transition cites exactly the
// bytes that justified it and any later substitution is detectable.
func evidenceRefs(res ValidationResult) []string {
	refs := make([]string, 0, len(res.Evidence))
	for i, o := range res.Evidence {
		kind := o.Kind
		if kind == "" {
			kind = fmt.Sprintf("evidence-%d", i+1)
		}
		refs = append(refs, res.Validator+":"+kind+":"+o.Hash())
	}
	return refs
}
