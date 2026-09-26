package research

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// StateMachineReplayValidator (S10/E7) independently re-tests an
// OriginStateMachine hypothesis Candidate: does the SAME authoritative
// TransitionRule, replayed in a genuinely FRESH session against the SAME
// target/build/protocol/harness, again observe a violation? It is
// deliberately narrow, exactly as scoped: one action, one fresh session, no
// new exploration capability, no state preparation, and it NEVER promotes —
// Replay returns a ValidationResult (the Engine's own input); advancing
// Candidate.State past Hypothesis remains exclusively the Engine's job.
//
// INDEPENDENT EVIDENCE, NOT A REPLAY OF OLD DATA. Replay never reads the
// original StateTransition's own BeforeFingerprint/AfterFingerprint as if
// they were evidence — it treats the Candidate's Refs purely as "what to
// test" (which rule, which action, which projector, which target), and
// produces every fact fresh: a new Collect, a new authorized Action bind,
// a new Execute, a new Collect. The original transition is provenance
// (what raised the hypothesis); it is never replay evidence (what confirms
// or refutes it).
//
// NO REOPENED "CALLER PICKS ACTIONID" BYPASS. A Candidate's own
// Refs["action_registry_key"]/["action_variant_id"] are NEVER handed
// directly to an Executor. Replay resolves rule := rules.LookupByRuleID(c.
// Refs["rule_id"]) against its OWN trusted TransitionRuleRegistry FIRST,
// cross-checks the Candidate's claimed action/projector identity against
// THAT rule (rejecting on any mismatch), and only then binds rule.ActionID
// — via a throwaway, single-entry actionauth.Registry scoped to exactly
// that RegistryKey, so ActionPolicy.Select is structurally incapable of
// returning anything else. The Candidate never supplies an execution
// credential, directly or indirectly.
//
// FRESH SESSION, SAME TARGET. v.target (a ReplayTarget — TargetID/BuildID/
// Protocol/HarnessID, deliberately WITHOUT SessionID) is fixed at
// construction; each Replay call takes a caller-supplied sessionID and
// builds a full ExplorationScope from v.target.Scope(sessionID). This
// proves reproduction under a genuinely INDEPENDENT session against the
// SAME real-world target — never "the same recorded session replayed", and
// never a substituted target (Replay rejects a Candidate whose
// Refs["replay_target_hash"] does not match v.target.Hash()).
//
// NO STATE PREPARATION. If ExpectFactTransition's own precondition
// (before.Facts[Fact] == BeforeValue) does not hold against the FRESH
// baseline, Replay stops immediately with OutcomeNoSignal — it never runs
// extra actions to force the precondition to hold. A future state-setup
// capability, if ever built, must be its own explicit, separately reviewed
// design — never smuggled into a replay validator.
//
// SAME E5 SAFETY BOUNDARIES, NO EXCEPTIONS. Replay uses the SAME Collector/
// Executor implementations (and therefore the SAME BudgetedRoundTripper,
// fail-closed-without-a-meter, redirect-refusal, and body-size cap) any
// Explorer session would, through the SAME collectAndProject path — never a
// parallel, less-audited code path. ReplayBudget gives it its OWN request
// meter and wall-clock deadline, independent of any Explorer's
// ExplorationBudget.
type StateMachineReplayValidator struct {
	target    ReplayTarget
	rules     *TransitionRuleRegistry
	collector Collector
	projector *stateauth.BoundRegistry
	executor  Executor
	budget    ReplayBudget
}

// ReplayBudget bounds ONE replay attempt: a fresh baseline collection,
// exactly one authorized action, and a fresh result collection. Unlike
// ExplorationBudget (which bounds an open-ended, possibly-branching,
// multi-step walk), a replay never loops and never branches — v1 needs no
// MaxDepth/MaxStates/MaxVisitsPerState/MaxBranching. Both fields must be
// strictly positive, matching ExplorationBudget's own "no zero-means-
// unlimited escape hatch" discipline.
type ReplayBudget struct {
	MaxRequests int
	MaxWallTime time.Duration
}

// Valid reports whether both bounds are strictly positive.
func (b ReplayBudget) Valid() bool { return b.MaxRequests > 0 && b.MaxWallTime > 0 }

// NewStateMachineReplayValidator builds a validator bound to exactly one
// ReplayTarget, one TRUSTED TransitionRuleRegistry (the SAME registry — or
// an equally trusted one built the same way — that produced the candidates
// it will be asked to replay), and one Collector/projector/Executor triple
// for that target. It performs no I/O.
func NewStateMachineReplayValidator(
	target ReplayTarget,
	rules *TransitionRuleRegistry,
	collector Collector,
	projector *stateauth.BoundRegistry,
	executor Executor,
	budget ReplayBudget,
) (*StateMachineReplayValidator, error) {
	if rules == nil || collector == nil || projector == nil || executor == nil {
		return nil, errors.New("research: replay validator requires a non-nil rules registry, collector, projector, and executor")
	}
	if !budget.Valid() {
		return nil, errors.New("research: replay budget is invalid (MaxRequests and MaxWallTime must both be strictly positive)")
	}
	return &StateMachineReplayValidator{target: target, rules: rules, collector: collector, projector: projector, executor: executor, budget: budget}, nil
}

// Name identifies this validator in ValidationResult.Validator and in
// Candidate.History after a future Engine promotion.
func (v *StateMachineReplayValidator) Name() string { return "state_machine_replay_v1" }

// Sentinel errors for Replay's precondition/authority checks — all of them
// caller-usage or Candidate-shape errors, distinct from a runtime I/O
// failure during the replay attempt itself (which Replay wraps and returns
// as an ordinary error too, per the "network error / scope drift / budget /
// timeout -> error" rule).
var (
	ErrReplayUnsupportedOrigin = errors.New("research: replay validator only supports OriginStateMachine candidates")
	ErrReplayMissingRuleID     = errors.New("research: candidate has no rule_id ref to replay against")
	ErrReplayUnknownRule       = errors.New("research: candidate's rule_id is not registered in this validator's TransitionRuleRegistry")
	ErrReplayActionMismatch    = errors.New("research: candidate's recorded action identity does not match the resolved rule's ActionID")
	ErrReplayProjectorMismatch = errors.New("research: candidate's recorded projector identity does not match the resolved rule's ProjectorID")
	ErrReplayTargetMismatch    = errors.New("research: candidate's replay_target_hash does not match this validator's own ReplayTarget")
	ErrReplaySessionIDRequired = errors.New("research: replay requires a non-empty, freshly chosen sessionID")
)

// Replay independently re-tests c against a FRESH session (sessionID) under
// v's own configured ReplayTarget. It NEVER calls c.Promote — advancing
// Candidate.State remains exclusively the Engine's job, driven by the
// returned ValidationResult.
//
// Outcome mapping (deliberately conservative, per the S10/E7 contract):
//
//	c is not OriginStateMachine, has no/an unknown rule_id, or its recorded
//	action/projector/target identity disagrees with the resolved rule/this
//	validator's own target                          -> error (never attempted)
//	fresh baseline does not satisfy a fact_transition
//	rule's own precondition                          -> OutcomeNoSignal (no execute)
//	fresh replay: rule satisfied, or not_applicable   -> OutcomeNoSignal
//	fresh replay: insufficient evidence (a fact the
//	rule needs is absent from the FRESH after-state) -> error (validation incomplete, never a claim)
//	fresh replay: rule violated again                -> OutcomeReproduced
//	network error / scope drift / budget exhausted /
//	timeout / projector failure                      -> error
func (v *StateMachineReplayValidator) Replay(ctx context.Context, c *Candidate, sessionID string) (ValidationResult, error) {
	if c.Origin.Kind != OriginStateMachine {
		return ValidationResult{}, ErrReplayUnsupportedOrigin
	}
	ruleID := c.Refs["rule_id"]
	if ruleID == "" {
		return ValidationResult{}, ErrReplayMissingRuleID
	}
	rule, ok := v.rules.LookupByRuleID(ruleID)
	if !ok {
		return ValidationResult{}, ErrReplayUnknownRule
	}
	if c.Refs["action_registry_key"] != rule.ActionID.RegistryKey || c.Refs["action_variant_id"] != rule.ActionID.VariantID {
		return ValidationResult{}, ErrReplayActionMismatch
	}
	if c.Refs["projector_id"] != string(rule.ProjectorID) {
		return ValidationResult{}, ErrReplayProjectorMismatch
	}
	if c.Refs["replay_target_hash"] != v.target.Hash() {
		return ValidationResult{}, ErrReplayTargetMismatch
	}
	if sessionID == "" {
		return ValidationResult{}, ErrReplaySessionIDRequired
	}

	scope := v.target.Scope(sessionID)
	meter := newBoundedRequestMeter(v.budget.MaxRequests)
	deadlineCtx, cancel := context.WithDeadline(ctx, time.Now().Add(v.budget.MaxWallTime))
	defer cancel()

	before, beforeRaw, err := collectAndProject(deadlineCtx, v.collector, v.projector, scope, meter)
	if err != nil {
		return ValidationResult{}, fmt.Errorf("research: replay baseline collection: %w", err)
	}

	// NO STATE PREPARATION: if the fresh baseline doesn't satisfy
	// ExpectFactTransition's own precondition, the rule simply never
	// engages here — stop now, before ever binding or executing an action.
	if rule.Expectation.Kind == ExpectFactTransition {
		val, factOK := before.Facts()[rule.Expectation.Fact]
		if !factOK || val != rule.Expectation.BeforeValue {
			return ValidationResult{
				Validator: v.Name(),
				Outcome:   OutcomeNoSignal,
				Evidence:  []Observation{replayFingerprintObservation("replay_baseline_precondition_not_met", before)},
			}, nil
		}
	}

	// Bind EXACTLY rule.ActionID — never the Candidate's claimed
	// action_registry_key directly. A throwaway, single-entry Registry
	// scoped to rule.ActionID.RegistryKey/rule.ProjectorID makes
	// ActionPolicy.Select structurally incapable of returning anything
	// else, exactly like S10-E1 already requires of a real Explorer.
	replayRegistry := actionauth.NewRegistry(actionauth.Registration{
		Action:       actionauth.RegisteredAction{Key: rule.ActionID.RegistryKey},
		Requirements: actionauth.StateRequirements{ProjectorID: rule.ProjectorID},
	})
	policy := actionauth.NewActionPolicy(replayRegistry, actionauth.NewRecoveryRegistry())
	boundAction, ok := policy.Select(scope.Hash(), before, nil)
	if !ok {
		return ValidationResult{}, fmt.Errorf("research: replay could not bind action %q for the fresh baseline", rule.ActionID.RegistryKey)
	}

	execCtx := ContextWithRequestMeter(deadlineCtx, meter)
	if err := v.executor.Execute(execCtx, boundAction); err != nil {
		return ValidationResult{}, fmt.Errorf("research: replay executing action %s: %w", rule.ActionID.RegistryKey, err)
	}

	after, afterRaw, err := collectAndProject(deadlineCtx, v.collector, v.projector, scope, meter)
	if err != nil {
		return ValidationResult{}, fmt.Errorf("research: replay result collection: %w", err)
	}

	now := time.Now().UTC()
	freshTransition := StateTransition{
		ScopeHash:              scope.Hash(),
		BeforeFingerprint:      before,
		Action:                 boundAction,
		AfterFingerprint:       after,
		EvidenceRefs:           []string{"replay_baseline", "replay_result"},
		TransitionArtifactHash: transitionArtifactHash(scope.Hash(), beforeRaw, boundAction.ID(), afterRaw, now),
		Timestamp:              now,
	}
	freshCase := resolvedTransitionCase{Transition: freshTransition, Scope: scope, Rule: rule}
	if !freshCase.validate() {
		// Should be unreachable given the checks above (fresh scope, fresh
		// authorization, matching projector) — kept as a REAL check, not a
		// decorative one, exactly like Explorer's own analogous checks.
		return ValidationResult{}, errors.New("research: replay produced a self-inconsistent transition (scope drift or authorization failure)")
	}

	assessment, anomalies := analyzeExpectation(freshCase)
	replayArtifactHash := transitionCaseArtifactHash(freshCase)

	outcome, isSignal := replayOutcomeFor(assessment)
	if !isSignal {
		return ValidationResult{}, fmt.Errorf("research: replay evidence incomplete (assessment=%s) — validation not complete, never claiming a signal either way", assessment)
	}
	evidence := []Observation{
		replayFingerprintObservation("replay_before_fingerprint", before),
		replayFingerprintObservation("replay_after_fingerprint", after),
	}
	if outcome == OutcomeReproduced {
		evidence = append(evidence, replaySummaryObservation(v, scope, rule, boundAction, anomalies, meter, replayArtifactHash))
	}
	return ValidationResult{Validator: v.Name(), Outcome: outcome, Evidence: evidence}, nil
}

// replayOutcomeFor is the pure, deterministic, no-I/O outcome-mapping rule
// table S10/E7's contract specifies — deliberately conservative:
//
//	satisfied      -> no_signal (the rule held; nothing to report)
//	not_applicable -> no_signal (the rule's own precondition never engaged)
//	violated       -> reproduced (the ONLY assessment that is ever a signal)
//	insufficient_evidence, or anything unrecognized
//	               -> isSignal=false: Replay reports this as an ERROR
//	                  (validation incomplete), never as a claim either way —
//	                  it must NEVER be silently upgraded to no_signal, which
//	                  would misreport "we don't know" as "we checked and
//	                  found nothing".
func replayOutcomeFor(assessment TransitionAssessment) (outcome Outcome, isSignal bool) {
	switch assessment {
	case TransitionSatisfied, TransitionNotApplicable:
		return OutcomeNoSignal, true
	case TransitionViolated:
		return OutcomeReproduced, true
	default:
		return "", false
	}
}

// replayFingerprintObservation renders a fresh stateauth.Fingerprint as an
// Observation: its own hashes plus every Fact, sorted for determinism only
// — read through Fingerprint's own accessor methods, never a struct literal
// or a bare json.Marshal of the opaque type.
func replayFingerprintObservation(kind string, fp stateauth.Fingerprint) Observation {
	facts := fp.Facts()
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	artifacts := []Artifact{
		{Kind: "state_fingerprint_hash", Ref: fp.StateFingerprintHash()},
		{Kind: "raw_state_artifact_hash", Ref: fp.RawStateArtifactHash()},
	}
	for _, k := range keys {
		artifacts = append(artifacts, Artifact{Kind: "fact:" + k, Ref: facts[k]})
	}
	return Observation{
		Kind:          kind,
		Source:        "state_machine_replay_v1",
		NetworkAction: ActionReadOnly,
		Tags:          []string{"state_transition", kind},
		Artifacts:     artifacts,
	}
}

// replaySummaryObservation bundles the replay's own identity and result —
// replay target identity, replay session/scope hash, rule_id, projector_id,
// action_id, the assessment, request count, and the replay's OWN case
// artifact hash — into one Observation, tagged so it satisfies a
// state-machine Candidate's RequiredEvidence ("authorized_expectation") for
// a future Engine promotion.
func replaySummaryObservation(v *StateMachineReplayValidator, scope ExplorationScope, rule TransitionRule, action actionauth.BoundAction, anomalies []TransitionAnomaly, meter RequestMeter, replayArtifactHash string) Observation {
	artifacts := []Artifact{
		{Kind: "replay_target_hash", Ref: v.target.Hash()},
		{Kind: "replay_scope_hash", Ref: scope.Hash()},
		{Kind: "rule_id", Ref: rule.RuleID},
		{Kind: "projector_id", Ref: string(rule.ProjectorID)},
		{Kind: "action_registry_key", Ref: action.ID().RegistryKey},
		{Kind: "action_variant_id", Ref: action.ID().VariantID},
		{Kind: "assessment", Ref: string(TransitionViolated)},
		{Kind: "request_count", Ref: strconv.Itoa(meter.Used())},
		// replay_case_artifact_hash is THIS replay's own artifact hash —
		// deliberately a DIFFERENT value from the original Candidate's own
		// case_artifact_hash (a different Transition, a different Scope), even
		// though both were judged against the identical Rule.
		{Kind: "replay_case_artifact_hash", Ref: replayArtifactHash},
	}
	for i, a := range anomalies {
		artifacts = append(artifacts,
			Artifact{Kind: fmt.Sprintf("anomaly[%d]_fact", i), Ref: a.Fact},
			Artifact{Kind: fmt.Sprintf("anomaly[%d]_expected_after", i), Ref: a.ExpectedAfter},
			Artifact{Kind: fmt.Sprintf("anomaly[%d]_observed_after", i), Ref: a.ObservedAfter},
		)
	}
	return Observation{
		Kind:          "replay_summary",
		Source:        "state_machine_replay_v1",
		NetworkAction: ActionReadOnly,
		Tags:          []string{"authorized_expectation", "replay_summary"},
		Artifacts:     artifacts,
	}
}
