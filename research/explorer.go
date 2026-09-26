package research

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// Explorer v1 — the first EXECUTION code S10 has, now that the contract
// itself is frozen (research/state_machine.go, internal/actionauth,
// internal/stateauth). This file implements exactly the closed loop that was
// agreed as v1's scope, and nothing beyond it:
//
//	Baseline: Collector -> StateArtifact -> StateProjector -> Fingerprint
//	Step:     policy.Bind(id, scope, current) -> BoundAction
//	          -> Executor.Execute -> Collector -> StateProjector -> Fingerprint
//	          -> StateTransition{before, action, after}
//	Recover:  policy.BindRecovery(ref, scope, baseline) -> BoundRecovery
//	          -> Executor.ExecuteRecovery -> Collector -> StateProjector
//	          -> stateauth.Recovered(baseline, result) -> true/STOP
//
// Explorer is PURE ORCHESTRATION and holds no authority of its own:
//   - it never decides what the state IS — that is stateauth.StateProjector's
//     job, called through the injected interface;
//   - it never decides what action MAY run — that is actionauth.ActionPolicy's
//     job; an ActionID given to Step is advisory input exactly like
//     ActionSuggestion (boundary 2), never itself a credential;
//   - it never decides whether a transition is WORTH a hypothesis — that is a
//     future producer's job against an authoritative ExpectationSource
//     (boundary 11), not implemented here;
//   - it never judges "different state == vulnerability" — StateTransition
//     stays facts-only (boundary 9), and this file adds no verdict of its own.
//
// v1 is deliberately narrow, per the locked scope: single ExplorationScope,
// single session, strictly serial (mu serializes every Step/Recover call —
// at most one in flight at a time, boundary 12), one caller-supplied action
// per Step (no AI action selection, no branching — MaxBranching is validated
// by ExplorationBudget.Valid() but has no corresponding runtime check here,
// since v1 never branches at all), a fixed compile-time registry (no dynamic
// registration, no hot reload), and a budget that must already be Valid()
// (no unlimited exploration). There is no automatic exploitability judgment
// anywhere in this file.
type Explorer struct {
	mu sync.Mutex

	scope     ExplorationScope
	collector Collector
	projector stateauth.StateProjector
	policy    *actionauth.ActionPolicy
	executor  Executor
	budget    ExplorationBudget

	started   bool
	stopped   bool
	stopErr   error
	startTime time.Time

	transitions int
	requests    int
	visits      map[string]int

	baseline   stateauth.Fingerprint
	current    stateauth.Fingerprint
	currentRaw []byte

	history []StateTransition
}

// Collector gathers a raw StateArtifact for scope. It is pure mechanical
// I/O — no interpretation, no authority: turning raw bytes into
// authoritative Facts is stateauth.StateProjector's job, never Collector's.
// A Collector implementation is free to make network/filesystem/process
// calls; Explorer counts each Collect call against ExplorationBudget.
type Collector interface {
	Collect(ctx context.Context, scope ExplorationScope) (stateauth.StateArtifact, error)
}

// Executor runs a single authorized action or recovery. It is the ONLY place
// production code may perform a side-effecting call against the explored
// target. Per boundary 4 of the S10 contract, a real Executor implementation
// MUST itself re-verify ValidFor before doing anything — Explorer's own
// ValidFor check below is defense-in-depth, never a substitute for the
// Executor's own.
type Executor interface {
	Execute(ctx context.Context, action actionauth.BoundAction) error
	ExecuteRecovery(ctx context.Context, recovery actionauth.BoundRecovery) error
}

// Sentinel errors. Explorer wraps ErrExplorerStopped with the specific reason
// it stopped for (via %w), so callers can both check "has it stopped" with
// errors.Is and log/inspect the underlying cause.
var (
	ErrExplorerStopped       = errors.New("research: explorer has stopped and refuses further steps")
	ErrBudgetExceeded        = errors.New("research: exploration budget exceeded")
	ErrActionNotAuthorized   = errors.New("research: action could not be bound (not registered, or scope/state mismatch)")
	ErrRecoveryNotAuthorized = errors.New("research: recovery could not be bound (not registered, or scope mismatch)")
)

// NewExplorer constructs an Explorer for exactly one ExplorationScope. It
// performs no I/O and takes no action itself — Baseline/Step/Recover do
// that. budget MUST already be Valid(); an invalid budget can never drive
// exploration (boundary 10), so NewExplorer refuses to construct one.
func NewExplorer(scope ExplorationScope, collector Collector, projector stateauth.StateProjector, policy *actionauth.ActionPolicy, executor Executor, budget ExplorationBudget) (*Explorer, error) {
	if !budget.Valid() {
		return nil, errors.New("research: exploration budget is invalid (every bound must be strictly positive)")
	}
	if collector == nil || projector == nil || policy == nil || executor == nil {
		return nil, errors.New("research: explorer requires a non-nil collector, projector, policy, and executor")
	}
	return &Explorer{
		scope:     scope,
		collector: collector,
		projector: projector,
		policy:    policy,
		executor:  executor,
		budget:    budget,
		visits:    make(map[string]int),
	}, nil
}

// Baseline collects and projects the CURRENT state without taking any
// action, and records it as both Explorer's current state and the baseline a
// later Recover call restores toward. It must be called exactly once, before
// the first Step or Recover.
func (e *Explorer) Baseline(ctx context.Context) (stateauth.Fingerprint, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkStoppedLocked(); err != nil {
		return stateauth.Fingerprint{}, err
	}
	if e.started {
		return stateauth.Fingerprint{}, errors.New("research: Baseline must be called exactly once, before the first Step or Recover")
	}

	fp, raw, err := e.collectAndProjectLocked(ctx)
	if err != nil {
		return stateauth.Fingerprint{}, err
	}
	e.requests++
	e.baseline = fp
	e.current = fp
	e.currentRaw = raw
	e.started = true
	e.startTime = time.Now()
	e.visits[fp.StateFingerprintHash()]++
	return fp, nil
}

// Step authorizes and executes exactly ONE action, identified by id. id may
// come from anywhere — a human researcher, a fixed pre-planned sequence, or
// an AI research.ActionSuggestion — but per boundary 2 it is never itself a
// credential: only e.policy.Bind, called here against the CURRENT scope and
// state, can turn it into a BoundAction. Step holds mu for its entire
// duration, so at most one action is ever in flight (boundary 12) — there is
// no path in this file for two Step calls to interleave.
//
// A bind failure (id not registered, or the observed state changed out from
// under a stale caller) is refused with no side effect and does NOT stop the
// explorer — the caller may retry with a different id, still within budget.
// A budget preflight failure is also refused with no side effect, but DOES
// stop the explorer permanently, since it means v1's fixed resource bounds
// are exhausted for this session.
func (e *Explorer) Step(ctx context.Context, id actionauth.ActionID) (StateTransition, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkStoppedLocked(); err != nil {
		return StateTransition{}, err
	}
	if !e.started {
		return StateTransition{}, errors.New("research: Baseline must be called before the first Step")
	}
	if err := e.preflightBudgetLocked(2); err != nil {
		e.stopLocked(err)
		return StateTransition{}, err
	}

	before := e.current
	beforeRaw := e.currentRaw

	action, ok := e.policy.Bind(id, e.scope.Hash(), before.StateFingerprintHash())
	if !ok {
		return StateTransition{}, ErrActionNotAuthorized
	}
	// Defense-in-depth: re-verify immediately before executing, exactly as
	// boundary 4 requires of a future Executor — this check is IN ADDITION
	// to, never a substitute for, the Executor's own.
	if !action.ValidFor(e.scope.Hash(), before.StateFingerprintHash()) {
		return StateTransition{}, ErrActionNotAuthorized
	}

	if err := e.executor.Execute(ctx, action); err != nil {
		return StateTransition{}, fmt.Errorf("research: executing action %s: %w", id.RegistryKey, err)
	}
	e.requests++

	after, afterRaw, err := e.collectAndProjectLocked(ctx)
	if err != nil {
		return StateTransition{}, err
	}
	e.requests++

	now := time.Now()
	transition := StateTransition{
		ScopeHash:              e.scope.Hash(),
		BeforeFingerprint:      before,
		Action:                 action,
		AfterFingerprint:       after,
		TransitionArtifactHash: transitionArtifactHash(e.scope.Hash(), beforeRaw, action.ID(), afterRaw, now),
		Timestamp:              now,
	}
	if !transition.ScopeConsistent() {
		// Should be unreachable given the checks above (before/after both came
		// from collectAndProjectLocked, which itself refuses a cross-scope
		// artifact/fingerprint) — but this is the recorded, recomputed proof
		// this transition is trustworthy at all. Treat any disagreement as a
		// hard stop rather than silently recording untrustworthy evidence.
		stopErr := errors.New("research: observed transition is not scope-consistent")
		e.stopLocked(stopErr)
		return StateTransition{}, stopErr
	}

	e.history = append(e.history, transition)
	e.transitions++
	e.visits[after.StateFingerprintHash()]++
	e.current = after
	e.currentRaw = afterRaw

	// Post-checks: this step already ran and is returned successfully: v1
	// stops FUTURE steps once a bound is reached, it never undoes a step
	// already taken.
	if e.visits[after.StateFingerprintHash()] > e.budget.MaxVisitsPerState {
		e.stopLocked(fmt.Errorf("%w: MaxVisitsPerState exceeded for the current state", ErrBudgetExceeded))
		return transition, nil
	}
	if len(e.visits) > e.budget.MaxStates {
		e.stopLocked(fmt.Errorf("%w: MaxStates exceeded", ErrBudgetExceeded))
		return transition, nil
	}

	return transition, nil
}

// Recover executes a registered recovery procedure toward the baseline state
// recorded by Baseline, then re-collects and re-projects to VERIFY it
// actually worked via stateauth.Recovered — never assuming success. A false
// result is a hard stop: per boundary 8's own doc, Explorer refuses every
// subsequent Step or Recover call from that point on; exploration must never
// continue on the assumption a rollback worked.
func (e *Explorer) Recover(ctx context.Context, ref actionauth.RecoveryPlanRef) (stateauth.RecoveryOutcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkStoppedLocked(); err != nil {
		return stateauth.RecoveryOutcome{}, err
	}
	if !e.started {
		return stateauth.RecoveryOutcome{}, errors.New("research: Baseline must be called before Recover")
	}
	if err := e.preflightBudgetLocked(2); err != nil {
		e.stopLocked(err)
		return stateauth.RecoveryOutcome{}, err
	}

	recovery, ok := e.policy.BindRecovery(ref, e.scope.Hash(), e.baseline.StateFingerprintHash())
	if !ok {
		return stateauth.RecoveryOutcome{}, ErrRecoveryNotAuthorized
	}
	if !recovery.ValidFor(e.scope.Hash()) {
		return stateauth.RecoveryOutcome{}, ErrRecoveryNotAuthorized
	}

	if err := e.executor.ExecuteRecovery(ctx, recovery); err != nil {
		return stateauth.RecoveryOutcome{}, fmt.Errorf("research: executing recovery %s: %w", ref.RegistryKey, err)
	}
	e.requests++

	result, resultRaw, err := e.collectAndProjectLocked(ctx)
	if err != nil {
		return stateauth.RecoveryOutcome{}, err
	}
	e.requests++

	outcome := stateauth.RecoveryOutcome{
		ScopeHash: e.scope.Hash(),
		Baseline:  e.baseline,
		Result:    result,
	}
	if !stateauth.Recovered(outcome) {
		stopErr := fmt.Errorf("research: recovery %q did not restore the baseline state for scope %s — exploration STOPS", ref.RegistryKey, e.scope.Hash())
		e.stopLocked(stopErr)
		return outcome, stopErr
	}

	e.current = result
	e.currentRaw = resultRaw
	e.visits[result.StateFingerprintHash()]++
	return outcome, nil
}

// History returns a copy of every StateTransition observed so far, in order.
func (e *Explorer) History() []StateTransition {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]StateTransition, len(e.history))
	copy(out, e.history)
	return out
}

// Stopped reports whether the explorer has permanently stopped (a budget
// bound was reached, a recovery failed to verify, or an internal consistency
// check failed) and, if so, why.
func (e *Explorer) Stopped() (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopped, e.stopErr
}

func (e *Explorer) checkStoppedLocked() error {
	if e.stopped {
		return fmt.Errorf("%w: %v", ErrExplorerStopped, e.stopErr)
	}
	return nil
}

func (e *Explorer) stopLocked(err error) {
	e.stopped = true
	e.stopErr = err
}

// preflightBudgetLocked refuses BEFORE any side effect if taking one more
// transition (which costs the given number of requests) would exceed a
// bound that is knowable in advance (MaxTransitions, MaxDepth, MaxRequests,
// MaxWallTime). MaxStates and MaxVisitsPerState depend on the state actually
// observed AFTER acting, so they are checked as post-checks in Step/Recover
// instead — this function never checks them.
func (e *Explorer) preflightBudgetLocked(requestCost int) error {
	if e.transitions+1 > e.budget.MaxTransitions {
		return fmt.Errorf("%w: MaxTransitions", ErrBudgetExceeded)
	}
	if e.transitions+1 > e.budget.MaxDepth {
		return fmt.Errorf("%w: MaxDepth", ErrBudgetExceeded)
	}
	if e.requests+requestCost > e.budget.MaxRequests {
		return fmt.Errorf("%w: MaxRequests", ErrBudgetExceeded)
	}
	if !e.startTime.IsZero() && time.Since(e.startTime) > e.budget.MaxWallTime {
		return fmt.Errorf("%w: MaxWallTime", ErrBudgetExceeded)
	}
	return nil
}

// collectAndProjectLocked is the one place Explorer turns raw evidence into
// an authoritative Fingerprint, by delegating to the injected Collector and
// StateProjector — Explorer itself never constructs one.
func (e *Explorer) collectAndProjectLocked(ctx context.Context) (stateauth.Fingerprint, []byte, error) {
	artifact, err := e.collector.Collect(ctx, e.scope)
	if err != nil {
		return stateauth.Fingerprint{}, nil, fmt.Errorf("research: collecting state: %w", err)
	}
	if artifact.ScopeHash != e.scope.Hash() {
		return stateauth.Fingerprint{}, nil, errors.New("research: collector returned a StateArtifact for a different scope")
	}
	fp, err := e.projector.Project(artifact)
	if err != nil {
		return stateauth.Fingerprint{}, nil, fmt.Errorf("research: projecting state: %w", err)
	}
	if fp.ScopeHash() != e.scope.Hash() {
		return stateauth.Fingerprint{}, nil, errors.New("research: projector returned a Fingerprint for a different scope")
	}
	return fp, artifact.Raw, nil
}

// transitionArtifactHash is the LOSSLESS hash of a transition's own raw
// record (the S9 caseArtifactHash analogue): every input byte that produced
// this transition, in a fixed order, never the denoised StateFingerprintHash.
func transitionArtifactHash(scopeHash string, beforeRaw []byte, action actionauth.ActionID, afterRaw []byte, ts time.Time) string {
	var b bytes.Buffer
	b.WriteString(scopeHash)
	b.WriteByte('\n')
	b.Write(beforeRaw)
	b.WriteByte('\n')
	b.WriteString(action.RegistryKey)
	b.WriteByte('\n')
	b.WriteString(action.VariantID)
	b.WriteByte('\n')
	b.Write(afterRaw)
	b.WriteByte('\n')
	b.WriteString(ts.UTC().Format(time.RFC3339Nano))
	return RawInputHash(b.Bytes())
}
