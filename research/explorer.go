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
//	Baseline: Collector -> StateArtifact -> stateauth.Registry.Project -> Fingerprint
//	Step:     policy.Select(scope, current, tried) -> BoundAction
//	          -> Executor.Execute -> Collector -> Registry.Project -> Fingerprint
//	          -> StateTransition{before, action, after}
//	Recover:  policy.BindRecovery(fixed ref, scope, baseline) -> BoundRecovery
//	          -> Executor.ExecuteRecovery -> Collector -> Registry.Project
//	          -> stateauth.Recovered(baseline, result) -> true/STOP
//
// Explorer is PURE ORCHESTRATION and holds no authority of its own:
//   - it never decides what the state IS — that is stateauth's own Registry's
//     job (see PROJECTOR AUTHORITY below), called through a *stateauth.Registry
//     and a ProjectorID, never a bare StateProjector value;
//   - it never decides WHICH action MAY run — that is
//     actionauth.ActionPolicy.Select's job, called with only facts (current
//     scope, current Fingerprint, which action keys have already been tried
//     from this exact state). An earlier version of this file took a
//     caller-supplied actionauth.ActionID directly into Step and asked the
//     policy "is this one registered?" — that reopened exactly the bypass
//     S10 exists to close: whoever supplies the ActionID (a human, or
//     indirectly an AI research.ActionSuggestion) would be choosing WHICH
//     action runs, with the registry doing nothing but rubber-stamp
//     membership. Step below takes NO action-identifying parameter at all;
//     Select is the only place a choice is made, and it is entirely
//     deterministic — a declarative actionauth.StateRequirements match (plain
//     data, never a callback: see that type's own doc for why a Go closure
//     would have been an escape hatch) plus the exclude set;
//   - it never decides whether a transition is WORTH a hypothesis — that is a
//     future producer's job against an authoritative ExpectationSource
//     (boundary 11), not implemented here;
//   - it never judges "different state == vulnerability" — StateTransition
//     stays facts-only (boundary 9), and this file adds no verdict of its own.
//
// v1 is deliberately narrow, per the locked scope: single ExplorationScope,
// single session, strictly serial (mu serializes every Step/Recover call —
// at most one in flight at a time, boundary 12), a fixed compile-time
// registry (no dynamic registration, no hot reload), and a budget that must
// already be Valid() (no unlimited exploration) AND have MaxBranching exactly
// 1 — NewExplorer refuses any other value, so a budget can never claim to
// support a branching capability v1's Step/Select do not actually provide
// (Select always picks at most one action; there is no code path to branch).
// There is no automatic exploitability judgment anywhere in this file.
//
// A budget violation discovered only AFTER a step (MaxStates/
// MaxVisitsPerState — these depend on the state actually observed, so they
// cannot be preflighted) is never treated as an ordinary stopping point that
// leaves Explorer sitting in the over-budget state: it triggers MANDATORY
// recovery back toward the baseline immediately, then a permanent stop —
// never a continuation from a state that was already known to exceed the
// budget the moment it was observed.
//
// SCOPE CONTINUITY is enforced structurally, not left to a caller's
// judgment: every single collect-and-project (in Baseline, after an action in
// Step, and inside a recovery attempt) requires the observed StateArtifact
// and Fingerprint to agree with this Explorer's own fixed ExplorationScope —
// collectAndProjectLocked refuses otherwise — and ANY error there (a scope
// drift, a plain I/O failure, a projector error) is treated as a PERMANENT
// STOP, never a retryable condition. Without this, a session that silently
// reconnected to a different target/session mid-exploration (the target
// dropped the connection, a load balancer routing a probe to a different
// backend, a test double was misconfigured) could keep recording
// "transitions" that are not really state A -> state B at all, but state A
// (old session) -> state B (an unrelated new session) — never a legitimate
// observation. Because both e.baseline and e.current are ALWAYS the result of
// a successful (and therefore same-scope) collectAndProjectLocked call for
// the entire lifetime of a non-stopped Explorer, RecoveryOutcome's own
// cross-scope check (stateauth.Recovered) can never actually be exercised by
// a genuine scope drift here — the drift is caught and stopped at the moment
// it is observed, before it could ever be compared against anything.
//
// FRESH-STATE AUTHORIZATION closes a narrower, but real, TOCTOU: even with
// scope continuity enforced, an action was still being authorized against
// e.current — a Fingerprint left over from a PAST collection (Baseline, or
// the previous Step's own post-action collect). Nothing stops the real
// target from changing on its own, for reasons this Explorer never caused,
// in the time between that past observation and this Step's Execute call. So
// Step (below) re-collects and re-projects FIRST, before Select is ever
// consulted, and compares the fresh result against e.current: any
// disagreement is EXTERNAL STATE DRIFT and a permanent stop, never silently
// treated as a new baseline to continue from. v1 has no revision/ETag/
// session-nonce freshness mechanism, so this is the deliberately blunt v1
// answer: no asynchronous network system can eliminate a TOCTOU window
// entirely, but authorizing off a fresh observation instead of a historical
// cache closes the window this Explorer itself controls.
//
// PROJECTOR AUTHORITY closes a subtler bypass of the fix above: fresh-state
// authorization only works if the Fingerprint Step re-collects is actually
// FRESH. An earlier version of this file held a bare stateauth.StateProjector
// interface value — any package can write a type satisfying that interface,
// and while it could never forge a NEW Fingerprint (stateauth's own
// constructor is unexported), nothing stopped it from CAPTURING a
// Fingerprint from one genuinely earlier Project call and REPLAYING it on
// every later call, ignoring the StateArtifact it was actually asked to
// project. That would make fresh-state authorization's own drift check see a
// perfectly self-consistent Fingerprint and never suspect it was minted for
// different bytes — the state-authority analogue of exactly the TOCTOU
// fresh-state authorization closes for actions. Fixed the same way
// actionauth closes action selection: Explorer holds a *stateauth.BoundRegistry
// (obtained ONLY via a named stateauth profile constructor, e.g.
// stateauth.FixtureRegistry() — there is no exported constructor an external
// package could hand a fake/replaying projector to), never a StateProjector
// value directly.
//
// Critically, BoundRegistry ALSO closes a narrower version of that same
// class of bypass one level up: an earlier version of this file took the
// registry and a caller-supplied ProjectorID as TWO SEPARATE parameters —
// which would have let a caller pick WHICH registered projector interprets
// the same raw evidence, the state-authority analogue of the "caller picks
// ActionID" bypass S10-E1 closed for actions. If a registry ever holds both
// a minimal fixture projector and a real protocol-specific one, a caller
// choosing the weaker one could turn "authoritative state" into "whichever
// state semantics the caller finds convenient". Explorer therefore holds a
// single *stateauth.BoundRegistry — registry and projector bound together,
// by stateauth itself, with no parameter through which Explorer's own caller
// could ask for a different pairing.
//
// WALL-TIME ENFORCEMENT closes a gap found once S10-E5 made real network
// I/O possible: preflightBudgetLocked's MaxWallTime check only runs BETWEEN
// calls to Baseline/Step — it says "too much time has already passed
// before this next call", never "this specific network call must give up
// by such-and-such a time". A single request that simply never returns
// (a hung connection, a target that accepts a socket and never responds)
// would defeat that check entirely: nothing would ever get to the next
// preflight to notice the budget was blown. Fixed: Baseline and Step both
// derive a context.WithDeadline from the session's absolute wall-clock
// budget (e.startTime + budget.MaxWallTime — set once, at Baseline, never
// renewed per call) and pass THAT to every real-I/O call they make
// (collectAndProjectLocked, Executor.Execute) — a hanging Collector or
// Executor implementation now has its ctx cancelled once the session's own
// wall-clock budget is exhausted, exactly like recoveryTimeout already
// does for recovery specifically (recovery deliberately keeps its OWN
// separate deadline mechanism, per its own "emergency allowance" design —
// this does not change that). The same COOPERATIVE-cancellation caveat
// recoveryTimeout's own doc states applies here too: Explorer can only
// provide the deadline; a real implementation must itself be
// context-aware (e.g. via http.NewRequestWithContext) for it to actually
// interrupt anything.
type Explorer struct {
	mu sync.Mutex

	scope           ExplorationScope
	collector       Collector
	projector       *stateauth.BoundRegistry
	policy          *actionauth.ActionPolicy
	executor        Executor
	budget          ExplorationBudget
	recoveryRef     actionauth.RecoveryPlanRef
	recoveryTimeout time.Duration

	// explorationMeter bounds real I/O for Baseline/Step; recoveryMeter is a
	// SEPARATE, independently bounded "emergency allowance" for every
	// recovery attempt (deliberate or mandatory) — see RequestMeter's own
	// doc for why Explorer no longer guesses a fixed request cost per call.
	explorationMeter *boundedRequestMeter
	recoveryMeter    *boundedRequestMeter

	started   bool
	stopped   bool
	stopErr   error
	startTime time.Time

	transitions int
	visits      map[string]int
	tried       map[string]map[string]bool

	baseline   stateauth.Fingerprint
	current    stateauth.Fingerprint
	currentRaw []byte

	history []StateTransition
}

// Collector gathers a raw StateArtifact for scope. It is pure mechanical
// I/O — no interpretation, no authority: turning raw bytes into
// authoritative Facts is stateauth's own BoundRegistry's job, never
// Collector's.
// A Collector implementation is free to make network/filesystem/process
// calls; it MUST call RequestMeter.Acquire (via RequestMeterFromContext) once
// for EACH real request it actually issues, so ExplorationBudget.MaxRequests
// bounds real I/O rather than a number Explorer itself guesses.
type Collector interface {
	Collect(ctx context.Context, scope ExplorationScope) (stateauth.StateArtifact, error)
}

// Executor runs a single authorized action or recovery. It is the ONLY place
// production code may perform a side-effecting call against the explored
// target. Per boundary 4 of the S10 contract, a real Executor implementation
// MUST itself re-verify ValidFor before doing anything — Explorer's own
// ValidFor check below is defense-in-depth, never a substitute for the
// Executor's own. Like Collector, it MUST call RequestMeter.Acquire for each
// real request it actually issues.
//
// A real Executor implementation MUST ALSO independently re-verify
// action.SpecID() against its own internally-computed canonical spec for
// the action it is about to run, and refuse on any mismatch — see
// HTTPExecutor.Execute and HTTPActionSpecID for the reference
// implementation. Neither Explorer nor S10/E7's replay validator performs
// this check itself: only the concrete Executor knows what its own
// "correct" SpecID actually is, so pre-checking it anywhere else would
// just be re-trusting the registry side without truly verifying the
// Executor's own wiring — exactly the gap SpecID exists to close (see
// actionauth.RegisteredAction.SpecID's own doc).
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
	ErrNoApplicableAction    = errors.New("research: no registered action is both applicable to the current state and not already tried")
	ErrActionNotAuthorized   = errors.New("research: selected action failed its own re-verification (should be unreachable)")
	ErrRecoveryNotAuthorized = errors.New("research: recovery could not be bound (not registered, or scope mismatch)")
)

// NewExplorer constructs an Explorer for exactly one ExplorationScope. It
// performs no I/O and takes no action itself — Baseline/Step/Recover do
// that.
//
// budget MUST already be Valid() AND have MaxBranching exactly 1 — v1 has no
// code path that ever branches, so a budget claiming to allow anything else
// would be configuration that lies about a capability this Explorer does not
// provide. budget.MaxRequests bounds the EXPLORATION meter (Baseline/Step);
// it is enforced by real Collector/Executor calls to RequestMeter.Acquire,
// never by Explorer guessing a fixed cost per call.
//
// projector names the ONE registered StateProjector (and registry) this
// Explorer will ever use to turn raw evidence into an authoritative
// Fingerprint. It must come from a named stateauth profile constructor, e.g.
// stateauth.FixtureRegistry() (test/fixture use only — see its own doc) —
// see the package doc's PROJECTOR AUTHORITY section for why Explorer cannot
// accept a bare StateProjector value, or a registry and ProjectorID as
// separate parameters a caller could mix and match.
//
// recoveryRef names the SINGLE registered recovery procedure this Explorer
// will ever use — both for a deliberate Recover call and for the mandatory
// recovery a post-action budget violation triggers — mirroring RecoveryPlan's
// own shape (one Baseline, one Recovery ref, never a menu). recoveryTimeout
// bounds EVERY recovery attempt with its own hard deadline context,
// independent of budget.MaxWallTime: a hung recovery — the one safety
// mechanism v1 has — must never turn "bounded exploration" into an unbounded
// wait. IMPORTANT CAVEAT: ctx cancellation in Go is COOPERATIVE, not
// forceful — Explorer cannot physically kill an Executor that ignores
// ctx.Done(); every real Executor v1 plugs in MUST itself be
// context-cooperative (e.g. build HTTP requests with
// http.NewRequestWithContext). recoveryRequestAllowance is recovery's own
// SEPARATE, independently bounded real-I/O meter: deliberately never blocked
// by the exploration meter being exhausted (a mandatory recovery must still
// be able to run when budget.MaxRequests is spent), but never unlimited
// either.
func NewExplorer(
	scope ExplorationScope,
	collector Collector,
	projector *stateauth.BoundRegistry,
	policy *actionauth.ActionPolicy,
	executor Executor,
	budget ExplorationBudget,
	recoveryRef actionauth.RecoveryPlanRef,
	recoveryTimeout time.Duration,
	recoveryRequestAllowance int,
) (*Explorer, error) {
	if !budget.Valid() {
		return nil, errors.New("research: exploration budget is invalid (every bound must be strictly positive)")
	}
	if budget.MaxBranching != 1 {
		return nil, errors.New("research: v1 never branches — MaxBranching must be exactly 1, not merely positive")
	}
	if collector == nil || projector == nil || policy == nil || executor == nil {
		return nil, errors.New("research: explorer requires a non-nil collector, projector, policy, and executor")
	}
	if recoveryRef.RegistryKey == "" {
		return nil, errors.New("research: explorer requires a non-empty recovery ref")
	}
	if recoveryTimeout <= 0 {
		return nil, errors.New("research: explorer requires a strictly positive recoveryTimeout — a hung recovery must never wait forever")
	}
	if recoveryRequestAllowance <= 0 {
		return nil, errors.New("research: explorer requires a strictly positive recoveryRequestAllowance — mandatory recovery must be bounded, never unlimited")
	}
	return &Explorer{
		scope:            scope,
		collector:        collector,
		projector:        projector,
		policy:           policy,
		executor:         executor,
		budget:           budget,
		recoveryRef:      recoveryRef,
		recoveryTimeout:  recoveryTimeout,
		explorationMeter: newBoundedRequestMeter(budget.MaxRequests),
		recoveryMeter:    newBoundedRequestMeter(recoveryRequestAllowance),
		visits:           make(map[string]int),
		tried:            make(map[string]map[string]bool),
	}, nil
}

// Baseline collects and projects the CURRENT state without taking any
// action, and records it as both Explorer's current state and the baseline
// a later Recover call (deliberate or mandatory) restores toward. It must be
// called exactly once, before the first Step or Recover.
func (e *Explorer) Baseline(ctx context.Context) (stateauth.Fingerprint, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkStoppedLocked(); err != nil {
		return stateauth.Fingerprint{}, err
	}
	if e.started {
		return stateauth.Fingerprint{}, errors.New("research: Baseline must be called exactly once, before the first Step or Recover")
	}

	// MaxWallTime must bound the ACTUAL network call, not just be checked
	// between steps — see the package doc's WALL-TIME ENFORCEMENT section.
	// Baseline is where the session's wall-clock budget starts, so its
	// deadline is simply "now + MaxWallTime".
	start := time.Now()
	deadlineCtx, cancel := context.WithDeadline(ctx, start.Add(e.budget.MaxWallTime))
	defer cancel()

	fp, raw, err := e.collectAndProjectLocked(deadlineCtx, e.explorationMeter)
	if err != nil {
		// Any collection/projection failure — including a scope mismatch — is
		// a permanent stop, never a retryable condition: see the package doc
		// on SCOPE CONTINUITY.
		e.stopLocked(err)
		return stateauth.Fingerprint{}, err
	}
	e.baseline = fp
	e.current = fp
	e.currentRaw = raw
	e.started = true
	e.startTime = start
	e.visits[fp.StateFingerprintHash()]++
	return fp, nil
}

// Step selects and executes exactly ONE action, chosen ENTIRELY by
// e.policy.Select from the current scope/state and the set of action keys
// already tried from this exact state — Step passes no action identity of
// its own, and takes no such parameter from its caller. Step holds mu for
// its entire duration, so at most one action is ever in flight (boundary
// 12) — there is no path in this file for two Step calls to interleave.
//
// ErrNoApplicableAction (no side effect, does NOT stop the explorer) means
// exactly what it says: either nothing registered supports the current
// state, or everything that does has already been tried from it. That is a
// normal, expected terminal condition for a given state — not a fault — and
// the caller may still call Recover.
//
// A budget preflight failure is refused with no side effect, and DOES stop
// the explorer permanently (v1's fixed resource bounds are exhausted). A
// budget violation discovered only AFTER this step (MaxStates/
// MaxVisitsPerState) triggers MANDATORY recovery and a permanent stop before
// Step returns — see the package doc.
//
// Step authorizes its action against a FRESHLY collected Fingerprint, never
// against e.current as a cached credential — see the package doc's
// FRESH-STATE AUTHORIZATION and PROJECTOR AUTHORITY sections for why both the
// re-collection AND the registry-owned projection are required to make that
// freshness actually trustworthy.
func (e *Explorer) Step(ctx context.Context) (StateTransition, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkStoppedLocked(); err != nil {
		return StateTransition{}, err
	}
	if !e.started {
		return StateTransition{}, errors.New("research: Baseline must be called before the first Step")
	}
	if err := e.preflightBudgetLocked(); err != nil {
		e.stopLocked(err)
		return StateTransition{}, err
	}
	if e.explorationMeter.Used() >= e.budget.MaxRequests {
		err := fmt.Errorf("%w: MaxRequests", ErrBudgetExceeded)
		e.stopLocked(err)
		return StateTransition{}, err
	}

	// MaxWallTime must bound the ACTUAL network calls this Step makes, not
	// just be checked before starting one — see the package doc's
	// WALL-TIME ENFORCEMENT section. The deadline is the session's absolute
	// wall-clock budget (e.startTime + MaxWallTime), shared by all three
	// real-I/O calls below, never renewed per call.
	deadlineCtx, cancel := context.WithDeadline(ctx, e.startTime.Add(e.budget.MaxWallTime))
	defer cancel()

	// Fresh authorization state — NEVER e.current used as-is. This is the
	// TOCTOU fix: Select/Bind below only ever see a Fingerprint collected
	// this instant, not one left over from a previous Step.
	before, beforeRaw, err := e.collectAndProjectLocked(deadlineCtx, e.explorationMeter)
	if err != nil {
		e.stopLocked(err)
		return StateTransition{}, err
	}
	beforeHash := before.StateFingerprintHash()
	if beforeHash != e.current.StateFingerprintHash() {
		// The target changed on its own between the end of the previous
		// step (or Baseline) and the start of this one — external state
		// drift, not anything this Explorer's own action caused (no action
		// has run yet this Step). v1's rule: fail-stop, never continue as if
		// the drifted state were the new current one, and never re-baseline
		// automatically — that decision belongs to whoever restarts
		// exploration, not to this Step call.
		stopErr := fmt.Errorf("research: external state drift observed before Step could authorize an action (expected state %q, observed %q) — exploration STOPS", e.current.StateFingerprintHash(), beforeHash)
		e.stopLocked(stopErr)
		return StateTransition{}, stopErr
	}

	action, ok := e.policy.Select(e.scope.Hash(), before, e.tried[beforeHash])
	if !ok {
		return StateTransition{}, ErrNoApplicableAction
	}
	// Defense-in-depth: re-verify immediately before executing, exactly as
	// boundary 4 requires of a future Executor — this check is IN ADDITION
	// to, never a substitute for, the Executor's own. Select just built
	// action against these exact values, so this should be unreachable; it
	// is kept as a real check, not a decorative one.
	if !action.ValidFor(e.scope.Hash(), beforeHash) {
		return StateTransition{}, ErrActionNotAuthorized
	}

	if e.tried[beforeHash] == nil {
		e.tried[beforeHash] = make(map[string]bool)
	}
	e.tried[beforeHash][action.ID().RegistryKey] = true

	execCtx := ContextWithRequestMeter(deadlineCtx, e.explorationMeter)
	if err := e.executor.Execute(execCtx, action); err != nil {
		return StateTransition{}, fmt.Errorf("research: executing action %s: %w", action.ID().RegistryKey, err)
	}

	after, afterRaw, err := e.collectAndProjectLocked(deadlineCtx, e.explorationMeter)
	if err != nil {
		// Any collection/projection failure after an action — including a
		// scope mismatch (the target dropped the connection, a load balancer
		// routed to a different backend, a session was silently rebuilt) — is
		// a permanent stop. The action already ran (recorded in e.tried) so
		// there is no meaningful "retry" here: the observed world no longer
		// matches this Explorer's own scope, so nothing further it collects
		// could be trusted either. See the package doc on SCOPE CONTINUITY.
		e.stopLocked(err)
		return StateTransition{}, err
	}

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

	// Post-check: MaxStates/MaxVisitsPerState depend on the state actually
	// observed, so they can only be checked here, after the side effect. This
	// step's own transition already happened and is real evidence — it is
	// still returned — but the state it landed in is NOT a valid point to
	// continue from: force recovery now, then stop permanently, rather than
	// leaving Explorer sitting in a state that was already over budget the
	// moment it was observed.
	if e.visits[after.StateFingerprintHash()] > e.budget.MaxVisitsPerState || len(e.visits) > e.budget.MaxStates {
		budgetErr := fmt.Errorf("%w: post-action state budget exceeded (MaxVisitsPerState/MaxStates)", ErrBudgetExceeded)
		e.forceRecoveryAndStopLocked(ctx, budgetErr)
		return transition, e.stopErr
	}

	return transition, nil
}

// Recover deliberately executes this Explorer's single registered recovery
// procedure toward the baseline state recorded by Baseline, then re-collects
// and re-projects to VERIFY it actually worked via stateauth.Recovered —
// never assuming success. A false result is a hard stop: per boundary 8's
// own doc, Explorer refuses every subsequent Step or Recover call from that
// point on; exploration must never continue on the assumption a rollback
// worked.
func (e *Explorer) Recover(ctx context.Context) (stateauth.RecoveryOutcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkStoppedLocked(); err != nil {
		return stateauth.RecoveryOutcome{}, err
	}
	if !e.started {
		return stateauth.RecoveryOutcome{}, errors.New("research: Baseline must be called before Recover")
	}
	if err := e.preflightBudgetLocked(); err != nil {
		e.stopLocked(err)
		return stateauth.RecoveryOutcome{}, err
	}

	outcome, err := e.executeRecoveryLocked(ctx)
	if err != nil {
		// Any failure to even RUN a recovery attempt (bind failure, executor
		// error, a recovery timeout, recovery's own request allowance being
		// exhausted, or a scope mismatch on re-collection) is a permanent
		// stop: a deliberate Recover call that could not complete cleanly
		// leaves no state this Explorer can trust enough to continue from.
		e.stopLocked(err)
		return stateauth.RecoveryOutcome{}, err
	}
	if !stateauth.Recovered(outcome) {
		stopErr := fmt.Errorf("research: recovery %q did not restore the baseline state for scope %s — exploration STOPS", e.recoveryRef.RegistryKey, e.scope.Hash())
		e.stopLocked(stopErr)
		return outcome, stopErr
	}
	e.visits[outcome.Result.StateFingerprintHash()]++
	return outcome, nil
}

// forceRecoveryAndStopLocked is called ONLY from Step, immediately after a
// post-action budget violation. It never returns an error itself: it always
// stops the explorer, but the message it stops with distinguishes whether
// the mandatory recovery also succeeded, failed to verify, or could not even
// run — a caller inspecting Stopped() can tell which happened. It
// deliberately does NOT go through preflightBudgetLocked and uses
// e.recoveryMeter, never e.explorationMeter — an already-exhausted
// exploration budget must never be able to block the one safety mechanism
// meant to run precisely when that budget is exhausted, but the recovery
// attempt itself is still bounded, by its own separate allowance.
func (e *Explorer) forceRecoveryAndStopLocked(ctx context.Context, cause error) {
	outcome, err := e.executeRecoveryLocked(ctx)
	switch {
	case err != nil:
		e.stopLocked(fmt.Errorf("%w (mandatory recovery could not run: %v)", cause, err))
	case !stateauth.Recovered(outcome):
		e.stopLocked(fmt.Errorf("%w (mandatory recovery did not restore baseline)", cause))
	default:
		e.stopLocked(fmt.Errorf("%w (mandatory recovery restored baseline; exploration stopped)", cause))
	}
}

// executeRecoveryLocked is the shared mechanics behind both a deliberate
// Recover call and forceRecoveryAndStopLocked's mandatory one: bind this
// Explorer's single fixed recoveryRef, re-verify ValidFor, run it under its
// own recoveryTimeout deadline AND its own recoveryMeter (never
// explorationMeter — recovery's "emergency allowance" is deliberately
// separate from, and unaffected by, the main exploration budget), and
// re-collect/re-project (itself subject to the same scope-continuity check
// as every other collection — a scope mismatch here surfaces as an ordinary
// error, handled like any other executeRecoveryLocked failure by its
// callers). It never itself decides whether the outcome counts as recovered
// (stateauth.Recovered is the only function that may) and never itself stops
// the explorer — callers do that.
func (e *Explorer) executeRecoveryLocked(ctx context.Context) (stateauth.RecoveryOutcome, error) {
	recovery, ok := e.policy.BindRecovery(e.recoveryRef, e.scope.Hash(), e.baseline.StateFingerprintHash())
	if !ok {
		return stateauth.RecoveryOutcome{}, ErrRecoveryNotAuthorized
	}
	if !recovery.ValidFor(e.scope.Hash()) {
		return stateauth.RecoveryOutcome{}, ErrRecoveryNotAuthorized
	}
	// recoveryTimeout is a hard deadline on this call alone, independent of
	// ExplorationBudget.MaxWallTime — the one safety mechanism v1 has must
	// never be able to hang forever. Layered with the recovery meter, never
	// the exploration one.
	recoveryCtx, cancel := context.WithTimeout(ContextWithRequestMeter(ctx, e.recoveryMeter), e.recoveryTimeout)
	err := e.executor.ExecuteRecovery(recoveryCtx, recovery)
	cancel()
	if err != nil {
		return stateauth.RecoveryOutcome{}, fmt.Errorf("research: executing recovery %s: %w", e.recoveryRef.RegistryKey, err)
	}

	result, resultRaw, err := e.collectAndProjectLocked(ctx, e.recoveryMeter)
	if err != nil {
		return stateauth.RecoveryOutcome{}, err
	}

	outcome := stateauth.RecoveryOutcome{
		ScopeHash: e.scope.Hash(),
		Baseline:  e.baseline,
		Result:    result,
	}
	if stateauth.Recovered(outcome) {
		e.current = result
		e.currentRaw = resultRaw
	}
	return outcome, nil
}

// History returns a copy of every StateTransition observed so far, in order
// — never the internal slice itself, so a caller can never mutate Explorer's
// own record (and, critically, can never influence e.tried/e.visits, which
// are built ENTIRELY from Explorer's own private bookkeeping and never
// accept caller-supplied history back in).
func (e *Explorer) History() []StateTransition {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]StateTransition, len(e.history))
	copy(out, e.history)
	return out
}

// Stopped reports whether the explorer has permanently stopped (a budget
// bound was reached, a recovery failed to run or verify, a scope-continuity
// check failed, or an internal consistency check failed) and, if so, why.
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
// transition would exceed a bound that is knowable in advance from
// Explorer's own counters (MaxTransitions, MaxDepth, MaxWallTime).
// MaxRequests is NOT checked here — real I/O is metered by
// explorationMeter/recoveryMeter, called by Collector/Executor themselves
// (see RequestMeter's doc) — Step does its own explorationMeter fail-fast
// check separately. MaxStates and MaxVisitsPerState depend on the state
// actually observed AFTER acting, so they are checked as post-checks in Step
// instead — this function never checks them either.
func (e *Explorer) preflightBudgetLocked() error {
	if e.transitions+1 > e.budget.MaxTransitions {
		return fmt.Errorf("%w: MaxTransitions", ErrBudgetExceeded)
	}
	if e.transitions+1 > e.budget.MaxDepth {
		return fmt.Errorf("%w: MaxDepth", ErrBudgetExceeded)
	}
	if !e.startTime.IsZero() && time.Since(e.startTime) > e.budget.MaxWallTime {
		return fmt.Errorf("%w: MaxWallTime", ErrBudgetExceeded)
	}
	return nil
}

// collectAndProjectLocked is the one place Explorer turns raw evidence into
// an authoritative Fingerprint, by delegating to the injected Collector and
// to e.projector.Project (never a bare StateProjector value, and never a
// registry plus a separately chosen ProjectorID — see PROJECTOR AUTHORITY).
// meter is attached to ctx so the Collector can account for every real
// request it actually issues. It is a thin wrapper over the package-level
// collectAndProject (below), which S10/E7's replay validator also calls
// directly — a replay session has no Explorer instance of its own (it never
// branches, loops, or needs Explorer's other budget fields), but it must
// turn evidence into a Fingerprint through the exact SAME scope-checked
// path, never a hand-rolled shortcut.
func (e *Explorer) collectAndProjectLocked(ctx context.Context, meter RequestMeter) (stateauth.Fingerprint, []byte, error) {
	return collectAndProject(ctx, e.collector, e.projector, e.scope, meter)
}

// collectAndProject turns raw evidence into an authoritative Fingerprint for
// scope: it calls collector.Collect, verifies the returned StateArtifact
// actually carries scope's own hash, calls projector.Project, and verifies
// the resulting Fingerprint does too — refusing (never silently accepting)
// any artifact or Fingerprint that claims a different scope. meter is
// attached to ctx so the Collector can account for every real request it
// actually issues.
func collectAndProject(ctx context.Context, collector Collector, projector *stateauth.BoundRegistry, scope ExplorationScope, meter RequestMeter) (stateauth.Fingerprint, []byte, error) {
	ctx = ContextWithRequestMeter(ctx, meter)
	artifact, err := collector.Collect(ctx, scope)
	if err != nil {
		return stateauth.Fingerprint{}, nil, fmt.Errorf("research: collecting state: %w", err)
	}
	if artifact.ScopeHash != scope.Hash() {
		return stateauth.Fingerprint{}, nil, errors.New("research: collector returned a StateArtifact for a different scope")
	}
	fp, err := projector.Project(artifact)
	if err != nil {
		return stateauth.Fingerprint{}, nil, fmt.Errorf("research: projecting state: %w", err)
	}
	if fp.ScopeHash() != scope.Hash() {
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
