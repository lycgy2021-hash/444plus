package research

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// fakeCollector returns a fixed queue of raw payloads, one per Collect call,
// repeating the last one once the queue is exhausted. It is a pure test
// double for the Collector seam — it has no authority and asserts nothing
// about what the raw bytes mean. scopeSeq, if set, overrides the SCOPE the
// collector responds with, per call index (0-based; the last entry repeats
// once exhausted) — used to simulate a scope drifting mid-exploration.
type fakeCollector struct {
	mu       sync.Mutex
	seq      [][]byte
	idx      int
	scope    ExplorationScope   // if non-zero, override every call with this scope
	scopeSeq []ExplorationScope // if non-empty, override per call index instead
	calls    int
}

func (c *fakeCollector) Collect(ctx context.Context, scope ExplorationScope) (stateauth.StateArtifact, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	respondScope := scope
	if c.scope != (ExplorationScope{}) {
		respondScope = c.scope
	}
	if len(c.scopeSeq) > 0 {
		i := c.calls
		if i >= len(c.scopeSeq) {
			i = len(c.scopeSeq) - 1
		}
		respondScope = c.scopeSeq[i]
	}
	c.calls++
	var raw []byte
	if c.idx < len(c.seq) {
		raw = c.seq[c.idx]
		c.idx++
	} else if len(c.seq) > 0 {
		raw = c.seq[len(c.seq)-1]
	}
	return stateauth.StateArtifact{ScopeHash: respondScope.Hash(), Raw: raw}, nil
}

// fakeExecutor records every action/recovery it is asked to run, and tracks
// (via an atomic counter) whether it is ever entered concurrently — proof
// Explorer's serial guarantee actually holds, not just that it is documented.
// recoveryDelay, if set, makes ExecuteRecovery wait that long UNLESS ctx is
// cancelled first (e.g. by Explorer's recoveryTimeout), in which case it
// returns ctx.Err() — a cooperative test double for the recovery-timeout test.
type fakeExecutor struct {
	mu            sync.Mutex
	executed      []actionauth.ActionID
	recovered     []actionauth.RecoveryPlanRef
	executeErr    error
	sawConcurrent bool
	delay         time.Duration
	recoveryDelay time.Duration
	inFlight      int32
}

func (e *fakeExecutor) Execute(ctx context.Context, action actionauth.BoundAction) error {
	if atomic.AddInt32(&e.inFlight, 1) > 1 {
		e.sawConcurrent = true
	}
	defer atomic.AddInt32(&e.inFlight, -1)
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	e.mu.Lock()
	e.executed = append(e.executed, action.ID())
	e.mu.Unlock()
	return e.executeErr
}

func (e *fakeExecutor) ExecuteRecovery(ctx context.Context, recovery actionauth.BoundRecovery) error {
	if atomic.AddInt32(&e.inFlight, 1) > 1 {
		e.sawConcurrent = true
	}
	defer atomic.AddInt32(&e.inFlight, -1)
	if e.recoveryDelay > 0 {
		select {
		case <-time.After(e.recoveryDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	e.mu.Lock()
	e.recovered = append(e.recovered, recovery.Ref())
	e.mu.Unlock()
	return nil
}

func generousBudget() ExplorationBudget {
	return ExplorationBudget{
		MaxStates: 100, MaxTransitions: 100, MaxDepth: 100, MaxRequests: 100,
		MaxVisitsPerState: 100, MaxBranching: 1, MaxWallTime: time.Minute,
	}
}

func testScope() ExplorationScope {
	return ExplorationScope{TargetID: "t", BuildID: "b", SessionID: "s", Protocol: "http", HarnessID: "h"}
}

// rawLenReq matches any Fingerprint produced by stateauth.RawLenProjector,
// regardless of its raw_len value — the declarative "always applies"
// requirement used throughout these tests.
func rawLenReq() actionauth.StateRequirements {
	return actionauth.StateRequirements{ProjectorID: stateauth.RawLenProjector{}.ID()}
}

// testPolicy returns a policy with one always-applicable action ("probe")
// and one registered recovery ("reset").
func testPolicy() *actionauth.ActionPolicy {
	return actionauth.NewActionPolicy(
		actionauth.NewRegistry(actionauth.Registration{Action: actionauth.RegisteredAction{Key: "probe", Reversible: true}, Requirements: rawLenReq()}),
		actionauth.NewRecoveryRegistry("reset"),
	)
}

// testPolicyTwoActions returns a policy with TWO always-applicable actions
// ("action-a", "action-b") — used by tests that need Select to be able to
// pick a genuinely different action on a repeat visit to the same state
// (Select excludes an action already tried from that exact state, so a
// single-action registry cannot be revisited more than once).
func testPolicyTwoActions() *actionauth.ActionPolicy {
	return actionauth.NewActionPolicy(
		actionauth.NewRegistry(
			actionauth.Registration{Action: actionauth.RegisteredAction{Key: "action-a"}, Requirements: rawLenReq()},
			actionauth.Registration{Action: actionauth.RegisteredAction{Key: "action-b"}, Requirements: rawLenReq()},
		),
		actionauth.NewRecoveryRegistry("reset"),
	)
}

func resetRef() actionauth.RecoveryPlanRef { return actionauth.RecoveryPlanRef{RegistryKey: "reset"} }

func newTestExplorer(t *testing.T, scope ExplorationScope, collector Collector, policy *actionauth.ActionPolicy, executor Executor, budget ExplorationBudget) *Explorer {
	t.Helper()
	exp, err := NewExplorer(scope, collector, stateauth.RawLenProjector{}, policy, executor, budget, resetRef(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return exp
}

func TestExplorerBaselineThenStepRecordsTransition(t *testing.T) {
	// Step now re-collects a FRESH authorization Fingerprint before it does
	// anything else (the S10-E4d fix) — so each Step consumes TWO collector
	// calls: a fresh-before (which must match the current state, or Step
	// fail-stops on drift) and the usual post-action "after". The middle
	// "AAAA" repeats the baseline value so the fresh-before check sees no
	// drift; "BB" is the real post-action state.
	collector := &fakeCollector{seq: [][]byte{[]byte("AAAA"), []byte("AAAA"), []byte("BB")}}
	executor := &fakeExecutor{}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())

	baseline, err := exp.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Facts()["raw_len"] != "4" {
		t.Fatalf("baseline facts = %v, want raw_len=4", baseline.Facts())
	}

	tr, err := exp.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tr.BeforeFingerprint.Facts()["raw_len"] != "4" || tr.AfterFingerprint.Facts()["raw_len"] != "2" {
		t.Fatalf("transition = %+v, want before raw_len=4, after raw_len=2", tr)
	}
	if tr.Action.ID().RegistryKey != "probe" {
		t.Fatalf("transition.Action = %+v, want the only registered action \"probe\"", tr.Action.ID())
	}
	if !tr.ScopeConsistent() {
		t.Fatal("a real transition produced by Step must be scope-consistent")
	}
	if tr.TransitionArtifactHash == "" {
		t.Fatal("TransitionArtifactHash must be populated")
	}
	if len(executor.executed) != 1 || executor.executed[0].RegistryKey != "probe" {
		t.Fatalf("executor.executed = %v, want exactly one call to probe", executor.executed)
	}
	if got := exp.History(); len(got) != 1 {
		t.Fatalf("History() = %v, want exactly one transition", got)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("explorer must not be stopped after one ordinary step")
	}
}

// TestExplorerStepSelectionIsDeterministicNotCallerChosen is the direct
// regression test for the S10-E1 authority fix: Step takes NO
// action-identifying parameter (a compile-time fact — there is nothing to
// pass), and two independently constructed Explorers, given the identical
// scope, collector script, and policy, must select the identical action —
// proving the choice comes entirely from (scope, state, registry), never
// from a caller.
func TestExplorerStepSelectionIsDeterministicNotCallerChosen(t *testing.T) {
	run := func() actionauth.ActionID {
		// See TestExplorerBaselineThenStepRecordsTransition's comment: Step
		// now costs two collector calls (fresh-before, then after).
		collector := &fakeCollector{seq: [][]byte{[]byte("AAAA"), []byte("AAAA"), []byte("BB")}}
		executor := &fakeExecutor{}
		exp := newTestExplorer(t, testScope(), collector, testPolicyTwoActions(), executor, generousBudget())
		if _, err := exp.Baseline(context.Background()); err != nil {
			t.Fatal(err)
		}
		tr, err := exp.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return tr.Action.ID()
	}
	a := run()
	b := run()
	if a != b {
		t.Fatalf("two identically configured explorers selected different actions: %+v vs %+v — selection must be deterministic", a, b)
	}
	if a.RegistryKey != "action-a" {
		t.Fatalf("selected %q, want the lexically-first applicable key \"action-a\"", a.RegistryKey)
	}
}

func TestExplorerStepReturnsNoApplicableActionWithoutSideEffectOrStop(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("AAAA")}}
	executor := &fakeExecutor{}
	// "unreachable" requires a ProjectorID no RawLenProjector fingerprint will
	// ever carry, so it never matches — deterministically, without a closure.
	policy := actionauth.NewActionPolicy(
		actionauth.NewRegistry(actionauth.Registration{Action: actionauth.RegisteredAction{Key: "unreachable"}, Requirements: actionauth.StateRequirements{ProjectorID: "some-other-projector"}}),
		actionauth.NewRecoveryRegistry("reset"),
	)
	exp := newTestExplorer(t, testScope(), collector, policy, executor, generousBudget())
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := exp.Step(context.Background()); !errors.Is(err, ErrNoApplicableAction) {
		t.Fatalf("Step with nothing applicable = %v, want ErrNoApplicableAction", err)
	}
	if len(executor.executed) != 0 {
		t.Fatalf("executor must never be called when nothing is applicable, got %v", executor.executed)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("ErrNoApplicableAction must not stop the explorer — it is a normal terminal condition for this state, not a fault")
	}
	// The caller can still deliberately recover afterward.
	if _, err := exp.Recover(context.Background()); err != nil {
		t.Fatalf("Recover must still work after ErrNoApplicableAction: %v", err)
	}
}

func TestExplorerBudgetStopsFurtherSteps(t *testing.T) {
	// "A" repeats for the fresh-before check (no drift), then "B" is the
	// post-action state. The second Step call must be refused by the budget
	// PREFLIGHT, before it ever touches the collector — so no third value is
	// needed.
	collector := &fakeCollector{seq: [][]byte{[]byte("A"), []byte("A"), []byte("B")}}
	executor := &fakeExecutor{}
	budget := generousBudget()
	budget.MaxTransitions = 1
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, budget)
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background()); err != nil {
		t.Fatalf("first step within budget must succeed: %v", err)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("explorer must not be stopped immediately after using up exactly its budget")
	}
	if _, err := exp.Step(context.Background()); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second step over MaxTransitions=1 = %v, want ErrBudgetExceeded", err)
	}
	if stopped, _ := exp.Stopped(); !stopped {
		t.Fatal("explorer must be stopped once a budget bound is exceeded")
	}
	if _, err := exp.Step(context.Background()); !errors.Is(err, ErrExplorerStopped) {
		t.Fatalf("a step after stopping = %v, want ErrExplorerStopped", err)
	}
}

// TestExplorerMaxVisitsPerStateTriggersMandatoryRecoveryThenStops is the
// regression test for the S10-E3 fix: a post-action budget violation must
// never leave Explorer sitting in the over-budget state as a normal
// stopping point. It must force a recovery attempt immediately, then stop
// permanently — proved here by asserting the executor actually recorded a
// recovery call, not merely that Stopped() became true.
func TestExplorerMaxVisitsPerStateTriggersMandatoryRecoveryThenStops(t *testing.T) {
	// The collector always returns the same raw bytes, so every observed
	// state has the identical StateFingerprintHash, regardless of which
	// action ran.
	same := []byte("SAME")
	collector := &fakeCollector{seq: [][]byte{same}}
	executor := &fakeExecutor{}
	budget := generousBudget()
	budget.MaxVisitsPerState = 2
	// Two always-applicable actions are required: Select excludes an action
	// already tried from the exact same before-state, so a single-action
	// registry could never be revisited a third time to exercise this path.
	exp := newTestExplorer(t, testScope(), collector, testPolicyTwoActions(), executor, budget)
	if _, err := exp.Baseline(context.Background()); err != nil { // visit 1
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background()); err != nil { // visit 2 -> at limit, still ok
		t.Fatalf("step reaching exactly MaxVisitsPerState must still succeed: %v", err)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("reaching MaxVisitsPerState exactly must not yet stop the explorer")
	}
	tr, err := exp.Step(context.Background()) // visit 3 -> exceeds
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("the step that first exceeds MaxVisitsPerState = %v, want it to wrap ErrBudgetExceeded (it still ran, but forces a stop)", err)
	}
	if tr.TransitionArtifactHash == "" {
		t.Fatal("the transition must still be populated — it really happened, and is real evidence, even though it forces a stop")
	}
	stopped, stopErr := exp.Stopped()
	if !stopped {
		t.Fatal("exceeding MaxVisitsPerState must stop the explorer")
	}
	if !errors.Is(stopErr, ErrBudgetExceeded) {
		t.Fatalf("stop reason = %v, want it to wrap ErrBudgetExceeded", stopErr)
	}
	if len(executor.recovered) != 1 || executor.recovered[0].RegistryKey != "reset" {
		t.Fatalf("a budget violation must trigger exactly one MANDATORY recovery call, got %v", executor.recovered)
	}
	if _, err := exp.Step(context.Background()); !errors.Is(err, ErrExplorerStopped) {
		t.Fatal("a step after a forced mandatory-recovery stop must be refused")
	}
}

func TestExplorerRecoverySuccessAndFailure(t *testing.T) {
	t.Run("success_restores_baseline", func(t *testing.T) {
		baselineRaw := []byte("BASELINE")
		// baselineRaw repeats once for Step's fresh-before check (no drift),
		// then "DIFFERENT-LEN-9" is the post-action state, then baselineRaw
		// again for Recover's re-collection.
		collector := &fakeCollector{seq: [][]byte{baselineRaw, baselineRaw, []byte("DIFFERENT-LEN-9"), baselineRaw}}
		executor := &fakeExecutor{}
		exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
		if _, err := exp.Baseline(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := exp.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		outcome, err := exp.Recover(context.Background())
		if err != nil {
			t.Fatalf("a recovery that actually restores the baseline byte-length must succeed: %v", err)
		}
		if !stateauth.Recovered(outcome) {
			t.Fatal("stateauth.Recovered(outcome) must be true when Recover itself reports success")
		}
		if len(executor.recovered) != 1 || executor.recovered[0].RegistryKey != "reset" {
			t.Fatalf("executor.recovered = %v, want exactly one call to reset", executor.recovered)
		}
		if stopped, _ := exp.Stopped(); stopped {
			t.Fatal("a successful recovery must not stop the explorer")
		}
	})

	t.Run("failure_stops_exploration", func(t *testing.T) {
		baselineRaw := []byte("BASELINE")                                    // len 8
		collector := &fakeCollector{seq: [][]byte{baselineRaw, []byte("X")}} // recovery collect returns len 1, never restored
		executor := &fakeExecutor{}
		exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
		if _, err := exp.Baseline(context.Background()); err != nil {
			t.Fatal(err)
		}
		_, err := exp.Recover(context.Background())
		if err == nil {
			t.Fatal("a recovery that does not restore the baseline state must return an error")
		}
		if stopped, stopErr := exp.Stopped(); !stopped || stopErr == nil {
			t.Fatal("a failed recovery must stop the explorer permanently, per boundary 8")
		}
		if _, err := exp.Step(context.Background()); !errors.Is(err, ErrExplorerStopped) {
			t.Fatal("no further Step must be allowed after a failed recovery")
		}
		if _, err := exp.Recover(context.Background()); !errors.Is(err, ErrExplorerStopped) {
			t.Fatal("no further Recover must be allowed after a failed recovery either")
		}
	})
}

func TestExplorerConstructionRejectsUnregisteredRecoveryRef(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}}
	executor := &fakeExecutor{}
	// The policy's recovery registry only knows "reset" — configuring the
	// explorer with a different ref must make every Recover call fail, never
	// silently fall back to something else.
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget(), actionauth.RecoveryPlanRef{RegistryKey: "not-registered"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Recover(context.Background()); !errors.Is(err, ErrRecoveryNotAuthorized) {
		t.Fatalf("Recover with an unregistered configured ref = %v, want ErrRecoveryNotAuthorized", err)
	}
	if len(executor.recovered) != 0 {
		t.Fatal("executor must never be called for a rejected recovery bind")
	}
	if stopped, _ := exp.Stopped(); !stopped {
		t.Fatal("a recovery that could not even run must stop the explorer, same as any other executeRecoveryLocked failure")
	}
}

// TestExplorerBaselineScopeMismatchStopsPermanently is the regression test
// for S10-E4b: a scope mismatch is not an ordinary, retryable error — it
// permanently disables the explorer, since NewExplorer performs no I/O and
// so cannot detect this at construction time; the FIRST real collection is
// where "this session is talking to the wrong scope" can first be observed,
// and it must be treated as fatal immediately.
func TestExplorerBaselineScopeMismatchStopsPermanently(t *testing.T) {
	other := ExplorationScope{TargetID: "different"}
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}, scope: other}
	executor := &fakeExecutor{}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
	if _, err := exp.Baseline(context.Background()); err == nil {
		t.Fatal("a collector returning a StateArtifact for a different scope must be rejected")
	}
	stopped, _ := exp.Stopped()
	if !stopped {
		t.Fatal("a scope-mismatched baseline must permanently stop the explorer, not merely return a retryable error")
	}
	if _, err := exp.Baseline(context.Background()); !errors.Is(err, ErrExplorerStopped) {
		t.Fatal("retrying Baseline after a scope-mismatch stop must be refused")
	}
}

// TestExplorerFreshStateDriftBeforeActionPreventsExecution is the direct
// regression test for the S10-E4d TOCTOU fix: Step now re-collects a FRESH
// Fingerprint before it ever selects or executes anything, specifically so
// it never authorizes an action against e.current as a stale cache. Here the
// fresh-before collection itself observes a drifted scope (the target
// changed between the end of Baseline and the start of Step) — the action
// must NEVER run: this proves the drift is caught BEFORE Execute, not just
// eventually noticed afterward.
func TestExplorerFreshStateDriftBeforeActionPreventsExecution(t *testing.T) {
	drifted := ExplorationScope{TargetID: "drifted"}
	collector := &fakeCollector{
		seq:      [][]byte{[]byte("AAAA")},
		scopeSeq: []ExplorationScope{testScope(), drifted}, // call 0 = baseline (real), call 1 = Step's fresh-before (drifted)
	}
	executor := &fakeExecutor{}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background()); err == nil {
		t.Fatal("a fresh-before collection returning a different scope must fail Step")
	}
	if len(executor.executed) != 0 {
		t.Fatalf("executor.executed = %v, want the action to NEVER run once fresh-before authorization observes drift", executor.executed)
	}
	stopped, _ := exp.Stopped()
	if !stopped {
		t.Fatal("fresh-state drift observed before authorization must permanently stop the explorer")
	}
	if got := exp.History(); len(got) != 0 {
		t.Fatalf("a drift caught before execution must never be recorded in History, got %v", got)
	}
}

// TestExplorerPostActionScopeDriftFailsStop is the regression test for the
// "target dropped/rebuilt the session mid-exploration" scenario S10-E4b
// closes, exercised at the OTHER collection point Step makes: the
// fresh-before check sees no drift (the action is legitimately authorized
// and runs), but the collection immediately AFTER it observes a different
// scope. That must never be recorded as a legitimate transition either.
func TestExplorerPostActionScopeDriftFailsStop(t *testing.T) {
	drifted := ExplorationScope{TargetID: "drifted"}
	collector := &fakeCollector{
		seq: [][]byte{[]byte("AAAA"), []byte("AAAA"), []byte("BB")},
		// call 0 = baseline (real), call 1 = Step's fresh-before (real, no
		// drift — the action DOES run), call 2 = post-action collect (drifted).
		scopeSeq: []ExplorationScope{testScope(), testScope(), drifted},
	}
	executor := &fakeExecutor{}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background()); err == nil {
		t.Fatal("a post-action collection returning a different scope must be rejected, not recorded as a transition")
	}
	if len(executor.executed) != 1 {
		t.Fatalf("executor.executed = %v, want the action to have run (drift was only observed AFTER it, not before)", executor.executed)
	}
	stopped, _ := exp.Stopped()
	if !stopped {
		t.Fatal("a post-action scope drift must permanently stop the explorer")
	}
	if got := exp.History(); len(got) != 0 {
		t.Fatalf("a scope-drifted step must never be recorded in History, got %v", got)
	}
	if _, err := exp.Step(context.Background()); !errors.Is(err, ErrExplorerStopped) {
		t.Fatal("a step after a scope-drift stop must be refused")
	}
}

// TestExplorerRecoveryScopeDriftFailsStop closes the same gap specifically
// for recovery's own re-collection: even a deliberate Recover call must
// fail-stop, never report false success, if what it re-collects no longer
// belongs to this Explorer's scope.
func TestExplorerRecoveryScopeDriftFailsStop(t *testing.T) {
	drifted := ExplorationScope{TargetID: "drifted"}
	collector := &fakeCollector{
		seq:      [][]byte{[]byte("A")},
		scopeSeq: []ExplorationScope{testScope(), drifted}, // call 0 = baseline, call 1 = recovery's re-collection
	}
	executor := &fakeExecutor{}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Recover(context.Background()); err == nil {
		t.Fatal("a recovery whose re-collection returns a different scope must fail")
	}
	stopped, _ := exp.Stopped()
	if !stopped {
		t.Fatal("a scope drift observed during recovery must permanently stop the explorer")
	}
	// The recovery WAS dispatched to the executor (a real side effect
	// happened) — the failure is in verifying it afterward, once the
	// re-collection observes a different scope than this Explorer's own.
	if len(executor.recovered) != 1 {
		t.Fatalf("executor.recovered = %v, want the recovery to have actually been dispatched before the scope drift was caught on re-collection", executor.recovered)
	}
}

// TestExplorerRecoveryTimeoutStopsAHungRecovery proves recoveryTimeout is a
// real, enforced deadline on the recovery call specifically — independent
// of the overall ExplorationBudget.MaxWallTime — by using a cooperative fake
// executor whose ExecuteRecovery blocks far longer than the configured
// timeout and checking it is cut short via ctx cancellation.
func TestExplorerRecoveryTimeoutStopsAHungRecovery(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}}
	executor := &fakeExecutor{recoveryDelay: 200 * time.Millisecond}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget(), resetRef(), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = exp.Recover(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a recovery that hangs past recoveryTimeout must fail")
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("Recover took %v, want it to be cut short by the 10ms recoveryTimeout well before the executor's 200ms delay", elapsed)
	}
	if stopped, _ := exp.Stopped(); !stopped {
		t.Fatal("a recovery timeout must permanently stop the explorer")
	}
	if len(executor.recovered) != 0 {
		t.Fatal("a timed-out recovery must not be recorded as completed")
	}
}

func TestExplorerRequiresBaselineBeforeStepOrRecover(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}}
	executor := &fakeExecutor{}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
	if _, err := exp.Step(context.Background()); err == nil {
		t.Fatal("Step before Baseline must fail")
	}
	if _, err := exp.Recover(context.Background()); err == nil {
		t.Fatal("Recover before Baseline must fail")
	}
}

func TestNewExplorerRejectsInvalidBudgetOrNilOrEmptyDependencies(t *testing.T) {
	collector := &fakeCollector{}
	executor := &fakeExecutor{}
	var invalidBudget ExplorationBudget
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, invalidBudget, resetRef(), time.Second); err == nil {
		t.Fatal("an invalid (zero-value) budget must be refused at construction")
	}
	nonBranchingBudget := generousBudget()
	nonBranchingBudget.MaxBranching = 5
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, nonBranchingBudget, resetRef(), time.Second); err == nil {
		t.Fatal("a budget with MaxBranching != 1 must be refused — v1 never branches, so a larger value would misrepresent a capability that does not exist")
	}
	if _, err := NewExplorer(testScope(), nil, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget(), resetRef(), time.Second); err == nil {
		t.Fatal("a nil Collector must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, nil, testPolicy(), executor, generousBudget(), resetRef(), time.Second); err == nil {
		t.Fatal("a nil StateProjector must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, nil, executor, generousBudget(), resetRef(), time.Second); err == nil {
		t.Fatal("a nil ActionPolicy must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), nil, generousBudget(), resetRef(), time.Second); err == nil {
		t.Fatal("a nil Executor must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget(), actionauth.RecoveryPlanRef{}, time.Second); err == nil {
		t.Fatal("an empty recoveryRef must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget(), resetRef(), 0); err == nil {
		t.Fatal("a zero or negative recoveryTimeout must be refused at construction")
	}
}

func TestExplorerSerializesConcurrentSteps(t *testing.T) {
	// Each successful Step needs its fresh-before collection to match the
	// PREVIOUS step's resulting state (or the drift check refuses it before
	// ever reaching Execute) — so consecutive values repeat once each:
	// baseline=V0; step: fresh-before=V0 (repeat, no drift), after=V1; next
	// step: fresh-before=V1 (repeat), after=V2; and so on. This is what lets
	// all 5 concurrent Step calls genuinely reach Execute (a single
	// always-applicable action would otherwise be excluded as "already
	// tried" the moment the state stopped changing).
	collector := &fakeCollector{seq: [][]byte{
		[]byte("A"),               // baseline V0
		[]byte("A"), []byte("BB"), // step: fresh-before V0, after V1
		[]byte("BB"), []byte("CCC"), // step: fresh-before V1, after V2
		[]byte("CCC"), []byte("DDDD"), // step: fresh-before V2, after V3
		[]byte("DDDD"), []byte("EEEEE"), // step: fresh-before V3, after V4
		[]byte("EEEEE"), []byte("FFFFFF"), // step: fresh-before V4, after V5
	}}
	executor := &fakeExecutor{delay: 10 * time.Millisecond}
	exp := newTestExplorer(t, testScope(), collector, testPolicy(), executor, generousBudget())
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = exp.Step(context.Background())
		}()
	}
	wg.Wait()

	if executor.sawConcurrent {
		t.Fatal("Explorer must serialize Step calls — the executor must never be entered concurrently")
	}
	if len(executor.executed) != 5 {
		t.Fatalf("executor.executed = %v, want all 5 concurrent Step calls to have genuinely reached Execute (otherwise this test does not exercise real concurrency)", executor.executed)
	}
}
