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
// about what the raw bytes mean.
type fakeCollector struct {
	mu      sync.Mutex
	seq     [][]byte
	idx     int
	scope   ExplorationScope // set non-zero to force a wrong-scope response
	callErr error
	calls   int
}

func (c *fakeCollector) Collect(ctx context.Context, scope ExplorationScope) (stateauth.StateArtifact, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.callErr != nil {
		return stateauth.StateArtifact{}, c.callErr
	}
	respondScope := scope
	if c.scope != (ExplorationScope{}) {
		respondScope = c.scope
	}
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
type fakeExecutor struct {
	mu            sync.Mutex
	executed      []actionauth.ActionID
	recovered     []actionauth.RecoveryPlanRef
	executeErr    error
	recoveryErr   error
	inFlight      int32
	sawConcurrent bool
	delay         time.Duration
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
	e.mu.Lock()
	e.recovered = append(e.recovered, recovery.Ref())
	e.mu.Unlock()
	return e.recoveryErr
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

func testPolicy() *actionauth.ActionPolicy {
	return actionauth.NewActionPolicy(
		actionauth.NewRegistry(actionauth.RegisteredAction{Key: "probe", Reversible: true}),
		actionauth.NewRecoveryRegistry("reset"),
	)
}

func TestExplorerBaselineThenStepRecordsTransition(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("AAAA"), []byte("BB")}}
	executor := &fakeExecutor{}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
	if err != nil {
		t.Fatal(err)
	}

	baseline, err := exp.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Facts()["raw_len"] != "4" {
		t.Fatalf("baseline facts = %v, want raw_len=4", baseline.Facts())
	}

	tr, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	if tr.BeforeFingerprint.Facts()["raw_len"] != "4" || tr.AfterFingerprint.Facts()["raw_len"] != "2" {
		t.Fatalf("transition = %+v, want before raw_len=4, after raw_len=2", tr)
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

func TestExplorerStepRefusesUnregisteredActionWithoutSideEffectOrStop(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("AAAA")}}
	executor := &fakeExecutor{}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "not-registered"}); !errors.Is(err, ErrActionNotAuthorized) {
		t.Fatalf("Step with an unregistered action = %v, want ErrActionNotAuthorized", err)
	}
	if len(executor.executed) != 0 {
		t.Fatalf("executor must never be called for a rejected bind, got %v", executor.executed)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("a rejected bind must not stop the explorer — it is refused, not fatal")
	}
	// The caller can retry with a registered id afterward.
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); err != nil {
		t.Fatalf("retry with a registered action should succeed: %v", err)
	}
}

func TestExplorerBudgetStopsFurtherSteps(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A"), []byte("B"), []byte("C")}}
	executor := &fakeExecutor{}
	budget := generousBudget()
	budget.MaxTransitions = 1
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); err != nil {
		t.Fatalf("first step within budget must succeed: %v", err)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("explorer must not be stopped immediately after using up exactly its budget")
	}
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second step over MaxTransitions=1 = %v, want ErrBudgetExceeded", err)
	}
	if stopped, _ := exp.Stopped(); !stopped {
		t.Fatal("explorer must be stopped once a budget bound is exceeded")
	}
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); !errors.Is(err, ErrExplorerStopped) {
		t.Fatalf("a step after stopping = %v, want ErrExplorerStopped", err)
	}
}

func TestExplorerMaxVisitsPerStateStopsAfterRevisit(t *testing.T) {
	// The collector always returns the same raw bytes, so every observed
	// state has the identical StateFingerprintHash.
	same := []byte("SAME")
	collector := &fakeCollector{seq: [][]byte{same, same, same, same}}
	executor := &fakeExecutor{}
	budget := generousBudget()
	budget.MaxVisitsPerState = 2
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil { // visit 1
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); err != nil { // visit 2 -> at limit, still ok
		t.Fatalf("step reaching exactly MaxVisitsPerState must still succeed: %v", err)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("reaching MaxVisitsPerState exactly must not yet stop the explorer")
	}
	tr, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}) // visit 3 -> exceeds
	if err != nil {
		t.Fatalf("the step that first exceeds MaxVisitsPerState must still return its own transition: %v", err)
	}
	if tr.TransitionArtifactHash == "" {
		t.Fatal("the returned transition must still be populated")
	}
	if stopped, _ := exp.Stopped(); !stopped {
		t.Fatal("exceeding MaxVisitsPerState must stop the explorer for FUTURE steps")
	}
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); !errors.Is(err, ErrExplorerStopped) {
		t.Fatal("a step after MaxVisitsPerState was exceeded must be refused")
	}
}

func TestExplorerRecoverySuccessAndFailure(t *testing.T) {
	t.Run("success_restores_baseline", func(t *testing.T) {
		baselineRaw := []byte("BASELINE")
		collector := &fakeCollector{seq: [][]byte{baselineRaw, []byte("DIFFERENT-LEN-9"), baselineRaw}}
		executor := &fakeExecutor{}
		exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exp.Baseline(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); err != nil {
			t.Fatal(err)
		}
		outcome, err := exp.Recover(context.Background(), actionauth.RecoveryPlanRef{RegistryKey: "reset"})
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
		exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exp.Baseline(context.Background()); err != nil {
			t.Fatal(err)
		}
		_, err = exp.Recover(context.Background(), actionauth.RecoveryPlanRef{RegistryKey: "reset"})
		if err == nil {
			t.Fatal("a recovery that does not restore the baseline state must return an error")
		}
		if stopped, stopErr := exp.Stopped(); !stopped || stopErr == nil {
			t.Fatal("a failed recovery must stop the explorer permanently, per boundary 8")
		}
		if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); !errors.Is(err, ErrExplorerStopped) {
			t.Fatal("no further Step must be allowed after a failed recovery")
		}
		if _, err := exp.Recover(context.Background(), actionauth.RecoveryPlanRef{RegistryKey: "reset"}); !errors.Is(err, ErrExplorerStopped) {
			t.Fatal("no further Recover must be allowed after a failed recovery either")
		}
	})
}

func TestExplorerRecoveryRefusesUnregisteredRecovery(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}}
	executor := &fakeExecutor{}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Recover(context.Background(), actionauth.RecoveryPlanRef{RegistryKey: "not-registered"}); !errors.Is(err, ErrRecoveryNotAuthorized) {
		t.Fatalf("Recover with an unregistered ref = %v, want ErrRecoveryNotAuthorized", err)
	}
	if len(executor.recovered) != 0 {
		t.Fatal("executor must never be called for a rejected recovery bind")
	}
}

func TestExplorerCollectorWrongScopeIsRejected(t *testing.T) {
	other := ExplorationScope{TargetID: "different"}
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}, scope: other}
	executor := &fakeExecutor{}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err == nil {
		t.Fatal("a collector returning a StateArtifact for a different scope must be rejected")
	}
}

func TestExplorerRequiresBaselineBeforeStepOrRecover(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A")}}
	executor := &fakeExecutor{}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"}); err == nil {
		t.Fatal("Step before Baseline must fail")
	}
	if _, err := exp.Recover(context.Background(), actionauth.RecoveryPlanRef{RegistryKey: "reset"}); err == nil {
		t.Fatal("Recover before Baseline must fail")
	}
}

func TestNewExplorerRejectsInvalidBudgetOrNilDependencies(t *testing.T) {
	collector := &fakeCollector{}
	executor := &fakeExecutor{}
	var invalidBudget ExplorationBudget
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, invalidBudget); err == nil {
		t.Fatal("an invalid (zero-value) budget must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), nil, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget()); err == nil {
		t.Fatal("a nil Collector must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, nil, testPolicy(), executor, generousBudget()); err == nil {
		t.Fatal("a nil StateProjector must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, nil, executor, generousBudget()); err == nil {
		t.Fatal("a nil ActionPolicy must be refused at construction")
	}
	if _, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), nil, generousBudget()); err == nil {
		t.Fatal("a nil Executor must be refused at construction")
	}
}

func TestExplorerSerializesConcurrentSteps(t *testing.T) {
	collector := &fakeCollector{seq: [][]byte{[]byte("A"), []byte("B"), []byte("C")}}
	executor := &fakeExecutor{delay: 10 * time.Millisecond}
	exp, err := NewExplorer(testScope(), collector, stateauth.RawLenProjector{}, testPolicy(), executor, generousBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exp.Baseline(context.Background()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = exp.Step(context.Background(), actionauth.ActionID{RegistryKey: "probe"})
		}()
	}
	wg.Wait()

	if executor.sawConcurrent {
		t.Fatal("Explorer must serialize Step calls — the executor must never be entered concurrently")
	}
}
