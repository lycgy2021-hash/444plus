package research

import (
	"testing"
	"time"
)

// This file tests only the two PURE functions the S10 contract defines
// (ExplorationScope.Hash, ExplorationBudget.Valid). There is no explorer, no
// registry, and no execution logic to test yet — that is the point of a
// contract-only stage. These tests exist so the contract's own value-level
// guarantees (scope separation, budget positivity) are pinned before any
// implementation is built on top of them.

func TestExplorationScopeHashSeparatesDimensions(t *testing.T) {
	base := ExplorationScope{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h1"}
	sameAgain := ExplorationScope{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h1"}
	if base.Hash() != sameAgain.Hash() {
		t.Fatal("identical scopes must hash identically")
	}
	variants := []ExplorationScope{
		{TargetID: "t", BuildID: "b2", SessionID: "s1", Protocol: "http", HarnessID: "h1"}, // different build
		{TargetID: "t", BuildID: "b1", SessionID: "s2", Protocol: "http", HarnessID: "h1"}, // different session
		{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "grpc", HarnessID: "h1"}, // different protocol
		{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h2"}, // different harness
	}
	for i, v := range variants {
		if v.Hash() == base.Hash() {
			t.Errorf("variant %d (differs from base in one dimension) must hash differently", i)
		}
	}
}

func TestExplorationBudgetValidRequiresEveryFieldStrictlyPositive(t *testing.T) {
	full := ExplorationBudget{
		MaxStates: 1, MaxTransitions: 1, MaxDepth: 1, MaxRequests: 1,
		MaxVisitsPerState: 1, MaxBranching: 1, MaxWallTime: time.Second,
	}
	if !full.Valid() {
		t.Fatal("a budget with every field strictly positive must be valid")
	}
	// Zeroing any single field must invalidate the whole budget — there is no
	// "0 means unlimited" reading anywhere in this type, unlike ai.Budget.
	zero := func(mutate func(*ExplorationBudget)) ExplorationBudget {
		b := full
		mutate(&b)
		return b
	}
	cases := []ExplorationBudget{
		zero(func(b *ExplorationBudget) { b.MaxStates = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxTransitions = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxDepth = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxRequests = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxVisitsPerState = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxBranching = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxWallTime = 0 }),
	}
	for i, b := range cases {
		if b.Valid() {
			t.Errorf("case %d: a budget with one zeroed field must be invalid (zero is not unlimited)", i)
		}
	}
	// A negative value must also invalidate (not merely "falsy zero").
	neg := full
	neg.MaxStates = -1
	if neg.Valid() {
		t.Fatal("a negative bound must be invalid")
	}
	var zeroVal ExplorationBudget
	if zeroVal.Valid() {
		t.Fatal("the zero-value budget must be invalid")
	}
}
