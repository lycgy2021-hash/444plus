package stateauth

import "testing"

func TestFixtureRegistryProjectsRawLenProjector(t *testing.T) {
	reg := FixtureRegistry()
	fp, err := reg.Project(StateArtifact{ScopeHash: "scope-1", Raw: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if fp.ScopeHash() != "scope-1" {
		t.Fatalf("ScopeHash() = %q, want scope-1", fp.ScopeHash())
	}
	if fp.Facts()["raw_len"] != "5" {
		t.Fatalf("Facts() = %v, want raw_len=5", fp.Facts())
	}
	if fp.ProjectorID() != "rawlen-v1" {
		t.Fatalf("ProjectorID() = %q, want rawlen-v1", fp.ProjectorID())
	}
}

// TestBoundRegistryHasNoWayToProjectADifferentID documents, rather than
// tests at runtime (Go's type system already enforces it at compile time),
// the central claim this file makes: BoundRegistry.Project takes no
// ProjectorID parameter at all — there is nothing for a caller to pass, so
// there is no way to ask a *BoundRegistry obtained from FixtureRegistry() to
// use a different projector than the one it was built with.
func TestBoundRegistryHasNoWayToProjectADifferentID(t *testing.T) {
	reg := FixtureRegistry()
	fp, err := reg.Project(StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if fp.ProjectorID() != "rawlen-v1" {
		t.Fatalf("every Project call on this BoundRegistry must use rawlen-v1, got %q", fp.ProjectorID())
	}
}

func TestNilBoundRegistryNeverProjects(t *testing.T) {
	var nilReg *BoundRegistry
	if _, err := nilReg.Project(StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("a nil *BoundRegistry must never project (and must not panic)")
	}
}

func TestRegistryProjectUnknownIDFails(t *testing.T) {
	reg := newRegistry(RawLenProjector{})
	if _, err := reg.project("no-such-projector", StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("project with an unregistered ProjectorID must fail")
	}
}

func TestNilOrZeroRegistryNeverProjects(t *testing.T) {
	var nilReg *registry
	if _, err := nilReg.project("rawlen-v1", StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("a nil *registry must never project (and must not panic)")
	}
	var zeroReg registry
	if _, err := zeroReg.project("rawlen-v1", StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("a zero-value registry (nil internal map) must never project")
	}
}
