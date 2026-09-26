package stateauth

import "testing"

func TestDefaultRegistryProjectsRawLenProjector(t *testing.T) {
	reg := DefaultRegistry()
	fp, err := reg.Project("rawlen-v1", StateArtifact{ScopeHash: "scope-1", Raw: []byte("hello")})
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

func TestRegistryProjectUnknownIDFails(t *testing.T) {
	reg := DefaultRegistry()
	if _, err := reg.Project("no-such-projector", StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("Project with an unregistered ProjectorID must fail")
	}
}

func TestNilOrZeroRegistryNeverProjects(t *testing.T) {
	var nilReg *Registry
	if _, err := nilReg.Project("rawlen-v1", StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("a nil *Registry must never project (and must not panic)")
	}
	var zeroReg Registry
	if _, err := zeroReg.Project("rawlen-v1", StateArtifact{ScopeHash: "scope-1", Raw: []byte("x")}); err == nil {
		t.Fatal("a zero-value Registry (nil internal map) must never project")
	}
}

// TestRegistryHasNoExportedConstructorAcceptingProjectors documents, rather
// than tests at runtime (Go's type system already enforces it at compile
// time), the central claim this file makes: newRegistry is unexported, so
// this is the ONLY file in the ONLY package that can ever call it with
// arbitrary StateProjector values. Any other package — research, a future
// AI-glue file, a future Explorer variant — can only ever obtain a *Registry
// via DefaultRegistry(), which always contains this package's OWN concrete
// projectors, never a caller-supplied one.
func TestRegistryHasNoExportedConstructorAcceptingProjectors(t *testing.T) {
	reg := DefaultRegistry()
	if reg == nil {
		t.Fatal("DefaultRegistry must return a usable, non-nil Registry")
	}
}
