package stateauth

import "testing"

func TestRawLenProjectorIsDeterministic(t *testing.T) {
	var p StateProjector = RawLenProjector{}
	if p.ID() != "rawlen-v1" {
		t.Fatalf("ID() = %q", p.ID())
	}
	fp1, err := p.Project(StateArtifact{ScopeHash: "s1", Raw: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := p.Project(StateArtifact{ScopeHash: "s1", Raw: []byte("world")}) // same length, different bytes
	if err != nil {
		t.Fatal(err)
	}
	if fp1.StateFingerprintHash() != fp2.StateFingerprintHash() {
		t.Fatal("RawLenProjector's fact is length-only: same-length raw input must project to the same StateFingerprintHash")
	}
	if fp1.RawStateArtifactHash() == fp2.RawStateArtifactHash() {
		t.Fatal("different raw bytes must still change RawStateArtifactHash even when the projected fact is identical")
	}
	fp3, _ := p.Project(StateArtifact{ScopeHash: "s1", Raw: []byte("hi")})
	if fp3.StateFingerprintHash() == fp1.StateFingerprintHash() {
		t.Fatal("a different raw length must change StateFingerprintHash")
	}
	if fp1.ProjectorID() != "rawlen-v1" {
		t.Fatalf("ProjectorID() = %q, want rawlen-v1", fp1.ProjectorID())
	}
}
