package stateauth

import "testing"

func TestHTTPStateProjectorDistinguishesSameLengthDifferentBody(t *testing.T) {
	p := HTTPStateProjector{}
	rawFalse, err := MarshalHTTPArtifact(HTTPArtifact{Status: 200, ContentType: "application/json", Body: []byte(`{"authenticated":false}`)})
	if err != nil {
		t.Fatal(err)
	}
	rawTrue, err := MarshalHTTPArtifact(HTTPArtifact{Status: 200, ContentType: "application/json", Body: []byte(`{"authenticated":true_}`)}) // same length (24 bytes) as the false-body above, deliberately
	if err != nil {
		t.Fatal(err)
	}

	fpFalse, err := p.Project(StateArtifact{ScopeHash: "scope-1", Raw: rawFalse})
	if err != nil {
		t.Fatal(err)
	}
	fpTrue, err := p.Project(StateArtifact{ScopeHash: "scope-1", Raw: rawTrue})
	if err != nil {
		t.Fatal(err)
	}
	if fpFalse.StateFingerprintHash() == fpTrue.StateFingerprintHash() {
		t.Fatal("HTTPStateProjector must distinguish different body content even at the same length — this is exactly what RawLenProjector cannot do")
	}
	if fpFalse.Facts()["status"] != "200" {
		t.Fatalf("Facts()[status] = %q, want 200", fpFalse.Facts()["status"])
	}
	if fpFalse.Facts()["content_type"] != "application/json" {
		t.Fatalf("Facts()[content_type] = %q, want application/json", fpFalse.Facts()["content_type"])
	}
	if fpFalse.Facts()["body_sha256"] == "" {
		t.Fatal("Facts()[body_sha256] must be populated")
	}
}

func TestHTTPStateProjectorDeterministic(t *testing.T) {
	p := HTTPStateProjector{}
	raw, err := MarshalHTTPArtifact(HTTPArtifact{Status: 200, ContentType: "text/plain", Body: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	fp1, err := p.Project(StateArtifact{ScopeHash: "scope-1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := p.Project(StateArtifact{ScopeHash: "scope-1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if fp1.StateFingerprintHash() != fp2.StateFingerprintHash() {
		t.Fatal("identical raw artifacts must project identically")
	}
}

func TestHTTPStateProjectorRejectsMalformedRaw(t *testing.T) {
	p := HTTPStateProjector{}
	if _, err := p.Project(StateArtifact{ScopeHash: "scope-1", Raw: []byte("not json")}); err == nil {
		t.Fatal("malformed StateArtifact.Raw must be rejected, never partially projected")
	}
}

func TestHTTPFixtureRegistryProjectsHTTPStateProjector(t *testing.T) {
	reg := HTTPFixtureRegistry()
	raw, err := MarshalHTTPArtifact(HTTPArtifact{Status: 404, ContentType: "text/plain", Body: []byte("not found")})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := reg.Project(StateArtifact{ScopeHash: "scope-1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if fp.ProjectorID() != "http-v1" {
		t.Fatalf("ProjectorID() = %q, want http-v1", fp.ProjectorID())
	}
	if fp.Facts()["status"] != "404" {
		t.Fatalf("Facts()[status] = %q, want 404", fp.Facts()["status"])
	}
}
