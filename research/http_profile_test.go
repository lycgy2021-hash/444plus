package research

import "testing"

func TestNewHTTPProfileBuildsCollectorAndExecutorFromSameOrigin(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	scope := ExplorationScope{TargetID: "e5-fixture"}
	profile, err := NewHTTPProfile(scope, ts.URL, "/state", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Scope() != scope {
		t.Fatalf("Scope() = %+v, want %+v", profile.Scope(), scope)
	}
	if profile.Collector() == nil || profile.Executor() == nil {
		t.Fatal("Collector() and Executor() must both be non-nil")
	}
}

func TestNewHTTPProfileRejectsInvalidBaseURLOrActions(t *testing.T) {
	scope := ExplorationScope{TargetID: "e5-fixture"}
	if _, err := NewHTTPProfile(scope, "http://[::1", "/state", map[string]string{"a": "/"}); err == nil {
		t.Fatal("an invalid baseURL must be refused")
	}
	if _, err := NewHTTPProfile(scope, "http://example.invalid", "/state", nil); err == nil {
		t.Fatal("an empty actions map must be refused (HTTPExecutor requires at least one)")
	}
}

// TestHTTPProfileOriginIDIsPureFunctionOfBaseURL is the direct proof
// OriginID() is a pure function of baseURL alone — never affected by
// observationPath, the actions map, or the ExplorationScope a caller pairs
// it with — and that two DIFFERENT real origins (different ports on the
// same host, from two independent fixture servers) produce different
// values. See S10/E8's "same-target physical binding" freeze item.
func TestHTTPProfileOriginIDIsPureFunctionOfBaseURL(t *testing.T) {
	ts := newHTTPFixtureServer(t)

	p1, err := NewHTTPProfile(ExplorationScope{TargetID: "a"}, ts.URL, "/state", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NewHTTPProfile(ExplorationScope{TargetID: "b"}, ts.URL, "/health", map[string]string{"get-health": "/health"})
	if err != nil {
		t.Fatal(err)
	}
	if p1.OriginID() == "" {
		t.Fatal("OriginID() must not be empty for a real baseURL")
	}
	if p1.OriginID() != p2.OriginID() {
		t.Fatalf("two profiles built from the SAME baseURL must share an OriginID regardless of scope/observationPath/actions: %q != %q", p1.OriginID(), p2.OriginID())
	}

	other := newHTTPFixtureServer(t) // a genuinely different origin (different random port)
	p3, err := NewHTTPProfile(ExplorationScope{TargetID: "a"}, other.URL, "/state", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	if p1.OriginID() == p3.OriginID() {
		t.Fatalf("two profiles built from DIFFERENT real origins must have different OriginID values, got the same %q for both", p1.OriginID())
	}
}
