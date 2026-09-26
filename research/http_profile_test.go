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
