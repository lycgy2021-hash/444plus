package weblogic

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// countingProbe counts TCP and GET calls to prove the shared assessment cache
// collapses N CVE checkers into one probe set.
type countingProbe struct {
	tcp, get *atomic.Int32
	t3       []byte
}

func (m countingProbe) Get(_ context.Context, _ model.Target, _ string) (httpx.Response, error) {
	m.get.Add(1)
	return httpx.Response{StatusCode: 200, Headers: map[string]string{}}, nil
}
func (m countingProbe) TCP(_ context.Context, _ model.Target, payload []byte, _ int) ([]byte, error) {
	m.tcp.Add(1)
	if bytes.HasPrefix(payload, []byte("t3 ")) {
		return m.t3, nil
	}
	return nil, nil
}
func (m countingProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m countingProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m countingProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}

func TestSharedAssessmentCache(t *testing.T) {
	var tcp, get atomic.Int32
	probe := countingProbe{tcp: &tcp, get: &get, t3: []byte("HELO:12.2.1.3.0.false\nAS:2048\n\n")}
	target, _ := model.ParseTarget("http://127.0.0.1:7001")
	checkers := []*advisoryChecker{
		NewCVE202321839(probe), NewCVE202660198(probe), NewCVE202660199(probe), NewCVE202660200(probe),
		NewCVE202660202(probe), NewCVE202660291(probe), NewCVE202660292(probe), NewCVE202660294(probe),
	}
	// Shared cache: assess runs ONCE for all 8. doAssess = T3 + IIOP (2 TCP) and
	// /console + 2 SOAP endpoints (3 GET).
	ctx := assesscache.With(context.Background(), assesscache.New())
	for _, c := range checkers {
		c.Check(ctx, target)
	}
	if tcp.Load() != 2 || get.Load() != 3 {
		t.Fatalf("shared cache: tcp=%d get=%d, want 2 and 3 (one assessment for 8 CVEs)", tcp.Load(), get.Load())
	}
	// Without a cache, each checker probes independently: 8x.
	tcp.Store(0)
	get.Store(0)
	for _, c := range checkers {
		c.Check(context.Background(), target)
	}
	if tcp.Load() != 16 || get.Load() != 24 {
		t.Fatalf("uncached should be 8x: tcp=%d get=%d, want 16 and 24", tcp.Load(), get.Load())
	}
}

// mockProbe implements httpx.Probe with canned HTTP and T3 responses, so the
// multi-protocol ladder can be driven without a live WebLogic.
type mockProbe struct {
	consoleStatus int
	consoleBody   string
	t3Resp        []byte // reply to the t3 handshake ("" = no HELO)
}

func (m mockProbe) Get(_ context.Context, _ model.Target, path string) (httpx.Response, error) {
	if path == "/console" {
		return httpx.Response{StatusCode: m.consoleStatus, Body: []byte(m.consoleBody), Headers: map[string]string{}}, nil
	}
	return httpx.Response{StatusCode: 404, Headers: map[string]string{}}, nil // SOAP endpoints absent
}
func (m mockProbe) TCP(_ context.Context, _ model.Target, payload []byte, _ int) ([]byte, error) {
	if bytes.HasPrefix(payload, []byte("t3 ")) {
		return m.t3Resp, nil
	}
	return nil, nil // GIOP: no reply
}
func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}

func TestWebLogicLadder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:7001")
	cases := []struct {
		name   string
		probe  mockProbe
		want   model.Verdict
		reason string
	}{
		{"not_weblogic", mockProbe{200, "<html>welcome to nginx</html>", nil}, model.VerdictNotFound, "product_not_weblogic"},
		{"version_unknown", mockProbe{200, "<html>WebLogic Server Console /console/</html>", nil}, model.VerdictUnknown, "version_unknown"},
		{"not_affected", mockProbe{302, "", []byte("HELO:12.2.2.0.0.false\nAS:2048\n\n")}, model.VerdictNotFound, "version_not_affected"},
		{"likely_t3", mockProbe{302, "", []byte("HELO:12.2.1.3.0.false\nAS:2048\n\n")}, model.VerdictLikely, "dangerous_protocol_exposed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewCVE202321839(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s: %+v", f.Verdict, f.Reason, tc.want, tc.reason, f)
			}
			if f.Verdict == model.VerdictConfirmed {
				t.Fatal("weblogic advisory must not confirm")
			}
		})
	}
}

// The CPU-2026-07 batch: HTTP surface reaches likely; SOAP surface stays
// detected when no WS endpoint is exposed; version matrix discriminates.
func TestCPU202607(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:7001")
	v1414 := mockProbe{302, "", []byte("HELO:12.2.1.4.0.false\nAS:2048\n\n")}
	v1412 := mockProbe{302, "", []byte("HELO:14.1.2.0.0.false\nAS:2048\n\n")}
	v1213 := mockProbe{302, "", []byte("HELO:12.2.1.3.0.false\nAS:2048\n\n")}
	cases := []struct {
		name   string
		mk     func(httpx.Probe) *advisoryChecker
		probe  mockProbe
		want   model.Verdict
		reason string
	}{
		{"http_likely", NewCVE202660199, v1414, model.VerdictLikely, "dangerous_protocol_exposed"},
		{"soap_detected", NewCVE202660200, v1414, model.VerdictDetected, "affected_version"}, // WS endpoints 404 -> surface not reached
		{"limited_not_1412", NewCVE202660292, v1412, model.VerdictNotFound, "version_not_affected"},
		{"t3iiop_not_1213", NewCVE202660198, v1213, model.VerdictNotFound, "version_not_affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.mk(tc.probe).Check(context.Background(), target)
			if f.Verdict != tc.want || f.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s", f.Verdict, f.Reason, tc.want, tc.reason)
			}
		})
	}
}

func TestAffectedBaseReleases(t *testing.T) {
	for _, v := range []string{"12.2.1.3.0", "12.2.1.4.0", "10.3.6.0", "14.1.1.0.0", "12.1.3.0.0"} {
		if !affected(v, affected21839) {
			t.Errorf("%s should be affected", v)
		}
	}
	for _, v := range []string{"12.2.2.0.0", "14.1.2.0.0", "12.2.1.30.0"} {
		if affected(v, affected21839) {
			t.Errorf("%s should not be affected", v)
		}
	}
}
