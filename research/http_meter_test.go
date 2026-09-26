package research

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestBudgetedRoundTripperMetersAndBlocksBeforeNetwork is the direct proof
// for the S10-E4h fix: the choke point must stop a request BEFORE it ever
// reaches the network, once the attached RequestMeter is exhausted — not
// merely count requests after the fact. A real server records how many
// requests it actually received; that count must match the meter's bound,
// not the number of times this test attempted a call.
func TestBudgetedRoundTripperMetersAndBlocksBeforeNetwork(t *testing.T) {
	var served int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&served, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	meter := newBoundedRequestMeter(2)
	client := &http.Client{Transport: &BudgetedRoundTripper{}}

	do := func() error {
		req, err := http.NewRequestWithContext(ContextWithRequestMeter(context.Background(), meter), http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	if err := do(); err != nil {
		t.Fatalf("first request within budget must succeed: %v", err)
	}
	if err := do(); err != nil {
		t.Fatalf("second request within budget must succeed: %v", err)
	}
	if err := do(); err == nil {
		t.Fatal("a third request past a MaxRequests-equivalent of 2 must fail")
	}
	if served != 2 {
		t.Fatalf("server received %d requests, want exactly 2 — the third must be blocked BEFORE reaching the network, not merely counted after", served)
	}
	if meter.Used() != 2 {
		t.Fatalf("meter.Used() = %d, want 2 (the blocked third attempt must not itself consume budget)", meter.Used())
	}
}

// TestBudgetedRoundTripperFailsClosedWithoutMeter is the direct regression
// test for the audit's one remaining ask on E4h: a request whose context
// carries NO RequestMeter must be refused outright, never quietly performed
// unmetered. Without this, a future real Collector that built its
// *http.Request with plain http.NewRequest (instead of
// http.NewRequestWithContext(ctx, ...) using the context Explorer actually
// attached a meter to) would silently escape MaxRequests entirely, even
// with BudgetedRoundTripper installed as its Transport — the choke point
// only works if "missing meter" means "refuse", not "proceed anyway".
func TestBudgetedRoundTripperFailsClosedWithoutMeter(t *testing.T) {
	var served int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&served, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	base := &fakeBaseRoundTripper{}
	client := &http.Client{Transport: &BudgetedRoundTripper{Base: base}}
	_, err := client.Get(ts.URL)
	if !errors.Is(err, ErrNoRequestMeter) {
		t.Fatalf("a request with no meter attached = %v, want it to wrap ErrNoRequestMeter", err)
	}
	if served != 0 {
		t.Fatalf("server received %d requests, want 0 — a request with no meter must never reach the network", served)
	}
	if atomic.LoadInt32(&base.calls) != 0 {
		t.Fatalf("base.calls = %d, want 0 — Base.RoundTrip must never be called when the meter is missing", base.calls)
	}
}

// fakeBaseRoundTripper is a minimal RoundTripper test double proving
// BudgetedRoundTripper actually delegates to a caller-supplied Base rather
// than always using http.DefaultTransport.
type fakeBaseRoundTripper struct {
	calls int32
}

func (f *fakeBaseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&f.calls, 1)
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
}

func TestBudgetedRoundTripperUsesProvidedBase(t *testing.T) {
	base := &fakeBaseRoundTripper{}
	rt := &BudgetedRoundTripper{Base: base}
	meter := newBoundedRequestMeter(1)
	req, err := http.NewRequestWithContext(ContextWithRequestMeter(context.Background(), meter), http.MethodGet, "http://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&base.calls) != 1 {
		t.Fatalf("base.calls = %d, want 1 — BudgetedRoundTripper must delegate to the provided Base", base.calls)
	}
}
