package research

import "net/http"

// BudgetedRoundTripper wraps an http.RoundTripper so that EVERY actual HTTP
// round trip is metered by whatever RequestMeter is attached to the
// request's own context — a real I/O CHOKE POINT, not something a
// Collector/Executor implementation could forget to call.
//
// The gap this closes: RequestMeter (meter.go) is otherwise purely
// cooperative — a real Collector/Executor implementation is supposed to
// call Acquire before each actual request it issues, but nothing stops one
// from forgetting to, or from calling it once while actually issuing two
// requests (a retry, a redirect follow-up). ExplorationBudget.MaxRequests
// would then bound "however diligent the implementation happened to be",
// not real I/O — silently reopening the same "guessed cost" problem
// S10-E4f closed at the Explorer level, one layer further down.
//
// BudgetedRoundTripper closes it for HTTP specifically: any future
// HTTP-based Collector/Executor/recovery implementation MUST build its
// *http.Client with this as its Transport (never a bare http.Client using
// http.DefaultTransport directly) and issue every request via
// http.NewRequestWithContext(ctx, ...) using the SAME ctx Explorer passed
// it (which already carries the RequestMeter via ContextWithRequestMeter).
// Metering then happens at the actual network call, regardless of whether
// the business logic on top remembers to call Acquire itself — a forgotten
// or miscounted Acquire in the Collector's own code no longer matters, and
// neither does an internal retry: every RoundTrip is metered, including
// ones the calling code didn't know it was making.
type BudgetedRoundTripper struct {
	// Base is the underlying RoundTripper actually used to perform a request
	// once budget is acquired. A nil Base defaults to http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip acquires one unit of request budget from the RequestMeter
// attached to req's own context (see RequestMeterFromContext) BEFORE
// forwarding to Base — a request refused here never reaches the network at
// all. If no meter is attached (e.g. a caller not going through Explorer),
// RoundTrip performs the request unmetered — the same "cooperative when
// absent" fallback RequestMeterFromContext documents.
func (t *BudgetedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if meter := RequestMeterFromContext(req.Context()); meter != nil {
		if err := meter.Acquire(); err != nil {
			return nil, err
		}
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
