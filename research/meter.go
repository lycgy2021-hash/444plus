package research

import (
	"context"
	"fmt"
	"sync"
)

// RequestMeter bounds the TOTAL number of real I/O operations exploration
// may perform. Explorer attaches one to ctx (via ContextWithRequestMeter)
// before every Collector/Executor call; a real implementation making actual
// network/file/process requests MUST call Acquire before EACH ONE it
// issues — not once per Collect/Execute/ExecuteRecovery call, but once per
// actual request, however many that turns out to be. This is what makes
// ExplorationBudget.MaxRequests bound REAL I/O rather than a guessed
// per-method-call cost Explorer itself has no way to verify: an earlier
// version of this file had Explorer itself increment a counter by a fixed
// amount per Step/Recover call (3 and 2) — that assumption breaks the
// moment a real Collector's single Collect() call turns out to issue
// several actual HTTP requests internally (a status check, a session
// check, a metadata fetch), or an Executor retries once. Explorer no longer
// guesses; it only ever reads Used() for a fail-fast check, and the actual
// count comes entirely from real I/O code calling Acquire().
type RequestMeter interface {
	// Acquire consumes one unit of request budget. It returns an error,
	// never blocks, once the budget is exhausted — the caller must stop
	// issuing further requests and propagate the error up (a Collect or
	// Execute implementation should return it as its own error).
	Acquire() error
	// Used reports how many units have been acquired so far.
	Used() int
}

type requestMeterKey struct{}

// ContextWithRequestMeter attaches meter to ctx so a Collector/Executor
// implementation, however deep in its own call chain (an HTTP transport, a
// retry wrapper), can retrieve it via RequestMeterFromContext and account
// for every real request it actually issues.
func ContextWithRequestMeter(ctx context.Context, meter RequestMeter) context.Context {
	return context.WithValue(ctx, requestMeterKey{}, meter)
}

// RequestMeterFromContext retrieves the RequestMeter Explorer attached to
// ctx, or nil if none is present (e.g. a caller that does not meter, or a
// context that was never derived from one Explorer built). A cooperative
// implementation should treat a nil meter as "no metering configured" —
// never as licence to skip accounting when one IS present.
func RequestMeterFromContext(ctx context.Context) RequestMeter {
	m, _ := ctx.Value(requestMeterKey{}).(RequestMeter)
	return m
}

// boundedRequestMeter is Explorer's own concrete RequestMeter: a hard cap,
// enforced by Acquire itself the instant it is reached, never by a caller's
// own bookkeeping after the fact.
type boundedRequestMeter struct {
	mu   sync.Mutex
	max  int
	used int
}

func newBoundedRequestMeter(max int) *boundedRequestMeter {
	return &boundedRequestMeter{max: max}
}

func (m *boundedRequestMeter) Acquire() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.used >= m.max {
		return fmt.Errorf("%w: request meter exhausted (%d/%d)", ErrBudgetExceeded, m.used, m.max)
	}
	m.used++
	return nil
}

func (m *boundedRequestMeter) Used() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.used
}
