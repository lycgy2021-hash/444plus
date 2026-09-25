// Package assesscache memoizes a product's shared assessment (fingerprint,
// version, protocol/service exposure) for the lifetime of a single scan, so a
// product's many CVE checkers reuse one assessment instead of re-probing the
// target N times. It caches assessments, never final verdicts. The cache flows
// through context.Context, so checkers opt in without constructor changes.
package assesscache

import (
	"context"
	"sync"
)

// Key identifies one shared assessment: a target, a product, and an optional
// scope (e.g. a mode), so different scopes do not collide.
type Key struct {
	Target  string
	Product string
	Scope   string
}

type entry struct {
	once sync.Once
	val  any
}

type Cache struct {
	mu      sync.Mutex
	entries map[Key]*entry
}

func New() *Cache { return &Cache{entries: map[Key]*entry{}} }

// GetOrRun returns the cached assessment for key, running run exactly once per
// key across concurrent callers. run must return the product's assessment value.
func (c *Cache) GetOrRun(key Key, run func() any) any {
	c.mu.Lock()
	e := c.entries[key]
	if e == nil {
		e = &entry{}
		c.entries[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val = run() })
	return e.val
}

// Len reports how many distinct assessments were computed (for reporting/metrics).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

type ctxKey struct{}

// With attaches a cache to ctx. From returns it, or nil if absent (callers then
// run their assessment directly, uncached).
func With(ctx context.Context, c *Cache) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

func From(ctx context.Context) *Cache {
	c, _ := ctx.Value(ctxKey{}).(*Cache)
	return c
}
