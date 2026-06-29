package clearing

import (
	"context"
	"sync"
	"time"

	"github.com/JetV/clearing-sdk-go/internal/canonicalkind"
)

// kindsCache caches GET /v1/kinds. On an unreachable server it falls back to the
// compiled-in canonicalkind mapping and flags the result degraded (U4) — the
// server remains authoritative; the fallback is a last resort with a TTL.
type kindsCache struct {
	ttl time.Duration
	now func() time.Time

	mu        sync.RWMutex
	mapping   map[string]string
	expiresAt time.Time
	degraded  bool // last result came from the compiled-in fallback
}

func newKindsCache(ttl time.Duration, now func() time.Time) *kindsCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &kindsCache{ttl: ttl, now: now}
}

// get returns the external→canonical kind mapping, server-first with cache, and
// compiled-in fallback if clearing is unreachable.
func (k *kindsCache) get(ctx context.Context, tr *transport) (map[string]string, error) {
	k.mu.RLock()
	if k.mapping != nil && k.now().Before(k.expiresAt) {
		m := cloneMap(k.mapping)
		k.mu.RUnlock()
		return m, nil
	}
	k.mu.RUnlock()

	var out struct {
		Kinds   []string          `json:"kinds"`
		Mapping map[string]string `json:"mapping"`
	}
	err := tr.getJSON(ctx, "/v1/kinds", &out)
	if err == nil && len(out.Mapping) > 0 {
		k.store(out.Mapping, false)
		return cloneMap(out.Mapping), nil
	}

	// Fallback: compiled-in mapping (degraded). Never silently authoritative.
	fb := compiledMapping()
	k.store(fb, true)
	return cloneMap(fb), nil
}

func (k *kindsCache) store(m map[string]string, degraded bool) {
	k.mu.Lock()
	k.mapping = m
	k.degraded = degraded
	k.expiresAt = k.now().Add(k.ttl)
	k.mu.Unlock()
}

// Degraded reports whether the last Kinds result came from the compiled-in
// fallback (clearing was unreachable).
func (k *kindsCache) Degraded() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.degraded
}

func compiledMapping() map[string]string {
	src := canonicalkind.Mapping()
	out := make(map[string]string, len(src))
	for ext, canon := range src {
		out[ext] = string(canon)
	}
	return out
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for kk, vv := range m {
		out[kk] = vv
	}
	return out
}
