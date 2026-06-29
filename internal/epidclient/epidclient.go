// Package epidclient is the resilient EPID resolution client.
//
// Once clearing sits on the critical path of principal resolution for the whole
// ecosystem, every consumer calls it on hot paths. This package captures a
// resilience pattern so consumers do not each re-implement caching, retries, and
// circuit breaking:
//
//   - Local cache: resolution results carry a TTL (identity -> EPID rarely
//     changes, so it caches well).
//   - Single-flight: concurrent resolutions of the same key collapse into one
//     backend call.
//   - Circuit breaker: consecutive backend failures open the breaker for fast
//     failure plus half-open recovery.
//   - Degradation semantics: it clearly distinguishes "not registered"
//     (ErrNotRegistered) from "clearing temporarily unavailable"
//     (ErrUnavailable). The latter is never silently masked; the caller decides
//     fail-open vs fail-closed.
//
// This package is intentionally self-contained so it can be imported by any
// downstream repository.
package epidclient

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Degradation-semantics errors (the caller decides fail-open vs fail-closed).
var (
	// ErrNotRegistered means the principal is authoritatively not registered
	// (an authoritative 404, safe to cache as a negative result).
	ErrNotRegistered = errors.New("epidclient: principal not registered")
	// ErrUnavailable means clearing is temporarily unreachable (breaker open or
	// backend error) and is never silently masked.
	ErrUnavailable = errors.New("epidclient: clearing unavailable")
)

// Identity is the resolution input (a natural key; realm is not part of it).
type Identity struct {
	AuthInstanceID string
	Kind           string
	Key            string
}

func (i Identity) cacheKey() string {
	return i.AuthInstanceID + "\x1f" + i.Kind + "\x1f" + i.Key
}

// Result is the resolution result (the minimal active-principal projection).
type Result struct {
	EPID          string
	CanonicalKind string
	Status        string
}

// Backend is the underlying resolution transport (HTTP implementation or a test
// double).
type Backend interface {
	ResolveByIdentity(ctx context.Context, id Identity) (Result, error)
}

// Options configures the resilience parameters (zero values get industrial
// defaults).
type Options struct {
	TTL              time.Duration // positive-result cache TTL (default 5m)
	NegativeTTL      time.Duration // negative-result (not registered) cache TTL (default 30s)
	FailureThreshold int           // trip the breaker at this many consecutive failures (default 5)
	OpenTimeout      time.Duration // how long the breaker stays open (default 10s)
	Now              func() time.Time
}

func (o *Options) withDefaults() {
	if o.TTL <= 0 {
		o.TTL = 5 * time.Minute
	}
	if o.NegativeTTL <= 0 {
		o.NegativeTTL = 30 * time.Second
	}
	if o.FailureThreshold <= 0 {
		o.FailureThreshold = 5
	}
	if o.OpenTimeout <= 0 {
		o.OpenTimeout = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

type cacheEntry struct {
	res        Result
	registered bool
	expiresAt  time.Time
}

// Client is the resilient EPID resolution client.
type Client struct {
	backend Backend
	opt     Options

	mu    sync.RWMutex
	cache map[string]cacheEntry

	sf singleflightGroup
	br breaker
}

// New constructs a resilient client.
func New(backend Backend, opt Options) *Client {
	opt.withDefaults()
	return &Client{
		backend: backend,
		opt:     opt,
		cache:   make(map[string]cacheEntry),
		br:      breaker{threshold: opt.FailureThreshold, openTimeout: opt.OpenTimeout, now: opt.Now},
	}
}

// Resolve maps an external identity to its active principal (a cache hit returns
// directly; a miss goes through single-flight to the backend).
func (c *Client) Resolve(ctx context.Context, id Identity) (Result, error) {
	key := id.cacheKey()

	// 1. Cache hit (positive or negative result).
	if e, ok := c.lookup(key); ok {
		if e.registered {
			return e.res, nil
		}
		return Result{}, ErrNotRegistered
	}

	// 2. Breaker open -> fail fast (no silent fallback).
	if !c.br.allow() {
		return Result{}, ErrUnavailable
	}

	// 3. Single-flight: concurrent calls for the same key collapse into one
	//    backend call.
	v, err, _ := c.sf.Do(key, func() (any, error) {
		res, berr := c.backend.ResolveByIdentity(ctx, id)
		if berr != nil {
			if errors.Is(berr, ErrNotRegistered) {
				c.store(key, Result{}, false) // negative cache
				c.br.success()                // an authoritative 404 is not a backend failure
				return Result{}, ErrNotRegistered
			}
			c.br.failure()
			return Result{}, ErrUnavailable
		}
		c.store(key, res, true)
		c.br.success()
		return res, nil
	})
	if err != nil {
		return Result{}, err
	}
	return v.(Result), nil
}

// Invalidate evicts the cache entry for an identity (the caller clears hot
// entries after a known merge/link).
func (c *Client) Invalidate(id Identity) {
	c.mu.Lock()
	delete(c.cache, id.cacheKey())
	c.mu.Unlock()
}

func (c *Client) lookup(key string) (cacheEntry, bool) {
	c.mu.RLock()
	e, ok := c.cache[key]
	c.mu.RUnlock()
	if !ok {
		return cacheEntry{}, false
	}
	if c.opt.Now().After(e.expiresAt) {
		c.mu.Lock()
		delete(c.cache, key)
		c.mu.Unlock()
		return cacheEntry{}, false
	}
	return e, true
}

func (c *Client) store(key string, res Result, registered bool) {
	ttl := c.opt.TTL
	if !registered {
		ttl = c.opt.NegativeTTL
	}
	c.mu.Lock()
	c.cache[key] = cacheEntry{res: res, registered: registered, expiresAt: c.opt.Now().Add(ttl)}
	c.mu.Unlock()
}
