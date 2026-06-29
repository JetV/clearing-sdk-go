package epidclient

import (
	"sync"
	"time"
)

// breaker is a minimal three-state circuit breaker
// (closed -> open -> half-open -> closed/open).
//
//   - closed:    requests pass; consecutive failures reaching threshold -> open.
//   - open:      every request fails fast until openTimeout elapses, then it
//     transitions to half-open (one probe is admitted).
//   - half-open: a successful probe -> closed (reset); a failed probe -> open.
type breaker struct {
	threshold   int
	openTimeout time.Duration
	now         func() time.Time

	mu          sync.Mutex
	failures    int
	state       breakerState
	openedAt    time.Time
	halfOpenOne bool // whether the half-open probe has already been admitted
}

type breakerState int

const (
	stateClosed breakerState = iota
	stateOpen
	stateHalfOpen
)

// allow reports whether this request may proceed.
func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case stateClosed:
		return true
	case stateOpen:
		if b.now().Sub(b.openedAt) >= b.openTimeout {
			b.state = stateHalfOpen
			b.halfOpenOne = true
			return true // admit one probe
		}
		return false
	case stateHalfOpen:
		if b.halfOpenOne {
			b.halfOpenOne = false
			return true
		}
		return false
	}
	return true
}

// success records a success (or an authoritative 404).
func (b *breaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.state = stateClosed
	b.halfOpenOne = false
}

// failure records a backend failure, tripping the breaker when warranted.
func (b *breaker) failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == stateHalfOpen {
		b.trip()
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.trip()
	}
}

func (b *breaker) trip() {
	b.state = stateOpen
	b.openedAt = b.now()
	b.halfOpenOne = false
}
