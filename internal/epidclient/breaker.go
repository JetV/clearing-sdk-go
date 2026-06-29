package epidclient

import (
	"sync"
	"time"
)

// breaker 是一个最小三态断路器（closed -> open -> half-open -> closed/open）。
//
//   - closed：正常放行；连续失败计数达到 threshold → open。
//   - open：在 openTimeout 内一律快速失败；超时后进入 half-open（放行一次探测）。
//   - half-open：探测成功 → closed（清零）；探测失败 → 重新 open。
type breaker struct {
	threshold   int
	openTimeout time.Duration
	now         func() time.Time

	mu          sync.Mutex
	failures    int
	state       breakerState
	openedAt    time.Time
	halfOpenOne bool // half-open 阶段是否已放出探测
}

type breakerState int

const (
	stateClosed breakerState = iota
	stateOpen
	stateHalfOpen
)

// allow 是否放行本次请求。
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
			return true // 放出一次探测
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

// success 记录一次成功（或权威 404）。
func (b *breaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.state = stateClosed
	b.halfOpenOne = false
}

// failure 记录一次后端故障，必要时打开断路器。
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
