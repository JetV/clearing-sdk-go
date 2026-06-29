// Package epidclient 是官方弹性 EPID 解析客户端（F5）。
//
// clearing 一旦成为全生态主体解析的关键路径，所有消费方（JetForge / billing / jetagents）
// 都会在热路径上调它。本 SDK 把 JETP-110 在 jetagents 侧验证的弹性范式沉淀为共享组件，
// 杜绝每个消费方重写缓存/重试/熔断的技术债：
//
//   - 本地缓存：解析结果带 TTL（身份→EPID 基本不变，适合缓存）。
//   - single-flight：同一 key 并发解析合并为一次后端调用。
//   - 熔断：后端连续失败打开断路器，快速失败 + 半开恢复。
//   - 降级语义：明确区分"未登记(ErrNotRegistered)"与"clearing 暂不可达
//     (ErrUnavailable)"——后者不静默兜底，由调用方决定 fail-open/closed。
//
// 本包刻意自包含（不依赖 clearing/internal），以便被任意下游仓 import。
package epidclient

import (
	"context"
	"errors"
	"sync"
	"time"
)

// 降级语义错误（调用方据此决定 fail-open/closed）。
var (
	// ErrNotRegistered 主体确实未登记（权威 404，可安全缓存为负结果）。
	ErrNotRegistered = errors.New("epidclient: principal not registered")
	// ErrUnavailable clearing 暂不可达（熔断打开或后端错误）——不静默兜底。
	ErrUnavailable = errors.New("epidclient: clearing unavailable")
)

// Identity 是解析输入（自然键，realm 不在其中，F1）。
type Identity struct {
	AuthInstanceID string
	Kind           string
	Key            string
}

func (i Identity) cacheKey() string {
	return i.AuthInstanceID + "\x1f" + i.Kind + "\x1f" + i.Key
}

// Result 是解析结果（活跃主体的最小投影）。
type Result struct {
	EPID          string
	CanonicalKind string
	Status        string
}

// Backend 是底层解析传输（HTTP 实现或测试替身）。
type Backend interface {
	ResolveByIdentity(ctx context.Context, id Identity) (Result, error)
}

// Options 配置弹性参数（零值有工业默认）。
type Options struct {
	TTL              time.Duration // 正结果缓存 TTL（默认 5m）
	NegativeTTL      time.Duration // 负结果（未登记）缓存 TTL（默认 30s）
	FailureThreshold int           // 连续失败达到即熔断（默认 5）
	OpenTimeout      time.Duration // 断路器打开持续时间（默认 10s）
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

// Client 是弹性 EPID 解析客户端。
type Client struct {
	backend Backend
	opt     Options

	mu    sync.RWMutex
	cache map[string]cacheEntry

	sf singleflightGroup
	br breaker
}

// New 构造弹性客户端。
func New(backend Backend, opt Options) *Client {
	opt.withDefaults()
	return &Client{
		backend: backend,
		opt:     opt,
		cache:   make(map[string]cacheEntry),
		br:      breaker{threshold: opt.FailureThreshold, openTimeout: opt.OpenTimeout, now: opt.Now},
	}
}

// Resolve 解析外部身份到活跃主体（缓存命中直接返回；未命中经 single-flight 调后端）。
func (c *Client) Resolve(ctx context.Context, id Identity) (Result, error) {
	key := id.cacheKey()

	// 1. 缓存命中（正/负结果）。
	if e, ok := c.lookup(key); ok {
		if e.registered {
			return e.res, nil
		}
		return Result{}, ErrNotRegistered
	}

	// 2. 熔断打开 → 快速失败（不静默兜底）。
	if !c.br.allow() {
		return Result{}, ErrUnavailable
	}

	// 3. single-flight：同 key 并发合并为一次后端调用。
	v, err, _ := c.sf.Do(key, func() (any, error) {
		res, berr := c.backend.ResolveByIdentity(ctx, id)
		if berr != nil {
			if errors.Is(berr, ErrNotRegistered) {
				c.store(key, Result{}, false) // 负缓存
				c.br.success()                // 权威 404 不算后端故障
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

// Invalidate 失效某身份的缓存（merge/link 后由调用方主动清理热点）。
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
