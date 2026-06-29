package epidclient

import "sync"

// singleflightGroup collapses concurrent calls for the same key into a single
// execution (a minimal subset of golang.org/x/sync/singleflight), keeping this
// module free of runtime external dependencies.
type singleflightGroup struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

// Do executes and de-duplicates fn: concurrent calls for the same key run fn
// only once, and the rest wait for and share the result. The returned shared
// flag reports whether the result was shared by more than one caller.
func (g *singleflightGroup) Do(key string, fn func() (any, error)) (val any, err error, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sfCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}
	c := new(sfCall)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err, false
}
