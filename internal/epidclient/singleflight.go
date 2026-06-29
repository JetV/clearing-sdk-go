package epidclient

import "sync"

// singleflightGroup 合并对同一 key 的并发调用为一次执行（等价 golang.org/x/sync
// 的最小子集），使本模块零运行时外部依赖。
type singleflightGroup struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

// Do 执行并去重 fn:同一 key 的并发调用只执行一次,其余等待并共享结果。
// 返回的 shared 表示结果是否被多个调用方共享。
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
