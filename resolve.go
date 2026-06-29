package clearing

import (
	"context"

	"github.com/JetV/clearing-sdk-go/internal/epidclient"
)

// ResolveClient is the L1 read tier. It is a thin facade over epidclient.Client
// (cache + single-flight + circuit breaker), so it inherits the resilience and
// degradation semantics verified there — no rewrite (AC-GOSDK-001).
type ResolveClient struct {
	inner *epidclient.Client
	kinds *kindsCache
	tr    *transport
}

// Resolve maps an external identity to its active EPID (following merges).
// Returns ErrNotRegistered (safe to treat as absent) or ErrUnavailable (do not
// silently fabricate) per the resilience contract.
func (c *ResolveClient) Resolve(ctx context.Context, id Identity) (Resolved, error) {
	r, err := c.inner.Resolve(ctx, epidclient.Identity(id))
	if err != nil {
		return Resolved{}, mapErr(err)
	}
	return Resolved{EPID: r.EPID, CanonicalKind: r.CanonicalKind, Status: r.Status}, nil
}

// GetByEPID fetches the active principal for an EPID (follows merges). It bypasses
// the identity cache (different key space) and calls GET /v1/principals/:epid.
func (c *ResolveClient) GetByEPID(ctx context.Context, epid string) (Resolved, error) {
	var out struct {
		EPID          string `json:"epid"`
		CanonicalKind string `json:"canonical_kind"`
		Status        string `json:"status"`
	}
	if err := c.tr.getJSON(ctx, "/v1/principals/"+epid, &out); err != nil {
		return Resolved{}, err
	}
	return Resolved{EPID: out.EPID, CanonicalKind: out.CanonicalKind, Status: out.Status}, nil
}

// Kinds returns the authoritative external→canonical kind mapping (cached). On
// unreachable server it falls back to the compiled-in canonicalkind table and
// records that the result is degraded (see kinds.go).
func (c *ResolveClient) Kinds(ctx context.Context) (map[string]string, error) {
	return c.kinds.get(ctx, c.tr)
}

// Invalidate drops the cached resolution for an identity (after a known
// merge/link, callers clear the hot entry).
func (c *ResolveClient) Invalidate(id Identity) { c.inner.Invalidate(epidclient.Identity(id)) }
