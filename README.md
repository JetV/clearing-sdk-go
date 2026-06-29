# clearing-sdk-go

[![Go Reference](https://pkg.go.dev/badge/github.com/JetV/clearing-sdk-go.svg)](https://pkg.go.dev/github.com/JetV/clearing-sdk-go)
[![CI](https://github.com/JetV/clearing-sdk-go/actions/workflows/ci.yml/badge.svg)](https://github.com/JetV/clearing-sdk-go/actions/workflows/ci.yml)

Official Go SDK for the **Clearing** economic-principal (EPID) service.

Clearing assigns every economic principal — humans, services, agents,
organizations, and providers — a stable **EPID** and a canonical kind, and exposes
signed, auditable operations for resolution, sourced writes, and identity
unification. This module is **self-contained**: the resilient resolver, the RSA
request-signing primitive, and the canonical-kind taxonomy are all vendored under
`internal/`, so it has no dependency on any private repository.

## Install

```bash
go get github.com/JetV/clearing-sdk-go
```

```go
import clearing "github.com/JetV/clearing-sdk-go"
```

## Capability tiers

The SDK is layered so each caller only takes the capability (and trust) it needs.
**The tier is the permission boundary** — constructing L2/L3 requires a source
identity and private key, so a read-only consumer cannot obtain write/unify
handles from the type system alone.

| Tier | Constructor | Capability |
| --- | --- | --- |
| L1 — read | `NewReadOnly(baseURL, opt)` | `Resolve` / `GetByEPID` / `Kinds` (cache + circuit breaker) |
| L2 — source | `NewSource(baseURL, sourceID, rsaKey, opt)` | source-signed `Ensure` / `Link` / `Affiliate` |
| L3 — unify | `NewUnify(baseURL, sourceID, rsaKey, opt)` | `ProveKey` / `SubmitVerifiedAttr` / `Bind` / `LinkRealm` |

## Quick start (L1, read-only)

```go
package main

import (
	"context"
	"fmt"
	"log"

	clearing "github.com/JetV/clearing-sdk-go"
)

func main() {
	c := clearing.NewReadOnly("https://clearing.internal", clearing.Options{})
	r, err := c.L1.Resolve(context.Background(), clearing.Identity{
		AuthInstanceID: "auth.local",
		Kind:           "user",
		Key:            "alice@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(r.EPID, r.CanonicalKind, r.Status)
}
```

## Resilience and degradation

The L1 read tier ships an in-process TTL cache, single-flight request
deduplication, and a circuit breaker. It distinguishes authoritative absence
(`ErrNotRegistered`, safe to treat as "not found") from transient unreachability
(`ErrUnavailable`) and **never silently fabricates a fallback** — the caller
decides fail-open vs fail-closed:

```go
switch {
case errors.Is(err, clearing.ErrNotRegistered):
	// principal is authoritatively absent
case errors.Is(err, clearing.ErrUnavailable):
	// clearing is unreachable / circuit open — you decide
}
```

`Kinds` is server-first with a compiled-in fallback; the result is flagged
`Degraded()` when it came from the fallback.

## Canonical JSON and signing

For source-signed writes (L2) and unify (L3) operations the SDK produces
deterministic canonical JSON (sorted keys, no insignificant whitespace, Go
`encoding/json` HTML escaping) and signs it with RS256 (RSA-PKCS1v15 + SHA-256),
base64-std. The three signing headers (`X-Clearing-Source`,
`X-Clearing-Signature`, `X-Clearing-Timestamp`), the Ed25519 challenge flow, and
the rule that an attribute assertion's `verifier_sig` is signed over the body
excluding itself are all handled for you. Signatures byte-match the
cross-language golden vectors shared by the Go / Python / TypeScript SDKs.

## Versioning

`ContractVersion` is the OpenAPI contract version this SDK targets. Construct any
client and call `Version()` to read it.

## License

[Apache-2.0](LICENSE)
