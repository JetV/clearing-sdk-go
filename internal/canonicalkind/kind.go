// Package canonicalkind is the single authoritative taxonomy of economic
// principal kinds (defined by Clearing, one source of truth).
//
// A kind describes economic capacity (who may hold a wallet, who may receive
// payment, who may be transacted with). It is clearing-layer semantics and is
// defined exactly once here so every repository references this one mapping
// instead of re-deriving it.
package canonicalkind

import "fmt"

// CanonicalKind is a normalized economic principal kind.
type CanonicalKind string

// The five first-class economic principal kinds.
const (
	KindHuman    CanonicalKind = "human"    // natural person
	KindAgent    CanonicalKind = "agent"    // autonomous agent (can hold a wallet, can be transacted with)
	KindService  CanonicalKind = "service"  // system/client service
	KindProvider CanonicalKind = "provider" // resource/capability provider (revenue wallet)
	KindOrg      CanonicalKind = "org"      // organization/team/project (shared-account principal)
)

// All returns every canonical kind in stable order (for GET /v1/kinds).
func All() []CanonicalKind {
	return []CanonicalKind{KindHuman, KindAgent, KindService, KindProvider, KindOrg}
}

// externalToCanonical is the single derivation table from external kind (the
// shape used in auth source tokens) to canonical kind.
var externalToCanonical = map[string]CanonicalKind{
	"user":     KindHuman,
	"client":   KindService,
	"agent":    KindAgent,
	"realm":    KindOrg,
	"provider": KindProvider,
}

// Mapping returns a copy of the external -> canonical mapping (for GET /v1/kinds
// and downstream references).
func Mapping() map[string]CanonicalKind {
	out := make(map[string]CanonicalKind, len(externalToCanonical))
	for k, v := range externalToCanonical {
		out[k] = v
	}
	return out
}

// ErrUnknownKind indicates the external kind is unknown (no silent fallback).
var ErrUnknownKind = fmt.Errorf("canonicalkind: unknown external kind")

// Derive maps an external kind to its canonical kind; an unknown value returns
// an error rather than a fallback (no-silent-fallback principle).
//
//	user -> human   client -> service   agent -> agent
//	realm -> org     provider -> provider   anything else -> ErrUnknownKind
func Derive(externalKind string) (CanonicalKind, error) {
	if c, ok := externalToCanonical[externalKind]; ok {
		return c, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownKind, externalKind)
}

// Valid reports whether the given value is a valid canonical kind.
func Valid(k CanonicalKind) bool {
	switch k {
	case KindHuman, KindAgent, KindService, KindProvider, KindOrg:
		return true
	}
	return false
}
