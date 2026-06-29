// Package clearing is the official Go SDK for the Clearing economic-principal
// (EPID) service. It composes self-contained primitives (resilient resolution,
// F4 RS256 signing, canonical-kind taxonomy — all vendored under internal/) into
// three capability tiers with a uniform shape across the Go / Python /
// TypeScript SDKs:
//
//	L1 ResolveClient — read: Resolve / GetByEPID / Kinds (epidclient resilience)
//	L2 SourceClient  — register: Ensure / Link / Affiliate (F4 RS256 auto-sign)
//	L3 UnifyClient   — unify: ProveKey / SubmitVerifiedAttr / Bind / LinkRealm
//
// Tier == permission boundary: constructing L2/L3 requires a source identity +
// private key, so an ordinary read-only consumer cannot obtain the dangerous
// write/unify handles from the type system alone (AC-SDK-SURFACE-002).
//
// The SDK hides every signing footgun the protocol exposes: the three F4
// headers (X-Clearing-Source / -Signature / -Timestamp), base64(std) encoding,
// Ed25519 vs RSA usage, the challenge fetch→sign→submit dance, and the
// verified-attr "verifier_sig is signed over the body WITHOUT itself" rule.
package clearing

import (
	"net/http"
	"time"

	"github.com/JetV/clearing-sdk-go/internal/epidclient"
)

// ContractVersion is the OpenAPI contract major.minor.patch this SDK targets.
// Integration tests compare it against the live server info.version for compat.
const ContractVersion = "1.0.0"

// Identity is the external identity natural key (realm is NOT part of the key,
// invariant F1). It mirrors epidclient.Identity field-for-field.
type Identity struct {
	AuthInstanceID string // issuing auth instance (= F4 source_id on writes)
	Kind           string // external kind (user/agent/client/realm/provider...)
	Key            string // stable principal key within that auth instance
}

// Resolved is the active-principal projection returned by resolve/getByEPID.
type Resolved struct {
	EPID          string
	CanonicalKind string
	Status        string // ACTIVE | MERGED | SUSPENDED (resolve always follows to active)
}

// Ensured is the ensure (idempotent adopt) result.
type Ensured struct {
	EPID          string
	CanonicalKind string
	Created       bool // true=newly created, false=idempotent hit
}

// AttrAssertion is a verifier's deduplication assertion for a strong attribute.
// The plaintext never leaves the verifier; only a salted hash is transmitted.
// Sig is filled by the SDK (RS256 over the canonical body, base64-std) — callers
// never set it.
type AttrAssertion struct {
	EPID          string
	AttrType      string // phone | email | gov_id ...
	SaltedHash    string
	AssuranceTier int
	Method        string
}

// DedupResult is the outcome of a unification (key-proof / verified-attr /
// binding). NeedsReview is only meaningful for verified-attr (low-tier hits).
type DedupResult struct {
	ActiveEPID  string
	Merged      bool
	NeedsReview bool
}

// Relation enumerates economically-neutral affiliation edges.
const (
	RelationMemberOf       = "member_of"
	RelationAccountableFor = "accountable_for"
)

// Options tunes both L1 resilience (forwarded to epidclient) and the HTTP
// transport shared by L2/L3. Zero values get industrial defaults.
type Options struct {
	// L1 resilience (forwarded verbatim to epidclient.Options).
	TTL              time.Duration
	NegativeTTL      time.Duration
	FailureThreshold int
	OpenTimeout      time.Duration

	// HTTPClient is used by L2/L3 (and L1's HTTP backend). Defaults to a client
	// with WriteTimeout. Injected so tests can stub transport (U3).
	HTTPClient *http.Client
	// WriteTimeout bounds L2/L3 calls when HTTPClient is not supplied (default 5s).
	WriteTimeout time.Duration
	// Now is an injectable clock (timestamps + resilience). Defaults to time.Now (U3).
	Now func() time.Time
}

func (o Options) writeTimeout() time.Duration {
	if o.WriteTimeout > 0 {
		return o.WriteTimeout
	}
	return 5 * time.Second
}

func (o Options) now() func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

func (o Options) httpClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{Timeout: o.writeTimeout()}
}

// toEpidclient maps SDK options to epidclient options (resilience knobs + clock).
func (o Options) toEpidclient() epidclient.Options {
	return epidclient.Options{
		TTL:              o.TTL,
		NegativeTTL:      o.NegativeTTL,
		FailureThreshold: o.FailureThreshold,
		OpenTimeout:      o.OpenTimeout,
		Now:              o.Now,
	}
}
