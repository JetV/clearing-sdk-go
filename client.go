package clearing

import (
	"crypto/rsa"

	"github.com/JetV/clearing-sdk-go/internal/epidclient"
)

// ClearingClient is the unified facade. Which tiers are non-nil depends on the
// constructor used, so capability == construction credential (AC-SDK-SURFACE-002):
//
//	NewReadOnly  -> L1 only
//	NewSource    -> L1 + L2
//	NewUnify     -> L1 + L2 + L3
type ClearingClient struct {
	L1 *ResolveClient // always present
	L2 *SourceClient  // nil unless constructed with a source key
	L3 *UnifyClient   // nil unless constructed with a source key
}

// Version returns the OpenAPI contract version this SDK targets.
func (c *ClearingClient) Version() string { return ContractVersion }

// NewReadOnly builds an L1-only client. Ordinary consumers (billing, jetagents,
// frontends) use this; the type system denies them L2/L3 (both stay nil).
func NewReadOnly(baseURL string, opt Options) *ClearingClient {
	return &ClearingClient{L1: newResolveClient(baseURL, opt)}
}

// NewSource builds an L1+L2 client for an authenticated event source (auth,
// model-lake provider). It requires the source identity + RSA private key.
func NewSource(baseURL, sourceID string, priv *rsa.PrivateKey, opt Options) *ClearingClient {
	signer := &f4signer{sourceID: sourceID, priv: priv}
	tr := newTransport(baseURL, opt)
	return &ClearingClient{
		L1: newResolveClient(baseURL, opt),
		L2: &SourceClient{tr: tr, signer: signer},
	}
}

// NewUnify builds a full L1+L2+L3 client for a unification orchestrator
// (jetforge, auth). It requires the source identity + RSA private key (used for
// verified-attr verifier_sig and realm-link F4 transport signing).
func NewUnify(baseURL, sourceID string, priv *rsa.PrivateKey, opt Options) *ClearingClient {
	signer := &f4signer{sourceID: sourceID, priv: priv}
	tr := newTransport(baseURL, opt)
	return &ClearingClient{
		L1: newResolveClient(baseURL, opt),
		L2: &SourceClient{tr: tr, signer: signer},
		L3: &UnifyClient{tr: tr, signer: signer},
	}
}

// newResolveClient wires the L1 facade over epidclient + a kinds cache + a plain
// transport for GetByEPID/Kinds.
func newResolveClient(baseURL string, opt Options) *ResolveClient {
	be := epidclient.NewHTTPBackend(baseURL)
	if opt.HTTPClient != nil {
		be.Client = opt.HTTPClient
	}
	return &ResolveClient{
		inner: epidclient.New(be, opt.toEpidclient()),
		kinds: newKindsCache(opt.TTL, opt.now()),
		tr:    newTransport(baseURL, opt),
	}
}

func newTransport(baseURL string, opt Options) *transport {
	return &transport{baseURL: baseURL, hc: opt.httpClient(), now: opt.now()}
}
