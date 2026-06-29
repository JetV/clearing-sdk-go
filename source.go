package clearing

import (
	"context"
	"encoding/json"
	"fmt"
)

// SourceClient is the L2 registration tier. Only an authenticated event source
// constructs it, because it requires the source identity + RSA private key.
// Every write is source-signed automatically.
type SourceClient struct {
	tr     *transport
	signer *requestSigner
}

// Ensure idempotently adopts an external identity as an economic principal and
// returns its EPID. body.auth_instance_id must equal the signing source (server
// enforces, else ErrPermission). Safe to retry (idempotent + re-sign).
func (c *SourceClient) Ensure(ctx context.Context, id Identity) (Ensured, error) {
	body, err := marshalIdentity(id, "")
	if err != nil {
		return Ensured{}, err
	}
	var out struct {
		EPID          string `json:"epid"`
		CanonicalKind string `json:"canonical_kind"`
		Created       bool   `json:"created"`
	}
	if err := c.tr.postJSON(ctx, "/v1/principals/ensure", body, c.signer, &out); err != nil {
		return Ensured{}, err
	}
	return Ensured{EPID: out.EPID, CanonicalKind: out.CanonicalKind, Created: out.Created}, nil
}

// Link attaches an unregistered identity to an existing EPID (source-signed).
func (c *SourceClient) Link(ctx context.Context, id Identity, targetEPID string) error {
	body, err := marshalIdentity(id, targetEPID)
	if err != nil {
		return err
	}
	return c.tr.postJSON(ctx, "/v1/principals/link", body, c.signer, nil)
}

// Affiliate writes an economically-neutral relation (member_of / accountable_for)
// between two principals (source-signed).
func (c *SourceClient) Affiliate(ctx context.Context, subjectEPID, relation, targetEPID string) error {
	body, err := json.Marshal(map[string]string{
		"subject_epid": subjectEPID,
		"relation":     relation,
		"target_epid":  targetEPID,
	})
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	return c.tr.postJSON(ctx, "/v1/principals/affiliate", body, c.signer, nil)
}

// RotateKey swaps the signing private key (key rotation; ensure is idempotent so
// re-signing after rotation is safe).
func (c *SourceClient) RotateKey(s requestSigner) { c.signer.priv = s.priv }

// marshalIdentity builds the ensure/link body. targetEPID != "" adds target_epid
// (link). Field names exactly match the server's request schema.
func marshalIdentity(id Identity, targetEPID string) ([]byte, error) {
	m := map[string]string{
		"auth_instance_id": id.AuthInstanceID,
		"kind":             id.Kind,
		"principal_key":    id.Key,
	}
	if targetEPID != "" {
		m["target_epid"] = targetEPID
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	return b, nil
}
