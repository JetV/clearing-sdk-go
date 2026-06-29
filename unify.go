package clearing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/JetV/clearing-sdk-go/internal/sourcesign"
)

// Unify purpose constants, per the server's wire contract.
const (
	purposeKeyProof = "key-proof"
)

// UnifyClient is the L3 unification tier. It orchestrates the challenge
// fetch->sign->submit flow and hides the Ed25519/RSA + base64(std) details.
// It holds the source RSA key (for the verified-attr verifier_sig and realm-link
// request signing) — so, like L2, only an authenticated source/orchestrator can
// construct it.
type UnifyClient struct {
	tr     *transport
	signer *requestSigner // RSA source key (verifier_sig + realm-link request signing)
}

// ProveKey deduplicates by key control: it fetches a key-proof challenge, signs
// it with edPriv, and submits public key + fingerprint + signature. Same key
// across sources => same principal. No source assertion is involved.
func (c *UnifyClient) ProveKey(ctx context.Context, epid string, edPriv ed25519.PrivateKey) (DedupResult, error) {
	ch, err := c.challenge(ctx, epid, purposeKeyProof)
	if err != nil {
		return DedupResult{}, err
	}
	pub := edPriv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(edPriv, []byte(ch)))
	body, merr := json.Marshal(map[string]string{
		"epid":       epid,
		"key_id":     keyFingerprint(pub),
		"public_key": pubB64,
		"challenge":  ch,
		"signature":  sig,
	})
	if merr != nil {
		return DedupResult{}, fmt.Errorf("%w: marshal: %v", ErrInvalid, merr)
	}
	return c.postDedup(ctx, "/v1/unify/key-proof", body)
}

// SubmitVerifiedAttr submits a verifier's deduplication assertion. The SDK signs
// the canonical assertion body (WITHOUT verifier_sig — that field is json:"-" on
// the server) with the source RSA key and attaches it base64(std) as verifier_sig
// (closing the base64 footgun the protocol exposes).
func (c *UnifyClient) SubmitVerifiedAttr(ctx context.Context, a AttrAssertion) (DedupResult, error) {
	// Signed body == the exact field set the server re-marshals for verification.
	signed, err := json.Marshal(map[string]any{
		"epid":           a.EPID,
		"attr_type":      a.AttrType,
		"salted_hash":    a.SaltedHash,
		"assurance_tier": a.AssuranceTier,
		"method":         a.Method,
		"verifier_id":    c.signer.sourceID,
	})
	if err != nil {
		return DedupResult{}, fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	rawSig, err := sourcesign.Sign(c.signer.priv, signed)
	if err != nil {
		return DedupResult{}, fmt.Errorf("%w: sign: %v", ErrInvalid, err)
	}
	// Full wire body = signed fields + verifier_sig (base64 std). This endpoint is
	// not transport-signed; auth is the in-body verifier_sig.
	body, err := json.Marshal(map[string]any{
		"epid":           a.EPID,
		"attr_type":      a.AttrType,
		"salted_hash":    a.SaltedHash,
		"assurance_tier": a.AssuranceTier,
		"method":         a.Method,
		"verifier_id":    c.signer.sourceID,
		"verifier_sig":   base64.StdEncoding.EncodeToString(rawSig),
	})
	if err != nil {
		return DedupResult{}, fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	return c.postDedup(ctx, "/v1/unify/verified-attr", body)
}

// Bind performs a dual-binding merge: it starts a binding challenge, has both
// sides sign it with their Ed25519 keys, and submits the proofs. Both keys must
// already be registered active anchors for their EPIDs (via ProveKey first).
func (c *UnifyClient) Bind(ctx context.Context, subjectEPID, targetEPID string, sk, tk ed25519.PrivateKey) (DedupResult, error) {
	ch, err := c.startBinding(ctx, subjectEPID, targetEPID, "dual_key")
	if err != nil {
		return DedupResult{}, err
	}
	sPub := sk.Public().(ed25519.PublicKey)
	tPub := tk.Public().(ed25519.PublicKey)
	body, merr := json.Marshal(map[string]string{
		"challenge":          ch,
		"subject_public_key": base64.StdEncoding.EncodeToString(sPub),
		"subject_signature":  base64.StdEncoding.EncodeToString(ed25519.Sign(sk, []byte(ch))),
		"target_public_key":  base64.StdEncoding.EncodeToString(tPub),
		"target_signature":   base64.StdEncoding.EncodeToString(ed25519.Sign(tk, []byte(ch))),
	})
	if merr != nil {
		return DedupResult{}, fmt.Errorf("%w: marshal: %v", ErrInvalid, merr)
	}
	return c.postDedup(ctx, "/v1/unify/binding/prove", body)
}

// LinkRealm projects an org realm identity into the org EPID. The whole request
// is source-signed by the realm's source (realm.AuthInstanceID must equal the
// signing source), and admin control is proven by signing the canonical
// org-admin message with the org's registered Ed25519 admin key.
func (c *UnifyClient) LinkRealm(ctx context.Context, orgEPID string, realm Identity, adminKey ed25519.PrivateKey) error {
	adminPub := adminKey.Public().(ed25519.PublicKey)
	msg := orgAdminMessage(orgEPID, realm)
	body, err := json.Marshal(map[string]any{
		"org_epid": orgEPID,
		"realm_identity": map[string]string{
			"auth_instance_id": realm.AuthInstanceID,
			"kind":             realm.Kind,
			"principal_key":    realm.Key,
		},
		"admin_proof": map[string]string{
			"public_key": base64.StdEncoding.EncodeToString(adminPub),
			"signature":  base64.StdEncoding.EncodeToString(ed25519.Sign(adminKey, []byte(msg))),
		},
	})
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	return c.tr.postJSON(ctx, "/v1/unify/realm-link", body, c.signer, nil)
}

// challenge fetches a one-time unification challenge for an EPID+purpose.
func (c *UnifyClient) challenge(ctx context.Context, epid, purpose string) (string, error) {
	body, err := json.Marshal(map[string]string{"epid": epid, "purpose": purpose})
	if err != nil {
		return "", fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := c.tr.postJSON(ctx, "/v1/unify/challenge", body, nil, &out); err != nil {
		return "", err
	}
	return out.Challenge, nil
}

// startBinding issues a dual-binding challenge.
func (c *UnifyClient) startBinding(ctx context.Context, subjectEPID, targetEPID, method string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"subject_epid": subjectEPID, "target_epid": targetEPID, "method": method,
	})
	if err != nil {
		return "", fmt.Errorf("%w: marshal: %v", ErrInvalid, err)
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := c.tr.postJSON(ctx, "/v1/unify/binding", body, nil, &out); err != nil {
		return "", err
	}
	return out.Challenge, nil
}

// postDedup posts an unsigned unify body and decodes the dedup result.
func (c *UnifyClient) postDedup(ctx context.Context, path string, body []byte) (DedupResult, error) {
	var out struct {
		ActiveEPID  string `json:"active_epid"`
		Merged      bool   `json:"merged"`
		NeedsReview bool   `json:"needs_review"`
	}
	if err := c.tr.postJSON(ctx, path, body, nil, &out); err != nil {
		return DedupResult{}, err
	}
	return DedupResult{ActiveEPID: out.ActiveEPID, Merged: out.Merged, NeedsReview: out.NeedsReview}, nil
}

// keyFingerprint computes the dedup anchor key_id per the server's wire
// contract: "sha256:" + hex(sha256(rawPubKey)).
func keyFingerprint(rawPub []byte) string {
	sum := sha256.Sum256(rawPub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// orgAdminMessage builds the canonical org-admin message per the wire contract.
func orgAdminMessage(orgEPID string, realm Identity) string {
	return "realm-link|" + orgEPID + "|" + realm.AuthInstanceID + "|" + realm.Kind + "|" + realm.Key
}
