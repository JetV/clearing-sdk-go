package clearing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/JetV/clearing-sdk-go/internal/contract"
	"github.com/JetV/clearing-sdk-go/internal/sourcesign"

	"github.com/stretchr/testify/require"
)

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func fixedNow() time.Time { return time.Unix(1700000000, 0) }

// AC-SDK-SURFACE-002: capability == construction credential. Read-only callers
// cannot obtain L2/L3 handles from the type system.
func TestTierIsolation(t *testing.T) {
	priv := genRSA(t)

	ro := NewReadOnly("http://x", Options{})
	require.NotNil(t, ro.L1)
	require.Nil(t, ro.L2, "read-only must not expose L2")
	require.Nil(t, ro.L3, "read-only must not expose L3")

	src := NewSource("http://x", "auth.local", priv, Options{})
	require.NotNil(t, src.L1)
	require.NotNil(t, src.L2)
	require.Nil(t, src.L3, "source must not expose L3")

	uni := NewUnify("http://x", "auth.local", priv, Options{})
	require.NotNil(t, uni.L1)
	require.NotNil(t, uni.L2)
	require.NotNil(t, uni.L3)
	require.Equal(t, ContractVersion, uni.Version())
}

// AC-GOSDK-002: L2 writes carry the THREE F4 headers (source + base64-std
// signature that verifies + fresh timestamp). Locks the two spec/reality fixes
// (correct header name; timestamp present).
func TestSourceEnsureF4Headers(t *testing.T) {
	priv := genRSA(t)
	var gotSource, gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/principals/ensure", r.URL.Path)
		gotSource = r.Header.Get("X-Clearing-Source")
		gotSig = r.Header.Get("X-Clearing-Signature")
		gotTS = r.Header.Get("X-Clearing-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{"epid": "ep_x", "canonical_kind": "human", "created": true})
	}))
	defer srv.Close()

	c := NewSource(srv.URL, "auth.local", priv, Options{Now: fixedNow})
	ens, err := c.L2.Ensure(context.Background(), Identity{AuthInstanceID: "auth.local", Kind: "user", Key: "u1"})
	require.NoError(t, err)
	require.Equal(t, "ep_x", ens.EPID)
	require.True(t, ens.Created)

	require.Equal(t, "auth.local", gotSource)
	sig, derr := base64.StdEncoding.DecodeString(gotSig)
	require.NoError(t, derr, "signature must be base64(std)")
	require.NoError(t, sourcesign.Verify(&priv.PublicKey, gotBody, sig), "signature must verify over raw body")
	ts, perr := strconv.ParseInt(gotTS, 10, 64)
	require.NoError(t, perr, "timestamp must be present and numeric")
	require.Equal(t, fixedNow().Unix(), ts)
}

// Error envelope → classified sentinel + preserved server code.
func TestErrorClassification(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   error
	}{
		{http.StatusForbidden, "source_unauthorized", ErrPermission},
		{http.StatusNotFound, "not_registered", ErrNotRegistered},
		{http.StatusConflict, "identity_already_mapped", ErrConflict},
		{http.StatusUnprocessableEntity, "merge_self", ErrInvalid},
		{http.StatusTooManyRequests, "too_many_challenges", ErrRateLimited},
		{http.StatusInternalServerError, "internal", ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": tc.code})
			}))
			defer srv.Close()
			c := NewSource(srv.URL, "auth.local", genRSA(t), Options{Now: fixedNow})
			_, err := c.L2.Ensure(context.Background(), Identity{AuthInstanceID: "auth.local", Kind: "user", Key: "u1"})
			require.ErrorIs(t, err, tc.want)
			var apiErr *APIError
			require.True(t, errors.As(err, &apiErr))
			require.Equal(t, tc.code, apiErr.Code)
			require.Equal(t, tc.status, apiErr.Status)
		})
	}
}

// L3 verified-attr: verifier_sig signs the canonical body WITHOUT itself
// (server field is json:"-"); SDK attaches base64(std).
func TestVerifiedAttrSignsBodyWithoutSig(t *testing.T) {
	priv := genRSA(t)
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/unify/verified-attr", r.URL.Path)
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{"active_epid": "ep1", "merged": true, "needs_review": false})
	}))
	defer srv.Close()

	c := NewUnify(srv.URL, "auth.local", priv, Options{Now: fixedNow})
	res, err := c.L3.SubmitVerifiedAttr(context.Background(), AttrAssertion{
		EPID: "ep1", AttrType: "gov_id", SaltedHash: "h", AssuranceTier: 3, Method: "kyc",
	})
	require.NoError(t, err)
	require.True(t, res.Merged)

	var wire map[string]any
	require.NoError(t, json.Unmarshal(gotBody, &wire))
	require.Equal(t, "auth.local", wire["verifier_id"])
	sigB64, _ := wire["verifier_sig"].(string)
	sig, derr := base64.StdEncoding.DecodeString(sigB64)
	require.NoError(t, derr)
	// Reconstruct the signed body (6 fields, no verifier_sig) and verify.
	signed, _ := json.Marshal(map[string]any{
		"epid": "ep1", "attr_type": "gov_id", "salted_hash": "h",
		"assurance_tier": 3, "method": "kyc", "verifier_id": "auth.local",
	})
	require.NoError(t, sourcesign.Verify(&priv.PublicKey, signed, sig),
		"verifier_sig must verify over the assertion body excluding itself")
}

// L3 key-proof: SDK fetches challenge, signs with Ed25519, computes key_id =
// fingerprint(rawPub), all base64(std).
func TestKeyProofOrchestration(t *testing.T) {
	pub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/unify/challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "chal123", "expires_at": 1700000300})
		case "/v1/unify/key-proof":
			gotBody, _ = io.ReadAll(r.Body)
			_ = json.NewEncoder(w).Encode(map[string]any{"active_epid": "ep1", "merged": false})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := NewUnify(srv.URL, "auth.local", genRSA(t), Options{Now: fixedNow})
	_, err = c.L3.ProveKey(context.Background(), "ep1", edPriv)
	require.NoError(t, err)

	var wire map[string]string
	require.NoError(t, json.Unmarshal(gotBody, &wire))
	require.Equal(t, "ep1", wire["epid"])
	require.Equal(t, "chal123", wire["challenge"])
	pubDecoded, derr := base64.StdEncoding.DecodeString(wire["public_key"])
	require.NoError(t, derr)
	require.Equal(t, []byte(pub), pubDecoded)
	require.Equal(t, keyFingerprint(pub), wire["key_id"])
	sig, derr := base64.StdEncoding.DecodeString(wire["signature"])
	require.NoError(t, derr)
	require.True(t, ed25519.Verify(pub, []byte("chal123"), sig), "ed25519 sig must verify over challenge")
}

// AC-GOSDK-001: L1 inherits epidclient resilience — 503 → ErrUnavailable and the
// breaker opens (later calls fail fast without hitting the backend).
func TestResolveResilienceAndDegradation(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewReadOnly(srv.URL, Options{FailureThreshold: 2, OpenTimeout: time.Hour, Now: fixedNow})
	id := Identity{AuthInstanceID: "auth.local", Kind: "user", Key: "u1"}
	for i := 0; i < 5; i++ {
		_, err := c.L1.Resolve(context.Background(), id)
		require.ErrorIs(t, err, ErrUnavailable)
	}
	require.LessOrEqual(t, hits, 2, "breaker must open and stop hammering the backend")
}

func TestResolveNotRegisteredAndOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/principals/resolve" {
			var in map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			if in["principal_key"] == "missing" {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "not_registered"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"epid": "ep_ok", "canonical_kind": "human", "status": "active"})
			return
		}
		if r.URL.Path == "/v1/principals/ep_ok" {
			_ = json.NewEncoder(w).Encode(map[string]any{"epid": "ep_ok", "canonical_kind": "human", "status": "active"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewReadOnly(srv.URL, Options{Now: fixedNow})

	_, err := c.L1.Resolve(context.Background(), Identity{AuthInstanceID: "auth.local", Kind: "user", Key: "missing"})
	require.ErrorIs(t, err, ErrNotRegistered)

	got, err := c.L1.Resolve(context.Background(), Identity{AuthInstanceID: "auth.local", Kind: "user", Key: "u1"})
	require.NoError(t, err)
	require.Equal(t, "ep_ok", got.EPID)

	byEpid, err := c.L1.GetByEPID(context.Background(), "ep_ok")
	require.NoError(t, err)
	require.Equal(t, "active", byEpid.Status)
}

// Kinds: server-first; compiled-in fallback (degraded) when unreachable.
func TestKindsServerFirstThenFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kinds":   []string{"human", "agent"},
			"mapping": map[string]string{"user": "human", "agent": "agent"},
		})
	}))
	c := NewReadOnly(srv.URL, Options{Now: fixedNow})
	m, err := c.L1.Kinds(context.Background())
	require.NoError(t, err)
	require.Equal(t, "human", m["user"])
	require.False(t, c.L1.kinds.Degraded())
	srv.Close()

	// Fresh client to a dead address → compiled fallback, flagged degraded.
	dead := NewReadOnly("http://127.0.0.1:0", Options{Now: fixedNow})
	fb, err := dead.L1.Kinds(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, fb)
	require.True(t, dead.L1.kinds.Degraded())
}

// AC-GOSDK-002 conformance: the SDK transport's F4 signature byte-matches the
// frozen cross-language golden vectors.
func TestTransportMatchesGoldenVectors(t *testing.T) {
	dir := filepath.Join("testdata", "vectors")
	suite, err := contract.Load(dir)
	require.NoError(t, err)
	require.NotEmpty(t, suite.F4Sign)

	for _, v := range suite.F4Sign {
		t.Run(v.Name, func(t *testing.T) {
			priv, err := contract.LoadRSAPriv(filepath.Join(dir, v.RSAPrivPEMRef))
			require.NoError(t, err)

			var gotSig string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotSig = r.Header.Get("X-Clearing-Signature")
				_, _ = w.Write([]byte("{}"))
			}))
			defer srv.Close()

			tr := newTransport(srv.URL, Options{Now: fixedNow})
			signer := &f4signer{sourceID: "auth.local", priv: priv}
			require.NoError(t, tr.postJSON(context.Background(), "/x", []byte(v.Body), signer, nil))
			require.Equal(t, v.ExpectedSigB64, gotSig, "SDK transport signature must match golden vector %s", v.Name)
		})
	}
}
