// Package contract is the Go reference implementation for CHP-005 cross-language
// golden vectors. It owns the canonical layout of clearing/contract/vectors/*
// and the single computation path (canonical JSON + RS256 + Ed25519) that the
// generator (cmd/gen-contract) freezes and that every language SDK must
// reproduce byte-for-byte.
//
// The Go side never hand-edits expected_sig_b64 / canonical / expected_*_b64:
// those are derived here from the input body/seed via pkg/sourcesign (the one
// F4 implementation) and pure crypto/ed25519, then committed. The freeze test
// (test/contract) re-derives and asserts equality, so the committed vectors can
// never drift from the reference implementation (U1-M2 / U2 contract-freeze).
package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/JetV/clearing-sdk-go/internal/sourcesign"
)

// File names under the vectors directory (single source of those names).
const (
	CanonicalFile = "canonical.json"
	F4SignFile    = "f4_sign.json"
	Ed25519File   = "ed25519_challenge.json"
	TestKeysDir   = "testkeys"
)

// FrozenServerURL is the placeholder server URL baked into the frozen
// contract/openapi.yaml. The live /.well-known endpoint substitutes the
// request-derived URL; consumers always override the server. The generator and
// the freeze test both build the doc with this value so the comparison is exact.
const FrozenServerURL = "http://clearing.internal:11020"

// ErrFloatInSignedBody is returned when a signed body contains a JSON float.
// CHP-005 forbids floats in signed bodies (cross-language precision drift): use
// integer minor units or strings. canonical-only vectors may still carry them.
var ErrFloatInSignedBody = errors.New("contract: float not allowed in signed body")

// CanonicalVector pins body -> expected canonical bytes (3 rules: sorted keys,
// no insignificant whitespace, number fidelity). body is stored raw so input
// formatting is irrelevant; canonical is the byte-exact expected output.
type CanonicalVector struct {
	Name      string          `json:"name"`
	Body      json.RawMessage `json:"body"`
	Canonical string          `json:"canonical"`
}

// F4SignVector pins body -> RS256(base64-std) over canonical(body), signed with
// the referenced fixed test RSA key.
type F4SignVector struct {
	Name           string          `json:"name"`
	Body           json.RawMessage `json:"body"`
	Canonical      string          `json:"canonical"`
	RSAPrivPEMRef  string          `json:"rsa_priv_pem_ref"`
	ExpectedSigB64 string          `json:"expected_sig_b64"`
}

// Ed25519Vector pins challenge + seed -> Ed25519(base64-std) signature over the
// challenge bytes, plus the base64-std raw public key.
type Ed25519Vector struct {
	Name           string `json:"name"`
	Challenge      string `json:"challenge"`
	EdSeedHex      string `json:"ed_seed_hex"`
	ExpectedSigB64 string `json:"expected_sig_b64"`
	ExpectedPubB64 string `json:"expected_pub_b64"`
}

// Suite is the full loaded vector set.
type Suite struct {
	Dir       string
	Canonical []CanonicalVector
	F4Sign    []F4SignVector
	Ed25519   []Ed25519Vector
}

// Load reads all vector files from dir (the vectors directory).
func Load(dir string) (*Suite, error) {
	s := &Suite{Dir: dir}
	if err := readJSON(filepath.Join(dir, CanonicalFile), &s.Canonical); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, F4SignFile), &s.F4Sign); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, Ed25519File), &s.Ed25519); err != nil {
		return nil, err
	}
	return s, nil
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("contract: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("contract: parse %s: %w", path, err)
	}
	return nil
}

// ComputeCanonical returns the canonical byte string for a body via the single
// reference implementation (sourcesign).
func ComputeCanonical(body []byte) (string, error) {
	canon, err := sourcesign.Canonicalize(body)
	if err != nil {
		return "", err
	}
	return string(canon), nil
}

// ComputeF4Sig returns base64(std) RS256 over canonical(body) using the test
// RSA key at dir/ref. Rejects floats in the signed body (precision drift guard).
func ComputeF4Sig(dir, ref string, body []byte) (string, error) {
	if err := rejectFloat(body); err != nil {
		return "", err
	}
	priv, err := LoadRSAPriv(filepath.Join(dir, ref))
	if err != nil {
		return "", err
	}
	sig, err := sourcesign.Sign(priv, body)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ComputeEd25519 returns base64(std) signature over the challenge bytes and the
// base64(std) raw public key, both derived from the 32-byte seed (hex).
func ComputeEd25519(seedHex, challenge string) (sigB64, pubB64 string, err error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", "", fmt.Errorf("contract: bad ed_seed_hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return "", "", fmt.Errorf("contract: ed_seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(challenge))
	pub := priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(pub), nil
}

// LoadRSAPriv parses a PEM RSA private key (PKCS#8 or PKCS#1).
func LoadRSAPriv(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("contract: read key %s: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("contract: no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("contract: %s is not RSA", path)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("contract: unsupported private key format in %s", path)
}

// rejectFloat fails if the JSON body contains any float (non-integer) number.
func rejectFloat(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}
	return walkRejectFloat(v)
}

func walkRejectFloat(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for _, e := range t {
			if err := walkRejectFloat(e); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := walkRejectFloat(e); err != nil {
				return err
			}
		}
	case json.Number:
		if _, err := t.Int64(); err != nil {
			// Not an integer -> float-like literal.
			return fmt.Errorf("%w: %s", ErrFloatInSignedBody, t.String())
		}
	}
	return nil
}
