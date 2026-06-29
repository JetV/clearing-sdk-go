// Package sourcesign is the single source of truth for F4 federated write-auth
// signing: deterministic canonical JSON + RS256 (RSA-PKCS1v15 + SHA-256)
// sign/verify.
//
// Both clearing (server-side verification, internal/sourceauth) and external
// issuing sources (e.g. the auth service in CHP-004) import this exact package,
// so the bytes that get signed are identical across repositories. Re-implementing
// the canonicalization on the source side is the #1 byte-drift risk for F4
// (Go's encoding/json HTML-escaping, key ordering, number handling); sharing one
// implementation eliminates it (CHP-004 audit H1).
package sourcesign

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strconv"
)

var (
	// ErrBadSignature is returned when RS256 verification fails.
	ErrBadSignature = errors.New("sourcesign: signature verification failed")
	// ErrNoPEMBlock is returned when a public key PEM cannot be decoded.
	ErrNoPEMBlock = errors.New("sourcesign: no PEM block")
	// ErrNotRSAPublicKey is returned when a parsed key is not RSA.
	ErrNotRSAPublicKey = errors.New("sourcesign: not an RSA public key")
	// ErrUnsupportedPublicKey is returned when the PEM is neither PKIX nor PKCS1.
	ErrUnsupportedPublicKey = errors.New("sourcesign: unsupported public key format")
)

// Canonicalize turns an arbitrary JSON body into a deterministic byte sequence:
// object keys sorted, insignificant whitespace removed. This lets signer and
// verifier agree on the digest regardless of serialization differences
// (whitespace, key order). Invalid JSON returns an error (never silently
// falls back).
func Canonicalize(body []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var sb bytes.Buffer
	writeCanonical(&sb, v)
	return sb.Bytes(), nil
}

func writeCanonical(sb *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeJSONString(sb, k)
			sb.WriteByte(':')
			writeCanonical(sb, t[k])
		}
		sb.WriteByte('}')
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeCanonical(sb, e)
		}
		sb.WriteByte(']')
	case string:
		writeJSONString(sb, t)
	case json.Number:
		sb.WriteString(t.String())
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case nil:
		sb.WriteString("null")
	default:
		// Fallback for float64 etc. (normally unreachable after UseNumber).
		b, _ := json.Marshal(t)
		sb.Write(b)
	}
}

func writeJSONString(sb *bytes.Buffer, s string) {
	b, _ := json.Marshal(s)
	sb.Write(b)
}

// Sign produces an RS256 signature over Canonicalize(body) using priv.
func Sign(priv *rsa.PrivateKey, body []byte) ([]byte, error) {
	canon, err := Canonicalize(body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canon)
	return rsa.SignPKCS1v15(nil, priv, crypto.SHA256, digest[:])
}

// Verify checks that sig is a valid RS256 signature over Canonicalize(body) for
// pub. It returns ErrBadSignature on mismatch.
func Verify(pub *rsa.PublicKey, body, sig []byte) error {
	canon, err := Canonicalize(body)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canon)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return ErrBadSignature
	}
	return nil
}

// Fingerprint returns a canonical fingerprint of a PEM public key:
// "sha256:" + hex(sha256(DER SubjectPublicKeyInfo)). Stable regardless of PEM
// whitespace/line endings, so signer and verifier agree on key identity.
func Fingerprint(pemStr string) (string, error) {
	pub, err := ParseRSAPublicKey(pemStr)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ParseRSAPublicKey parses a PEM-encoded RSA public key (PKIX or PKCS1).
func ParseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, ErrNoPEMBlock
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, ErrNotRSAPublicKey
	}
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub, nil
	}
	return nil, ErrUnsupportedPublicKey
}
