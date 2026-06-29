package clearing

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/JetV/clearing-sdk-go/internal/sourcesign"
)

// F4 source-signed write headers (mirror internal/features/middleware.go — the
// authoritative server contract; the CHP-005 sketch used the wrong source header
// name and omitted the timestamp, both corrected here).
const (
	headerSource    = "X-Clearing-Source"
	headerSignature = "X-Clearing-Signature"
	headerTimestamp = "X-Clearing-Timestamp"
	contentTypeJSON = "application/json"
)

// transport is the shared signed/unsigned JSON caller for L2/L3.
type transport struct {
	baseURL string
	hc      *http.Client
	now     func() time.Time
}

// postJSON sends body to path. If priv != "" sourceID, it adds the three F4
// headers (RS256 over the raw body, base64-std, plus a fresh unix timestamp).
// out (if non-nil) is JSON-decoded from a 200 body. Non-2xx is classified via
// the server error envelope.
func (t *transport) postJSON(ctx context.Context, path string, body []byte, signer *f4signer, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrInvalid, err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	if signer != nil {
		sig, serr := sourcesign.Sign(signer.priv, body)
		if serr != nil {
			return fmt.Errorf("%w: sign: %v", ErrInvalid, serr)
		}
		req.Header.Set(headerSource, signer.sourceID)
		req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(sig))
		req.Header.Set(headerTimestamp, strconv.FormatInt(t.now().Unix(), 10))
	}
	return t.do(req, out)
}

// getJSON performs a GET and decodes a 200 body into out.
func (t *transport) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrInvalid, err)
	}
	return t.do(req, out)
}

func (t *transport) do(req *http.Request, out any) error {
	resp, err := t.hc.Do(req)
	if err != nil {
		// network/timeout → unavailable (caller decides fail-open/closed).
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		code, detail := decodeEnvelope(raw)
		return classifyStatus(resp.StatusCode, code, detail)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%w: decode response: %v", ErrUnavailable, err)
		}
	}
	return nil
}

// decodeEnvelope extracts {error, detail} from the unified error envelope.
func decodeEnvelope(raw []byte) (code, detail string) {
	var env struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &env)
	return env.Error, env.Detail
}

// f4signer binds a source identity to its RSA private key for F4 write-auth.
type f4signer struct {
	sourceID string
	priv     *rsa.PrivateKey
}
