package epidclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// HTTPBackend resolves via the clearing REST API (POST /v1/principals/resolve).
type HTTPBackend struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPBackend constructs an HTTP backend (default 5s timeout).
func NewHTTPBackend(baseURL string) *HTTPBackend {
	return &HTTPBackend{BaseURL: baseURL, Client: &http.Client{Timeout: 5 * time.Second}}
}

// ResolveByIdentity implements Backend: it maps 404 -> ErrNotRegistered and any
// other failure -> ErrUnavailable.
func (h *HTTPBackend) ResolveByIdentity(ctx context.Context, id Identity) (Result, error) {
	payload, _ := json.Marshal(map[string]string{
		"auth_instance_id": id.AuthInstanceID,
		"kind":             id.Kind,
		"principal_key":    id.Key,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/v1/principals/resolve", bytes.NewReader(payload))
	if err != nil {
		return Result{}, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")

	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			EPID          string `json:"epid"`
			CanonicalKind string `json:"canonical_kind"`
			Status        string `json:"status"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return Result{}, ErrUnavailable
		}
		return Result{EPID: out.EPID, CanonicalKind: out.CanonicalKind, Status: out.Status}, nil
	case http.StatusNotFound:
		return Result{}, ErrNotRegistered
	default:
		return Result{}, ErrUnavailable
	}
}
