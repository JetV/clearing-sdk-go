package clearing

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/JetV/clearing-sdk-go/internal/epidclient"
)

// Stable SDK error sentinels. Consumers branch on these (errors.Is) to choose
// fail-open/closed; the SDK never silently fabricates a fallback (U4).
var (
	// ErrNotRegistered: the principal/identity is authoritatively absent (404).
	// Re-exported from epidclient so L1 and L2/L3 share one sentinel.
	ErrNotRegistered = epidclient.ErrNotRegistered
	// ErrUnavailable: clearing is unreachable / circuit open / 5xx — not silently
	// masked; the caller decides fail-open vs fail-closed.
	ErrUnavailable = epidclient.ErrUnavailable
	// ErrPermission: source not authorized for this identity, or admin/governance
	// gate rejected (401/403).
	ErrPermission = errors.New("clearing: permission denied")
	// ErrConflict: unification/registration conflict (409) — identity already
	// mapped, challenge expired/used, binding not proven, low-tier auto-merge.
	ErrConflict = errors.New("clearing: conflict")
	// ErrInvalid: semantically invalid request (400/422) — bad body, unknown
	// kind/relation, self-merge, malformed key.
	ErrInvalid = errors.New("clearing: invalid request")
	// ErrRateLimited: too many challenges / requests (429).
	ErrRateLimited = errors.New("clearing: rate limited")
)

// APIError carries the server's stable machine code + HTTP status alongside the
// classified sentinel, so consumers can log precisely while branching coarsely.
type APIError struct {
	Status int    // HTTP status code
	Code   string // server "error" envelope code (e.g. not_registered)
	Detail string // optional human detail (500 only)
	class  error  // classified sentinel for errors.Is
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("clearing: %s (http %d): %s", e.Code, e.Status, e.Detail)
	}
	return fmt.Sprintf("clearing: %s (http %d)", e.Code, e.Status)
}

// Is lets errors.Is(err, ErrPermission) match the classified sentinel.
func (e *APIError) Is(target error) bool { return errors.Is(e.class, target) }

// mapErr passes through epidclient sentinels unchanged (L1 path).
func mapErr(err error) error { return err }

// classifyStatus maps an HTTP status + envelope code to an APIError whose class
// is one of the SDK sentinels. Single source of status→sentinel truth (U2),
// aligned with the server's writeRegistryError / writeUnifyError mappings.
func classifyStatus(status int, code, detail string) error {
	var class error
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		class = ErrNotRegistered
	case http.StatusUnauthorized, http.StatusForbidden:
		class = ErrPermission
	case http.StatusConflict, http.StatusPreconditionRequired:
		class = ErrConflict
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		class = ErrInvalid
	case http.StatusTooManyRequests:
		class = ErrRateLimited
	default: // 5xx and anything unexpected → unavailable (caller decides)
		class = ErrUnavailable
	}
	return &APIError{Status: status, Code: code, Detail: detail, class: class}
}
