// Package websession provides the optional server_session authentication mode.
// OAuth credentials and transaction control remain on the application backend.
package websession

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidSession    = errors.New("websession: invalid session")
	ErrUnavailable       = errors.New("websession: dependency unavailable")
	ErrForbidden         = errors.New("websession: forbidden")
	ErrRateLimited       = errors.New("websession: rate limited")
	ErrExchangeUncertain = errors.New("websession: exchange uncertain")
	ErrRefreshUncertain  = errors.New("websession: refresh uncertain")
	ErrAbsent            = errors.New("websession: record absent or expired")
	ErrConflict          = errors.New("websession: conditional operation conflict")
	ErrCapacity          = errors.New("websession: provider capacity")
	ErrClosed            = errors.New("websession: provider closed")
	ErrValidation        = errors.New("websession: invalid input")
	errNotSent           = errors.New("websession: request provably not sent")
)

// Error preserves a safe machine code and cause without rendering upstream
// diagnostics, request URLs, credentials or token bytes.
type Error struct {
	Code       string
	Status     int
	RetryAfter int
	Cause      error
}

func (e *Error) Error() string { return fmt.Sprintf("websession: %s (HTTP %d)", e.Code, e.Status) }
func (e *Error) Unwrap() error { return e.Cause }

func failure(status int, code string, cause error) error {
	return &Error{Code: code, Status: status, Cause: cause}
}

func storeError(err error) error {
	switch {
	case errors.Is(err, ErrAbsent):
		return failure(401, "SESSION_REQUIRED", errors.Join(ErrInvalidSession, err))
	case errors.Is(err, ErrConflict):
		return failure(409, "SESSION_ACTION_PENDING", err)
	case errors.Is(err, ErrCapacity):
		return failure(503, "SESSION_STORE_CAPACITY", errors.Join(ErrUnavailable, err))
	default:
		return failure(503, "SESSION_STORE_UNAVAILABLE", errors.Join(ErrUnavailable, err))
	}
}

func invalid() error { return failure(400, "VALIDATION_ERROR", ErrValidation) }
