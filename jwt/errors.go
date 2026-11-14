package iamjwt

import (
	"errors"
	"fmt"
)

// Verification error categories can be inspected with errors.Is.
var (
	ErrInvalidToken = errors.New("iamjwt: invalid token")
	ErrUnknownKey   = errors.New("iamjwt: unknown signing key")
	ErrJWKSFetch    = errors.New("iamjwt: JWKS fetch failed")
	ErrJWKSParse    = errors.New("iamjwt: JWKS parse failed")
)

// VerificationError classifies a verification failure without discarding its
// underlying cause. Error messages are for internal diagnostics, not HTTP bodies.
type VerificationError struct {
	Kind  error
	Cause error
}

func (e *VerificationError) Error() string {
	if e.Cause == nil {
		return e.Kind.Error()
	}
	return fmt.Sprintf("%s: %v", e.Kind, e.Cause)
}

// Is matches the stable verification category.
func (e *VerificationError) Is(target error) bool { return target == e.Kind }
func (e *VerificationError) Unwrap() error        { return e.Cause }

// JWKSStatusError preserves a non-success HTTP status without exposing a body.
type JWKSStatusError struct {
	StatusCode int
}

func (e *JWKSStatusError) Error() string {
	return fmt.Sprintf("JWKS HTTP status %d", e.StatusCode)
}

func verificationError(kind, cause error) error {
	return &VerificationError{Kind: kind, Cause: cause}
}
