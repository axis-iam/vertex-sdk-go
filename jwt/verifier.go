package iamjwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	jwt "github.com/go-jose/go-jose/v4/jwt"
)

// Verifier validates IAM-issued JWTs.
type Verifier struct {
	jwks              *JWKSProvider
	expectedIssuer    string
	expectedAudience  string
	allowedAlgorithms []jose.SignatureAlgorithm
	leeway            time.Duration
}

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	JWKS             *JWKSProvider
	Issuer           string
	Audience         string
	SignatureAlgs    []jose.SignatureAlgorithm
	ClockSkewLeeway  time.Duration
}

// NewVerifier constructs a Verifier. Both JWKS and Issuer are required.
func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	if opts.JWKS == nil {
		return nil, errors.New("iamjwt: nil JWKSProvider")
	}
	if opts.Issuer == "" {
		return nil, errors.New("iamjwt: empty Issuer")
	}
	if len(opts.SignatureAlgs) == 0 {
		opts.SignatureAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}
	}
	if opts.ClockSkewLeeway <= 0 {
		opts.ClockSkewLeeway = 30 * time.Second
	}
	return &Verifier{
		jwks:              opts.JWKS,
		expectedIssuer:    opts.Issuer,
		expectedAudience:  opts.Audience,
		allowedAlgorithms: opts.SignatureAlgs,
		leeway:            opts.ClockSkewLeeway,
	}, nil
}

// Verify parses and validates a JWT, returning the union claims struct.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parsed, err := jwt.ParseSigned(token, v.allowedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("iamjwt: parse: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return nil, errors.New("iamjwt: missing JWT header")
	}
	kid := parsed.Headers[0].KeyID
	if kid == "" {
		return nil, errors.New("iamjwt: missing kid header")
	}
	key, err := v.jwks.KeyByID(ctx, kid)
	if err != nil {
		return nil, err
	}

	var c Claims
	if err := parsed.Claims(key, &c); err != nil {
		return nil, fmt.Errorf("iamjwt: verify signature: %w", err)
	}

	expected := jwt.Expected{
		Issuer: v.expectedIssuer,
		Time:   time.Now(),
	}
	if v.expectedAudience != "" {
		expected.AnyAudience = jwt.Audience{v.expectedAudience}
	}
	if err := c.Claims.ValidateWithLeeway(expected, v.leeway); err != nil {
		return nil, fmt.Errorf("iamjwt: validate claims: %w", err)
	}

	return &c, nil
}
