package iamjwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/axis-iam/vertex-sdk-go/iamtest"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func newVerifier(t *testing.T, srv *iamtest.MockServer, aud string) *iamjwt.Verifier {
	t.Helper()
	jwks, err := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{
		URL:     srv.URL + "/.well-known/jwks.json",
		Client:  srv.Client(),
		Refresh: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := iamjwt.NewVerifier(iamjwt.VerifierOptions{
		JWKS:     jwks,
		Issuer:   srv.Issuer(),
		Audience: aud,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerify_Valid(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.WithAudience("api://orders")

	v := newVerifier(t, srv, "api://orders")
	tok, err := srv.TokenForWith("u1", []string{"admin"}, map[string]any{
		"app_id": "my-app",
		"email":  "alice@example.com",
		"acr":    "urn:iam:acr:mfa",
		"amr":    []string{"pwd", "mfa"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "u1" || claims.AppID != "my-app" || claims.Email != "alice@example.com" {
		t.Fatalf("bad claims: %+v", claims)
	}
	if claims.ACR != "urn:iam:acr:mfa" || len(claims.AMR) != 2 {
		t.Fatalf("acr/amr lost: %+v", claims)
	}
}

func TestVerify_BadIssuer(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.WithAudience("api://orders")

	// Build a verifier expecting a different issuer.
	jwks, _ := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: srv.URL + "/.well-known/jwks.json", Client: srv.Client()})
	v, _ := iamjwt.NewVerifier(iamjwt.VerifierOptions{JWKS: jwks, Issuer: "https://wrong", Audience: "api://orders"})

	tok, _ := srv.TokenFor("u1", []string{"admin"})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestVerify_Garbage(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	v := newVerifier(t, srv, "api://orders")
	if _, err := v.Verify(context.Background(), "not.a.jwt"); err == nil {
		t.Fatal("expected error")
	}
}

func TestJWKSProvider_Rotation(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	jwks, _ := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{
		URL:              srv.URL + "/.well-known/jwks.json",
		Client:           srv.Client(),
		Refresh:          time.Hour,
		RotationCooldown: 10 * time.Millisecond,
	})
	if err := jwks.Preload(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Unknown kid should error, and subsequent call within cooldown should not retry.
	if _, err := jwks.KeyByID(context.Background(), "unknown"); err == nil {
		t.Fatal("expected unknown kid error")
	}
}

func TestNewVerifier_RequiresAudience(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	jwks, err := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: srv.URL + "/.well-known/jwks.json", Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for _, audience := range []string{"", " ", "\t\n"} {
		if verifier, err := iamjwt.NewVerifier(iamjwt.VerifierOptions{JWKS: jwks, Issuer: srv.Issuer(), Audience: audience}); err == nil || verifier != nil {
			t.Fatal("blank audience must fail at construction")
		}
	}
}

func TestVerify_ResourceAudienceContract(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	v := newVerifier(t, srv, "api://orders")
	for _, tc := range []struct {
		name  string
		extra map[string]any
		valid bool
	}{
		{"resource-audience", nil, true},
		{"audience-array", map[string]any{"aud": []string{"api://other", "api://orders"}}, true},
		{"client-id-is-not-resource-audience", map[string]any{"aud": "orders-m2m-client"}, false},
		{"missing-audience", map[string]any{"aud": nil}, false},
		{"empty-audience", map[string]any{"aud": ""}, false},
		{"wrong-issuer", map[string]any{"iss": "https://wrong.example.com"}, false},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, false},
		{"not-yet-valid", map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := srv.TokenForWith("u1", []string{"admin"}, tc.extra)
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.Verify(context.Background(), token)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestVerify_WrongSignature(t *testing.T) {
	trusted, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.Close()
	other, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	v := newVerifier(t, trusted, "api://orders")
	token, err := other.TokenForWith("u1", nil, map[string]any{"iss": trusted.Issuer()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("token signed by another key must fail")
	}
}

func TestVerify_DisallowedAlgorithm(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	v := newVerifier(t, srv, "api://orders")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("non-secret-test-signing-key-32bytes")}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := josejwt.Signed(signer).Claims(map[string]any{"iss": srv.Issuer(), "aud": "api://orders", "exp": time.Now().Add(time.Hour).Unix()}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("HS256 must not be accepted by the default verifier")
	}
}
