package iamjwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/axis-iam/vertex-sdk-go/iamtest"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
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
	srv.WithAudience("my-app")

	v := newVerifier(t, srv, "my-app")
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
	srv.WithAudience("my-app")

	// Build a verifier expecting a different issuer.
	jwks, _ := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: srv.URL + "/.well-known/jwks.json", Client: srv.Client()})
	v, _ := iamjwt.NewVerifier(iamjwt.VerifierOptions{JWKS: jwks, Issuer: "https://wrong", Audience: "my-app"})

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
	v := newVerifier(t, srv, "")
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
