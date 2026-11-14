package iamjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestJWKSFreshCacheSurvivesRotationFailure(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var failed atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failed.Load() {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known", Algorithm: "ES256", Use: "sig"}}})
	}))
	defer s.Close()
	p, err := NewJWKSProvider(JWKSOptions{URL: s.URL, RotationCooldown: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Preload(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	_, err = p.KeyByID(context.Background(), "rotated")
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(VerifierOptions{JWKS: p, Issuer: "https://issuer.test", Audience: "api://orders"})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "known"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{Issuer: "https://issuer.test", Audience: josejwt.Audience{"api://orders"}, Expiry: josejwt.NewNumericDate(time.Now().Add(time.Hour))}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("fresh cached key affected by other key outage: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other}, (&jose.SignerOptions{}).WithHeader("kid", "known"))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := josejwt.Signed(wrongSigner).Claims(josejwt.Claims{Issuer: "https://issuer.test"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.Verify(context.Background(), bad); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("cached bad signature classified as dependency: %v", err)
	}
	p.mu.Lock()
	p.lastFetch = time.Now().Add(-2 * p.refresh)
	p.mu.Unlock()
	if _, err = verifier.Verify(context.Background(), token); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("stale key used or dependency lost: %v", err)
	}
	failed.Store(false)
	if err = p.Preload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.KeyByID(context.Background(), "rotated"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("successful refresh did not clear failure: %v", err)
	}
	p.mu.Lock()
	p.lastFetch = time.Now().Add(-2 * p.refresh)
	p.mu.Unlock()
	failed.Store(true)
	if _, err = p.KeyByID(context.Background(), "known"); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("stale known key became unknown during successful-refresh cooldown: %v", err)
	}
}
