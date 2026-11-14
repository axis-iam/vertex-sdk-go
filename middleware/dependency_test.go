package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/axis-iam/vertex-sdk-go/iamtest"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
	"github.com/axis-iam/vertex-sdk-go/middleware"
)

func TestAuthDependencyFailures(t *testing.T) {
	mock, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()
	token, err := mock.TokenFor("u1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body       string
		upstream, status int
	}{
		{"fetch", "sensitive upstream details", 502, 503},
		{"parse", "{", 200, 503},
		{"unknown", `{"keys":[]}`, 200, 401},
		{"malformed", "{", 200, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.upstream)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()
			p, e := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: s.URL})
			if e != nil {
				t.Fatal(e)
			}
			v, e := iamjwt.NewVerifier(iamjwt.VerifierOptions{JWKS: p, Issuer: mock.Issuer(), Audience: "api://orders"})
			if e != nil {
				t.Fatal(e)
			}
			h := middleware.Auth(middleware.AuthConfig{Verifier: v, Resolver: iamtest.NewMockResolver()})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("must fail closed") }))
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				bearer := token
				if tc.name == "malformed" {
					bearer = "not.a.jwt"
				}
				req.Header.Set("Authorization", "Bearer "+bearer)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				code, message := "UNAUTHORIZED", "invalid bearer token"
				if tc.status == 503 {
					code, message = "AUTH_DEPENDENCY_UNAVAILABLE", "authentication service unavailable"
				}
				want := "{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}\n"
				if rec.Code != tc.status || rec.Body.String() != want || strings.Contains(rec.Body.String(), s.URL) {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
				}
			}
			wantCalls := int32(1)
			if tc.name == "malformed" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls {
				t.Fatalf("cooldown fetch count=%d", calls.Load())
			}
		})
	}
}

func TestAuthCachedKeyBadSignatureIsUnauthorized(t *testing.T) {
	stack := newStack(t)
	other, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	valid, err := stack.mock.TokenFor("u1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stack.verifier.Verify(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	bad, err := other.TokenForWith("u1", nil, map[string]any{"iss": stack.mock.Issuer()})
	if err != nil {
		t.Fatal(err)
	}
	h := middleware.Auth(middleware.AuthConfig{Verifier: stack.verifier, Resolver: iamtest.NewMockResolver()})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid signature reached handler") }))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 || rec.Body.String() != "{\"code\":\"UNAUTHORIZED\",\"message\":\"invalid bearer token\"}\n" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}
