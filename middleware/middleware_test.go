package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/axis-iam/vertex-sdk-go/authz"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
	"github.com/axis-iam/vertex-sdk-go/middleware"
)

type stack struct {
	mock     *iamtest.MockServer
	verifier *iamjwt.Verifier
}

func newStack(t *testing.T) *stack {
	t.Helper()
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.WithAudience("my-app")

	jwks, err := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{
		URL:    srv.URL + "/.well-known/jwks.json",
		Client: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := iamjwt.NewVerifier(iamjwt.VerifierOptions{
		JWKS:     jwks,
		Issuer:   srv.Issuer(),
		Audience: "my-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &stack{mock: srv, verifier: verifier}
}

func TestAuth_MissingHeader(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver()
	mw := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("should not reach") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestAuth_BadToken(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver()
	mw := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("should not reach") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestAuth_Valid(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver().Given("admin", "posts:*", "users:read")
	mw := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver, ClientID: "my-app"})

	tok, err := s.mock.TokenFor("u1", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	reached := false
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		u := authz.FromContext(r.Context())
		if u == nil || u.Subject != "u1" {
			t.Fatalf("bad user: %+v", u)
		}
		if !u.HasPermission("posts", "read") {
			t.Fatal("wildcard match broken")
		}
	})).ServeHTTP(rec, req)
	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached=%v code=%d", reached, rec.Code)
	}
}

func TestRequirePerm(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver().
		Given("admin", "posts:*").
		Given("viewer", "posts:read")
	auth := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver, ClientID: "my-app"})
	requireWrite := middleware.RequirePerm(authz.PermissionKey{Resource: "posts", Action: "write"})

	// admin allowed
	tok, _ := s.mock.TokenFor("u1", []string{"admin"})
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth(requireWrite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("admin should pass, got %d", rec.Code)
	}

	// viewer denied
	tok2, _ := s.mock.TokenFor("u2", []string{"viewer"})
	req2 := httptest.NewRequest("POST", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+tok2)
	rec2 := httptest.NewRecorder()
	auth(requireWrite(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("should 403") }))).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("viewer should be 403, got %d", rec2.Code)
	}
}

func TestRequireAnyPerm(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver().Given("viewer", "posts:read")
	auth := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver, ClientID: "my-app"})

	tok, _ := s.mock.TokenFor("u1", []string{"viewer"})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	any := middleware.RequireAnyPerm([]authz.PermissionKey{
		{Resource: "posts", Action: "read"},
		{Resource: "posts", Action: "write"},
	})
	auth(any(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("want 204, got %d", rec.Code)
	}
}

func TestRequireAllPerms(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver().Given("editor", "posts:read", "posts:write")
	auth := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver, ClientID: "my-app"})
	all := middleware.RequireAllPerms([]authz.PermissionKey{
		{Resource: "posts", Action: "read"},
		{Resource: "posts", Action: "write"},
	})
	tok, _ := s.mock.TokenFor("u", []string{"editor"})
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth(all(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("want 204, got %d", rec.Code)
	}
}

func TestRequireNoImpersonation(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver().Given("admin", "posts:*")
	auth := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver, ClientID: "my-app"})

	tok, _ := s.mock.TokenForWith("u1", []string{"admin"}, map[string]any{"act": map[string]any{"sub": "admin-actor"}})
	req := httptest.NewRequest("POST", "/danger", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mw := middleware.RequireNoImpersonation()
	auth(mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("should 403") }))).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("impersonation should be blocked, got %d", rec.Code)
	}
}

func TestRequireStepUp(t *testing.T) {
	s := newStack(t)
	resolver := iamtest.NewMockResolver().Given("admin", "posts:*")
	auth := middleware.Auth(middleware.AuthConfig{Verifier: s.verifier, Resolver: resolver, ClientID: "my-app"})
	mfa := middleware.RequireStepUp("urn:iam:acr:mfa")

	// without acr → 403
	tok, _ := s.mock.TokenFor("u1", []string{"admin"})
	req := httptest.NewRequest("POST", "/transfer", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth(mfa(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("should 403") }))).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}

	// with acr → allowed
	tok2, _ := s.mock.TokenForWith("u1", []string{"admin"}, map[string]any{"acr": "urn:iam:acr:mfa"})
	req2 := httptest.NewRequest("POST", "/transfer", nil)
	req2.Header.Set("Authorization", "Bearer "+tok2)
	rec2 := httptest.NewRecorder()
	auth(mfa(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(rec2, req2)
	if rec2.Code != 204 {
		t.Fatalf("want 204, got %d", rec2.Code)
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":     "abc",
		"bearer abc":     "abc",
		"BEARER   xyz  ": "xyz",
		"":               "",
		"Token abc":      "",
		"Bearer":         "",
	}
	for h, want := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		if got := middleware.BearerToken(req); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", h, got, want)
		}
	}
}
