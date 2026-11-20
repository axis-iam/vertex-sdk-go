package websession

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

const fixtureApp = "019b0000-0000-7000-8000-000000000001"
const fixtureUser = "019b0000-0000-7000-8000-000000000002"
const fixtureTx = "019b0000-0000-7000-8000-000000000003"
const fixtureReg = "019b0000-0000-7000-8000-000000000004"

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Time() time.Time     { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type fixture struct {
	server                                                            *httptest.Server
	key                                                               *rsa.PrivateKey
	clock                                                             *testClock
	mu                                                                sync.Mutex
	codes                                                             map[string]string
	used                                                              map[string]bool
	txState, txNonce, txBinding                                       string
	idOverride                                                        map[string]any
	noRefresh, omitPermissionContext                                  bool
	tokenCount, refreshCount, validityCount, logoutCount, revokeCount atomic.Int32
	validityStatus, tokenStatus, logoutStatus                         atomic.Int32
	refreshStarted, refreshRelease                                    chan struct{}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: key, clock: &testClock{now: time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)},
		codes: map[string]string{}, used: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixture) config(m Provider) Config {
	return Config{Issuer: f.server.URL, Audience: "resource", ClientID: "connected-web", ClientSecret: "fixture-secret",
		Origin: "http://127.0.0.1:33391", CallbackURL: "http://127.0.0.1:33391/auth/callback",
		Scopes: []string{"openid", "offline_access"}, ReturnTo: "/", AllowedReturnTo: []string{"/", "/account"},
		Provider: m, AllowLoopbackHTTP: true, Clock: f.clock.Time}
}

func newTestService(t *testing.T) (*fixture, *Memory, *Service) {
	t.Helper()
	f := newFixture(t)
	m, err := NewMemory(MemoryOptions{Clock: f.clock.Time})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s, err := New(context.Background(), f.config(m))
	if err != nil {
		t.Fatal(err)
	}
	return f, m, s
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (f *fixture) idToken(nonce string) string {
	claims := map[string]any{"iss": f.server.URL, "aud": "connected-web", "sub": fixtureUser,
		"iat": f.clock.Time().Unix(), "exp": f.clock.Time().Add(time.Hour).Unix(), "nonce": nonce}
	for k, v := range f.idOverride {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture-key"))
	if err != nil {
		panic(err)
	}
	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		jsonReply(w, 200, map[string]any{"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/jwks":
		jsonReply(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "fixture-key", Algorithm: "RS256", Use: "sig"}}})
	case "/oauth2/token":
		f.tokenCount.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != "connected-web" || secret != "fixture-secret" {
			jsonReply(w, 401, map[string]string{"error": "invalid_client"})
			return
		}
		_ = r.ParseForm()
		if status := f.tokenStatus.Load(); status != 0 {
			jsonReply(w, int(status), map[string]string{"error": "invalid_grant"})
			return
		}
		nonce := ""
		if r.Form.Get("grant_type") == "refresh_token" {
			f.refreshCount.Add(1)
			f.mu.Lock()
			started, release := f.refreshStarted, f.refreshRelease
			f.mu.Unlock()
			if started != nil {
				started <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
		} else {
			f.mu.Lock()
			code := r.Form.Get("code")
			nonce = f.codes[code]
			bad := nonce == "" || f.used[code] || r.Form.Get("redirect_uri") != "http://127.0.0.1:33391/auth/callback" || len(r.Form.Get("code_verifier")) != 43
			if !bad {
				f.used[code] = true
			}
			f.mu.Unlock()
			if bad {
				jsonReply(w, 400, map[string]string{"error": "invalid_grant"})
				return
			}
		}
		out := map[string]any{"access_token": "fixture-access", "token_type": "Bearer", "expires_in": 120}
		if !f.noRefresh {
			out["refresh_token"] = "fixture-refresh-" + random()
		}
		if nonce != "" {
			out["id_token"] = f.idToken(nonce)
		}
		jsonReply(w, 200, out)
	case "/api/v1/auth/me":
		if r.Header.Get("Authorization") != "Bearer fixture-access" {
			w.WriteHeader(401)
			return
		}
		jsonReply(w, 200, f.profile())
	case "/api/v1/auth/me/permissions":
		data := map[string]any{"applicationId": fixtureApp, "organizationId": nil, "roles": []string{"reader"}, "permissions": []string{"documents:read"}}
		if f.omitPermissionContext {
			delete(data, "organizationId")
		}
		jsonReply(w, 200, data)
	case "/api/v1/auth/session/validity":
		f.validityCount.Add(1)
		if status := f.validityStatus.Load(); status != 0 {
			jsonReply(w, int(status), map[string]string{"error": "DEPENDENCY_UNAVAILABLE"})
			return
		}
		now := f.clock.Time()
		jsonReply(w, 200, map[string]any{"sessionId": "session-one", "clientId": "connected-web", "applicationId": fixtureApp,
			"expiresAt": now.Add(time.Hour), "idleExpiresAt": now.Add(30 * time.Minute), "accessExpiresAt": now.Add(120 * time.Second)})
	case "/api/v1/auth/logout":
		f.logoutCount.Add(1)
		if status := f.logoutStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		w.WriteHeader(204)
	case "/oauth2/revoke":
		f.revokeCount.Add(1)
		w.WriteHeader(200)
	case "/api/v1/auth/transactions":
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.txNonce, _ = in["nonce"].(string)
		f.txBinding, _ = in["state"].(string)
		f.txState = "AUTHENTICATING"
		f.mu.Unlock()
		jsonReply(w, 201, map[string]any{"transactionId": fixtureTx, "controlSecret": "fixture-control", "expiresAt": f.clock.Time().Add(5 * time.Minute), "nextAction": "authenticate"})
	case "/api/v1/auth/signup":
		if r.Header.Get("Idempotency-Key") == "" {
			w.WriteHeader(400)
			return
		}
		jsonReply(w, 202, map[string]any{"registrationId": fixtureReg, "status": "PENDING_VERIFICATION", "expiresAt": f.clock.Time().Add(5 * time.Minute), "nextAction": "VERIFY_EMAIL", "controlSecret": "registration-control", "nextChallengeAt": nil})
	case "/api/v1/auth/password/forgot":
		w.WriteHeader(204)
	case "/api/v1/auth/password/reset":
		if r.Header.Get("Password-Reset-Client") != "connected-web" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	default:
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth/transactions/"+fixtureTx) {
			f.serveTransaction(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth/signup/operations/"+fixtureReg) {
			if r.Header.Get("Registration-Client") != "connected-web" {
				w.WriteHeader(400)
				return
			}
			jsonReply(w, 200, map[string]any{"registrationId": fixtureReg, "status": "VERIFIED", "expiresAt": f.clock.Time().Add(5 * time.Minute), "nextAction": "NONE", "controlSecret": nil, "nextChallengeAt": nil})
			return
		}
		http.NotFound(w, r)
	}
}

func (f *fixture) blockRefresh() {
	f.mu.Lock()
	f.refreshStarted = make(chan struct{}, 1)
	f.refreshRelease = make(chan struct{})
	f.mu.Unlock()
}

func (f *fixture) serveTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authentication-Transaction") != "fixture-control" {
		w.WriteHeader(401)
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/auth/transactions/"+fixtureTx)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch suffix {
	case "/authenticate":
		var body AuthenticateInput
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Password == "wrong" {
			jsonReply(w, 400, map[string]string{"error": "AUTHENTICATION_FAILED"})
			return
		}
		f.txState = "AUTHENTICATED"
	case "/mfa":
		f.txState = "AUTHENTICATED"
	case "/authorize":
		f.txState = "AWAITING_PROVIDER"
		jsonReply(w, 200, map[string]any{"authorizationUrl": f.server.URL + "/provider", "expiresAt": f.clock.Time().Add(time.Minute)})
		return
	case "/complete":
		if r.Header.Get("Idempotency-Key") == "" || f.txState != "AUTHENTICATED" {
			w.WriteHeader(400)
			return
		}
		code := "custom-code-" + random()
		f.codes[code] = f.txNonce
		jsonReply(w, 200, map[string]any{"kind": "authorization_code", "code": code, "state": f.txBinding, "expiresIn": 60})
		return
	case "/cancel":
		f.txState = "CANCELLED"
	case "/challenges":
		jsonReply(w, 200, map[string]any{"transactionId": fixtureTx, "expiresAt": f.clock.Time().Add(5 * time.Minute), "nextAction": "authenticate", "challengeExpiresAt": f.clock.Time().Add(time.Minute), "cooldownSeconds": 30})
		return
	}
	jsonReply(w, 200, map[string]any{"transactionId": fixtureTx, "state": f.txState, "expiresAt": f.clock.Time().Add(5 * time.Minute), "nextAction": stateActions[f.txState]})
}

func (f *fixture) profile() map[string]any {
	return map[string]any{"id": fixtureUser, "email": "reader@example.test", "username": nil, "status": "ACTIVE", "emailVerified": true, "metadata": map[string]any{},
		"authenticationContext": map[string]any{"subjectType": "USER", "applicationId": fixtureApp, "clientId": "connected-web", "sessionId": "session-one",
			"workspaceId": nil, "workspaceSelectionRequired": false, "organizationId": nil, "organizationSlug": nil, "organizationRole": nil,
			"authTime": f.clock.Time(), "authenticationMethods": []string{"PASSWORD"}, "assuranceLevel": "urn:iam:acr:password", "impersonation": nil}}
}

func hostedSession(t *testing.T, f *fixture, s *Service) (string, View) {
	t.Helper()
	ctx := context.Background()
	id, _, err := s.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	navigation, err := s.Hosted(ctx, id, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(navigation)
	f.mu.Lock()
	code := "hosted-code-" + random()
	f.codes[code] = u.Query().Get("nonce")
	f.mu.Unlock()
	next, v, _, err := s.Callback(ctx, id, url.Values{"code": {code}, "state": {u.Query().Get("state")}})
	if err != nil {
		t.Fatal(err)
	}
	return next, v
}
