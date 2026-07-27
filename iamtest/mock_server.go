package iamtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	jwt "github.com/go-jose/go-jose/v4/jwt"
)

// MockServer is an httptest.Server that exposes the subset of IAM endpoints
// the SDK needs: OIDC discovery, JWKS, resolve, and permission snapshots.
type MockServer struct {
	*httptest.Server

	mu           sync.Mutex
	roleToPerms  map[string][]string
	meCalls      int
	tokenCalls   map[string]int
	userProfiles map[string]UserProfileDTO

	signer      jose.Signer
	privateKey  *ecdsa.PrivateKey
	keyID       string
	issuer      string
	audienceFor string
}

// PermissionDefinitionDTO mirrors the SDK's wire format (duplicated to avoid
// a dependency on the top-level iam package).
type PermissionDefinitionDTO struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// AccountOrganizationDTO mirrors current-user organization membership responses.
type AccountOrganizationDTO struct {
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	Slug           string `json:"slug,omitempty"`
	Role           string `json:"role"`
	JoinedAt       string `json:"joinedAt,omitempty"`
	Current        bool   `json:"current"`
}

// UserProfileDTO mirrors GET /api/v1/auth/me/profile.
//
// Metadata is profile metadata for test profile responses, not App User
// authorization attributes.
type UserProfileDTO struct {
	UserID              string                  `json:"userId"`
	ApplicationID       string                  `json:"applicationId,omitempty"`
	GlobalIdentityID    string                  `json:"globalIdentityId,omitempty"`
	Email               string                  `json:"email"`
	EmailVerified       bool                    `json:"emailVerified"`
	Username            string                  `json:"username"`
	DisplayName         string                  `json:"displayName,omitempty"`
	AvatarURL           string                  `json:"avatarUrl,omitempty"`
	Status              string                  `json:"status"`
	CreatedAt           string                  `json:"createdAt,omitempty"`
	UpdatedAt           string                  `json:"updatedAt,omitempty"`
	CurrentOrganization *AccountOrganizationDTO `json:"currentOrganization,omitempty"`
	Roles               []string                `json:"roles,omitempty"`
	Metadata            map[string]any          `json:"metadata,omitempty"`
}

// NewMockServer spins up a server. Call s.Close() when done.
func NewMockServer() (*MockServer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		return nil, err
	}
	m := &MockServer{
		roleToPerms:  map[string][]string{},
		tokenCalls:   map[string]int{},
		userProfiles: map[string]UserProfileDTO{},
		signer:       signer,
		privateKey:   priv,
		keyID:        "test-key",
	}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	m.issuer = m.Server.URL
	return m, nil
}

// Issuer returns the URL of the server (used as the JWT issuer).
func (m *MockServer) Issuer() string { return m.issuer }

// WithAudience sets the aud claim stamped by TokenFor.
func (m *MockServer) WithAudience(aud string) *MockServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audienceFor = aud
	return m
}

// Given maps a role → perms for the resolve endpoint.
func (m *MockServer) Given(role string, perms ...string) *MockServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roleToPerms[role] = append([]string(nil), perms...)
	return m
}

// GivenUserProfile configures the response returned by /api/v1/auth/me for a subject.
func (m *MockServer) GivenUserProfile(subject string, profile UserProfileDTO) *MockServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userProfiles[subject] = profile
	return m
}

// TokenFor signs a JWT for the given subject + roles, with default validity
// of 5 minutes.
func (m *MockServer) TokenFor(subject string, roles []string) (string, error) {
	return m.TokenForWith(subject, roles, nil)
}

// TokenForWith signs a JWT with extra claims merged in (typically app_id,
// org_id, acr, etc.).
func (m *MockServer) TokenForWith(subject string, roles []string, extra map[string]any) (string, error) {
	m.mu.Lock()
	aud := m.audienceFor
	iss := m.issuer
	m.mu.Unlock()

	now := time.Now()
	claims := map[string]any{
		"iss":   iss,
		"sub":   subject,
		"roles": roles,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	}
	if aud != "" {
		claims["aud"] = aud
	}
	maps.Copy(claims, extra)
	return jwt.Signed(m.signer).Claims(claims).Serialize()
}

// MeCalls returns how many times /api/v1/auth/me was invoked.
func (m *MockServer) MeCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meCalls
}

// TokenCalls returns how many /oauth2/token requests used the given scope.
func (m *MockServer) TokenCalls(scope string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokenCalls[scope]
}

// ----- handler -----

func (m *MockServer) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/.well-known/openid-configuration":
		m.writeJSON(w, map[string]any{
			"issuer":   m.issuer,
			"jwks_uri": m.issuer + "/.well-known/jwks.json",
		})
	case r.URL.Path == "/.well-known/jwks.json":
		m.writeJWKS(w)
	case r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost:
		m.token(w, r)
	case r.URL.Path == "/open/v1/permissions:resolve" && r.Method == http.MethodPost:
		m.resolve(w, r)
	case r.URL.Path == "/api/v1/auth/me/profile" && r.Method == http.MethodGet:
		m.me(w, r)
	case r.URL.Path == "/api/v1/auth/me/profile" && r.Method == http.MethodPatch:
		m.me(w, r)
	case r.URL.Path == "/api/v1/auth/me/security" && r.Method == http.MethodGet:
		if !m.requireBearer(w, r) {
			return
		}
		m.writeJSON(w, map[string]any{
			"emailVerified":             true,
			"passwordCredentialPresent": true,
			"mfaEnrolled":               false,
			"totpEnrolled":              false,
			"webAuthnEnrolled":          false,
			"activeSessionCount":        2,
		})
	case r.URL.Path == "/api/v1/auth/email/verification/send" && r.Method == http.MethodPost:
		m.writeJSON(w, map[string]any{
			"message":           "If eligible, a verification email has been sent. Please wait before retrying.",
			"retryAfterSeconds": 60,
		})
	case r.URL.Path == "/api/v1/auth/email/verification/verify" && r.Method == http.MethodPost:
		m.writeJSON(w, map[string]any{"message": "Email verified", "retryAfterSeconds": nil})
	case r.URL.Path == "/api/v1/auth/password/change" && r.Method == http.MethodPost:
		if !m.requireBearer(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v1/auth/password/forgot" && r.Method == http.MethodPost:
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v1/auth/password/reset" && r.Method == http.MethodPost:
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v1/auth/sessions" && r.Method == http.MethodGet:
		if !m.requireBearer(w, r) {
			return
		}
		m.writeJSON(w, []map[string]any{{
			"sessionId":  "sid-current",
			"ipAddress":  "127.0.0.1",
			"userAgent":  "iamtest",
			"deviceId":   nil,
			"createdAt":  "2026-07-07T00:00:00Z",
			"lastSeenAt": "2026-07-07T01:00:00Z",
			"current":    true,
		}})
	case strings.HasPrefix(r.URL.Path, "/api/v1/auth/sessions/") && r.Method == http.MethodDelete:
		if !m.requireBearer(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v1/auth/sessions" && r.Method == http.MethodDelete:
		if !m.requireBearer(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v1/auth/logout" && r.Method == http.MethodPost:
		if !m.requireBearer(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v1/auth/me/organizations" && r.Method == http.MethodGet:
		if !m.requireBearer(w, r) {
			return
		}
		m.writeJSON(w, []AccountOrganizationDTO{{
			OrganizationID: "org-1",
			Name:           "Acme",
			Slug:           "acme",
			Role:           "ADMIN",
			JoinedAt:       "2026-07-06T00:00:00Z",
			Current:        true,
		}})
	case r.URL.Path == "/api/v1/auth/me/organizations/current" && r.Method == http.MethodGet:
		if !m.requireBearer(w, r) {
			return
		}
		m.writeJSON(w, AccountOrganizationDTO{
			OrganizationID: "org-1",
			Name:           "Acme",
			Slug:           "acme",
			Role:           "ADMIN",
			JoinedAt:       "2026-07-06T00:00:00Z",
			Current:        true,
		})
	case r.URL.Path == "/api/v1/auth/me/organizations/current" && r.Method == http.MethodPost:
		if !m.requireBearer(w, r) {
			return
		}
		m.writeJSONStatus(w, http.StatusAccepted, map[string]any{
			"organizationId":       "org-2",
			"continuation":         "REFRESH_OR_REAUTHENTICATE_WITH_ORGANIZATION",
			"tokenRefreshRequired": true,
			"message":              "Refresh token to receive the new organization context.",
		})
	case r.URL.Path == "/api/v1/auth/me/permissions" && r.Method == http.MethodGet:
		if !m.requireBearer(w, r) {
			return
		}
		organizationID := r.URL.Query().Get("organizationId")
		if organizationID == "" {
			organizationID = "org-1"
		}
		m.writeJSON(w, map[string]any{
			"applicationId":  "app-1",
			"organizationId": organizationID,
			"roles":          []string{"admin"},
			"permissions":    []string{"orders:read", "orders:*"},
		})
	case r.URL.Path == "/api/v1/auth/me/permissions:check" && r.Method == http.MethodPost:
		if !m.requireBearer(w, r) {
			return
		}
		m.writeJSON(w, map[string]any{
			"applicationId":  "app-1",
			"organizationId": "org-1",
			"permission":     "orders:write",
			"allowed":        true,
			"roles":          []string{"admin"},
		})
	case strings.HasPrefix(r.URL.Path, "/api/v1/auth/organization-invitations/") && strings.HasSuffix(r.URL.Path, "/accept") && r.Method == http.MethodPost:
		m.writeJSONStatus(w, http.StatusAccepted, map[string]any{
			"status":           "LOGIN_REQUIRED",
			"continuation":     "LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT",
			"applicationId":    "app-1",
			"organizationId":   "org-1",
			"organizationName": "Acme",
			"role":             "MEMBER",
		})
	case strings.HasPrefix(r.URL.Path, "/api/v1/auth/organization-invitations/") && r.Method == http.MethodGet:
		m.writeJSON(w, map[string]any{
			"applicationId":    "app-1",
			"applicationName":  "Demo",
			"organizationId":   "org-1",
			"organizationName": "Acme",
			"inviteeEmail":     "a***@example.com",
			"role":             "MEMBER",
			"status":           "PENDING",
			"expiresAt":        "2026-07-08T00:00:00Z",
		})
	case strings.HasSuffix(r.URL.Path, "/permissions") && r.Method == http.MethodGet:
		m.list(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (m *MockServer) token(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := r.BasicAuth(); !ok {
		m.writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	if err := r.ParseForm(); err != nil {
		m.writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if r.Form.Get("grant_type") != "client_credentials" {
		m.writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}
	scope := r.Form.Get("scope")
	if scope == "" {
		m.writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
		return
	}
	m.mu.Lock()
	m.tokenCalls[scope]++
	call := m.tokenCalls[scope]
	m.mu.Unlock()
	m.writeJSON(w, map[string]any{
		"access_token": "mock-" + scope + "-" + strconv.Itoa(call),
		"token_type":   "Bearer",
		"expires_in":   120,
		"scope":        scope,
	})
}

func (m *MockServer) writeJWKS(w http.ResponseWriter) {
	jwk := jose.JSONWebKey{Key: &m.privateKey.PublicKey, KeyID: m.keyID, Algorithm: "ES256", Use: "sig"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	m.writeJSON(w, set)
}

func (m *MockServer) resolve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string   `json:"clientId"`
		Roles    []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	m.mu.Lock()
	seen := map[string]struct{}{}
	var out []string
	for _, role := range req.Roles {
		for _, p := range m.roleToPerms[role] {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	m.mu.Unlock()
	m.writeJSON(w, map[string]any{"permissions": out})
}

func (m *MockServer) me(w http.ResponseWriter, r *http.Request) {
	if !m.requireBearer(w, r) {
		return
	}
	m.mu.Lock()
	m.meCalls++
	profile, ok := m.userProfiles["u1"]
	m.mu.Unlock()
	if !ok {
		profile = UserProfileDTO{
			UserID:        "u1",
			ApplicationID: "app-1",
			Email:         "u1@example.com",
			EmailVerified: true,
			Username:      "u1",
			Status:        "ACTIVE",
		}
	}
	m.writeJSON(w, profile)
}

func (m *MockServer) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return false
	}
	return true
}

func (m *MockServer) list(w http.ResponseWriter, r *http.Request) {
	cid := extractClientID(r.URL.Path, "")
	m.mu.Lock()
	seen := map[string]struct{}{}
	perms := make([]PermissionDefinitionDTO, 0)
	for _, values := range m.roleToPerms {
		for _, key := range values {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			parts := strings.SplitN(key, ":", 2)
			if len(parts) == 2 {
				perms = append(perms, PermissionDefinitionDTO{Resource: parts[0], Action: parts[1]})
			}
		}
	}
	m.mu.Unlock()
	keys := make([]string, 0, len(perms))
	for _, permission := range perms {
		keys = append(keys, permission.Resource+":"+permission.Action)
	}
	m.writeJSON(w, map[string]any{
		"applicationId": "123e4567-e89b-42d3-a456-426614174000",
		"clientId":      cid,
		"roles":         []map[string]any{{"key": "registered", "name": "Registered", "permissions": keys}},
	})
}

func (m *MockServer) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (m *MockServer) writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// /open/v1/apps/{cid}/permissions
func extractClientID(path, suffix string) string {
	const prefix = "/open/v1/apps/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	if suffix != "" {
		rest = strings.TrimSuffix(rest, "/permissions"+suffix)
	} else {
		rest = strings.TrimSuffix(rest, "/permissions")
	}
	return rest
}
