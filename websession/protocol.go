package websession

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	iam "github.com/axis-iam/vertex-sdk-go"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

type tokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	ID      string `json:"id_token"`
	Type    string `json:"token_type"`
	Expires int64  `json:"expires_in"`
	Scope   string `json:"scope"`
	subject string
}

func (s *Service) token(ctx context.Context, form url.Values, nonce string, isRefresh bool) (tokens, error) {
	var t tokens
	err := s.request(ctx, "POST", "/oauth2/token", form, "", nil, &t, true)
	if err != nil {
		return t, err
	}
	if t.Access == "" || t.Type != "Bearer" || t.Expires <= 0 || t.Expires > 1<<31 {
		return t, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	if !isRefresh && contains(s.cfg.Scopes, "openid") && t.ID == "" {
		return t, failure(401, "OIDC_INVALID", ErrInvalidSession)
	}
	if t.ID != "" {
		subject, err := s.verifyID(ctx, t.ID, nonce, isRefresh)
		if err != nil {
			return t, err
		}
		t.subject = subject
	}
	return t, nil
}

func contains(a []string, b string) bool {
	for _, x := range a {
		if x == b {
			return true
		}
	}
	return false
}

func challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *Service) verifyID(ctx context.Context, raw, nonce string, refresh bool) (string, error) {
	bad := failure(401, "OIDC_INVALID", ErrInvalidSession)
	token, err := josejwt.ParseSigned(raw, s.algs)
	if err != nil || len(token.Headers) != 1 || token.Headers[0].KeyID == "" {
		return "", bad
	}
	key, err := s.keys.KeyByID(ctx, token.Headers[0].KeyID)
	if err != nil {
		if errors.Is(err, iamjwt.ErrUnknownKey) {
			return "", bad
		}
		return "", failure(503, "IAM_JWKS_UNAVAILABLE", errors.Join(ErrUnavailable, err))
	}
	var claims struct {
		josejwt.Claims
		Nonce string `json:"nonce"`
		AZP   string `json:"azp"`
	}
	if token.Claims(key, &claims) != nil || claims.Expiry == nil || claims.IssuedAt == nil ||
		claims.Subject == "" || claims.IssuedAt.Time().After(s.cfg.Clock().Add(30*time.Second)) ||
		claims.ValidateWithLeeway(josejwt.Expected{Issuer: s.cfg.Issuer, Time: s.cfg.Clock(), AnyAudience: josejwt.Audience{s.cfg.ClientID}}, 0) != nil ||
		(len(claims.Audience) > 1 && claims.AZP != s.cfg.ClientID) || (claims.AZP != "" && claims.AZP != s.cfg.ClientID) ||
		(!refresh && claims.Nonce != nonce) || (refresh && claims.Nonce != "" && claims.Nonce != nonce) {
		return "", bad
	}
	return claims.Subject, nil
}

type validity struct {
	SessionID       string    `json:"sessionId"`
	ClientID        string    `json:"clientId"`
	ApplicationID   string    `json:"applicationId"`
	ExpiresAt       time.Time `json:"expiresAt"`
	IdleExpiresAt   time.Time `json:"idleExpiresAt"`
	AccessExpiresAt time.Time `json:"accessExpiresAt"`
}

func (s *Service) validity(ctx context.Context, r *Record) error {
	var v validity
	if err := s.request(ctx, "GET", "/api/v1/auth/session/validity", nil, r.AccessToken, nil, &v, false); err != nil {
		return err
	}
	c := r.Profile.AuthenticationContext
	if v.SessionID != c.SessionID || v.ClientID != s.cfg.ClientID || v.ApplicationID != c.ApplicationID ||
		v.ExpiresAt.IsZero() || v.IdleExpiresAt.IsZero() || v.AccessExpiresAt.IsZero() {
		return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	now := s.cfg.Clock()
	r.AbsoluteExpiresAt = minTime(r.AbsoluteExpiresAt, v.ExpiresAt)
	r.IdleExpiresAt = minTime(r.AbsoluteExpiresAt, v.IdleExpiresAt, now.Add(s.cfg.IdleTTL))
	r.AccessExpiresAt = minTime(r.AccessExpiresAt, v.AccessExpiresAt)
	if expired(*r, now) || !now.Before(r.AccessExpiresAt) {
		return failure(401, "SESSION_INVALIDATED", ErrInvalidSession)
	}
	return nil
}

func (s *Service) identity(ctx context.Context, r *Record) error {
	var raw json.RawMessage
	if err := s.request(ctx, "GET", "/api/v1/auth/me", nil, r.AccessToken, nil, &raw, false); err != nil {
		return err
	}
	p, err := iam.ParseCurrentUser(raw)
	if err != nil || !uuidPattern.MatchString(p.ID) || !uuidPattern.MatchString(p.AuthenticationContext.ApplicationID) ||
		p.AuthenticationContext.ClientID != s.cfg.ClientID {
		return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	r.Profile = p
	for _, id := range []*string{p.AuthenticationContext.WorkspaceID, p.AuthenticationContext.OrganizationID} {
		if id != nil && !uuidPattern.MatchString(*id) {
			return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
	}
	var perms struct {
		ApplicationID  string   `json:"applicationId"`
		OrganizationID *string  `json:"organizationId"`
		Roles          []string `json:"roles"`
		Permissions    []string `json:"permissions"`
	}
	path := "/api/v1/auth/me/permissions"
	if p.AuthenticationContext.OrganizationID != nil {
		path += "?organizationId=" + url.QueryEscape(*p.AuthenticationContext.OrganizationID)
	}
	var rawPermissions json.RawMessage
	if err := s.request(ctx, "GET", path, nil, r.AccessToken, nil, &rawPermissions, false); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if decode(rawPermissions, &keys, false) != nil || keys["organizationId"] == nil || decode(rawPermissions, &perms, false) != nil {
		return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	if perms.ApplicationID != p.AuthenticationContext.ApplicationID || !equalOptional(perms.OrganizationID, p.AuthenticationContext.OrganizationID) ||
		perms.Roles == nil || perms.Permissions == nil {
		return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	for _, key := range perms.Permissions {
		if !permissionPattern.MatchString(key) {
			return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
	}
	r.Permissions = &Permissions{Roles: perms.Roles, Permissions: perms.Permissions}
	for _, role := range perms.Roles {
		if strings.TrimSpace(role) == "" {
			return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
	}
	return s.validity(ctx, r)
}

// Hosted starts a bound top-level navigation after bootstrap. The provider CAS
// binds exactly one attempt; it never replaces an authenticated identity.
func (s *Service) Hosted(ctx context.Context, id, returnTo string) (string, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return "", err
	}
	if r.Kind != "prelogin" || r.State != Prelogin || r.OAuthState != "" {
		return "", failure(409, "SESSION_ACTION_PENDING", ErrConflict)
	}
	if returnTo == "" {
		returnTo = s.cfg.ReturnTo
	}
	if !contains(s.cfg.AllowedReturnTo, returnTo) {
		return "", invalid()
	}
	r.OAuthState, r.Verifier, r.Nonce, r.ReturnTo = random(), random(), random(), returnTo
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		return "", storeError(err)
	}
	challenge := sha256.Sum256([]byte(r.Verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {s.cfg.ClientID}, "redirect_uri": {s.cfg.CallbackURL},
		"scope": {strings.Join(s.cfg.Scopes, " ")}, "state": {r.OAuthState}, "nonce": {r.Nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	return strings.TrimRight(s.cfg.Issuer, "/") + "/oauth2/authorize?" + q.Encode(), nil
}
