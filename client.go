package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// Client is a low-level HTTP client against the IAM server's /open/v1 API.
// It is safe for concurrent use.
type Client struct {
	cfg  *SDKConfig
	http *http.Client
}

// NewClient constructs a Client from cfg. cfg.Validate() is called; callers
// should normally use New (in sdk.go) which also builds the verifier, resolver
// and registrar.
func NewClient(cfg *SDKConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.HTTPTimeout},
	}, nil
}

// Endpoint returns the normalized IAM endpoint (no trailing slash).
func (c *Client) Endpoint() string { return strings.TrimRight(c.cfg.Endpoint, "/") }

// Config returns a pointer to the underlying config. Callers must not mutate
// fields used by the SDK (Endpoint, ClientID, ...).
func (c *Client) Config() *SDKConfig { return c.cfg }

// HTTP exposes the underlying http.Client (e.g. for test override).
func (c *Client) HTTP() *http.Client { return c.http }

// SetHTTPClient lets callers inject a custom http.Client. Intended for tests.
func (c *Client) SetHTTPClient(h *http.Client) { c.http = h }

// ResolvePermissionsRequest is the request body for /open/v1/permissions:resolve.
type ResolvePermissionsRequest struct {
	ClientID string   `json:"clientId"`
	Roles    []string `json:"roles"`
}

// ResolvePermissionsResponse is the response body for /open/v1/permissions:resolve.
type ResolvePermissionsResponse struct {
	Permissions []string `json:"permissions"`
}

var permissionSegment = regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)
var canonicalPermissionSnapshotUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ResolvePermissions calls POST /open/v1/permissions:resolve.
func (c *Client) ResolvePermissions(ctx context.Context, clientID string, roles []string) (*ResolvePermissionsResponse, error) {
	if len(roles) == 0 {
		return &ResolvePermissionsResponse{Permissions: []string{}}, nil
	}
	body := ResolvePermissionsRequest{ClientID: clientID, Roles: roles}
	var wire resolvePermissionsWire
	if err := c.doJSONStrictRetry(ctx, http.MethodPost, "/open/v1/permissions:resolve", body, &wire); err != nil {
		return nil, err
	}
	permissions, err := strictResolvedPermissionKeys(wire.Permissions)
	if err != nil {
		return nil, fmt.Errorf("iam: invalid permission resolve response: %w", err)
	}
	return &ResolvePermissionsResponse{Permissions: permissions}, nil
}

func strictResolvedPermissionKeys(values *[]string) ([]string, error) {
	if values == nil {
		return nil, errors.New("permissions is required")
	}
	seen := make(map[string]struct{}, len(*values))
	out := make([]string, 0, len(*values))
	for _, key := range *values {
		parts := strings.Split(key, ":")
		valid := len(parts) == 2 && ((parts[0] == "*" && parts[1] == "*") ||
			(parts[0] != "*" && permissionSegment.MatchString(parts[0]) &&
				(parts[1] == "*" || permissionSegment.MatchString(parts[1]))))
		if !valid {
			return nil, fmt.Errorf("malformed permission key %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate permission key %q", key)
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, nil
}

type resolvePermissionsWire struct {
	Permissions *[]string `json:"permissions"`
}

// PermissionDefinitionDTO mirrors the request/response shape used by the
// /open/v1/apps/{cid}/permissions endpoints. It is intentionally duplicated
// here (rather than imported from authz) to keep the client package free of
// circular dependencies.
type PermissionDefinitionDTO struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// ListPermissionsResponse is the response body for
// GET /open/v1/apps/{cid}/permissions.
type ListPermissionsResponse struct {
	Permissions []PermissionDefinitionDTO `json:"permissions"`
}

type permissionSnapshotWire struct {
	ApplicationID *string                       `json:"applicationId"`
	ClientID      *string                       `json:"clientId"`
	Roles         *[]permissionSnapshotRoleWire `json:"roles"`
}

type permissionSnapshotRoleWire struct {
	Key         *string   `json:"key"`
	Name        *string   `json:"name"`
	Permissions *[]string `json:"permissions"`
}

// ListPermissions calls GET /open/v1/apps/{cid}/permissions.
func (c *Client) ListPermissions(ctx context.Context, clientID string) (*ListPermissionsResponse, error) {
	path := fmt.Sprintf("/open/v1/apps/%s/permissions", url.PathEscape(clientID))
	var wire permissionSnapshotWire
	if err := c.doJSONStrictRetry(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}
	permissions, err := parsePermissionSnapshot(wire, clientID)
	if err != nil {
		return nil, fmt.Errorf("iam: invalid permission snapshot response: %w", err)
	}
	return &ListPermissionsResponse{Permissions: permissions}, nil
}

func parsePermissionSnapshot(wire permissionSnapshotWire, clientID string) ([]PermissionDefinitionDTO, error) {
	if wire.ApplicationID == nil || !canonicalPermissionSnapshotUUID.MatchString(*wire.ApplicationID) || wire.ClientID == nil || *wire.ClientID != clientID || wire.Roles == nil {
		return nil, errors.New("required applicationId, matching clientId, and roles are required")
	}
	roleKeys := make(map[string]struct{}, len(*wire.Roles))
	permissionKeys := make(map[string]struct{})
	var out []PermissionDefinitionDTO
	for _, role := range *wire.Roles {
		if role.Key == nil || !permissionSegment.MatchString(*role.Key) || role.Name == nil || strings.TrimSpace(*role.Name) == "" || role.Permissions == nil {
			return nil, errors.New("role key, name, and permissions are required")
		}
		if _, duplicate := roleKeys[*role.Key]; duplicate {
			return nil, fmt.Errorf("duplicate role key %q", *role.Key)
		}
		roleKeys[*role.Key] = struct{}{}
		rolePermissions, err := strictResolvedPermissionKeys(role.Permissions)
		if err != nil {
			return nil, err
		}
		for _, key := range rolePermissions {
			if _, seen := permissionKeys[key]; seen {
				continue
			}
			permissionKeys[key] = struct{}{}
			parts := strings.SplitN(key, ":", 2)
			out = append(out, PermissionDefinitionDTO{Resource: parts[0], Action: parts[1]})
		}
	}
	return out, nil
}

// AccountOrganization is the current user's Application-scoped Organization membership.
type AccountOrganization struct {
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	Slug           string `json:"slug,omitempty"`
	Role           string `json:"role"`
	JoinedAt       string `json:"joinedAt,omitempty"`
	Current        bool   `json:"current"`
}

// UserProfile is the response returned by GET /api/v1/auth/me/profile.
//
// Metadata is profile metadata for display/profile reads. It is not App User
// authorization attributes and must not be used as an authorization source.
type UserProfile struct {
	ID                  string               `json:"id,omitempty"` // legacy /api/v1/auth/me field
	UserID              string               `json:"userId"`
	ApplicationID       string               `json:"applicationId,omitempty"`
	GlobalIdentityID    string               `json:"globalIdentityId,omitempty"`
	Email               string               `json:"email"`
	EmailVerified       bool                 `json:"emailVerified"`
	Username            string               `json:"username"`
	DisplayName         string               `json:"displayName,omitempty"`
	AvatarURL           string               `json:"avatarUrl,omitempty"`
	Status              string               `json:"status"`
	CreatedAt           string               `json:"createdAt,omitempty"`
	UpdatedAt           string               `json:"updatedAt,omitempty"`
	CurrentOrganization *AccountOrganization `json:"currentOrganization,omitempty"`
	Roles               []string             `json:"roles,omitempty"` // legacy /api/v1/auth/me field
	// Metadata is /api/v1/auth/me profile metadata, not app-scoped authorization attributes.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AccountUpdateProfileRequest is the safe scalar profile update request.
type AccountUpdateProfileRequest struct {
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
}

// AccountSecuritySummary is the current user's secret-free security summary.
type AccountSecuritySummary struct {
	EmailVerified             bool `json:"emailVerified"`
	PasswordCredentialPresent bool `json:"passwordCredentialPresent"`
	MFAEnrolled               bool `json:"mfaEnrolled"`
	TOTPEnrolled              bool `json:"totpEnrolled"`
	WebAuthnEnrolled          bool `json:"webAuthnEnrolled"`
	ActiveSessionCount        int  `json:"activeSessionCount"`
}

// EmailVerificationResponse is returned by public email verification helpers.
type EmailVerificationResponse struct {
	Message           string `json:"message"`
	RetryAfterSeconds *int   `json:"retryAfterSeconds"`
}

// PasswordChangeRequest is the authenticated password-change body.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// SessionView is the current user's session/device view.
type SessionView struct {
	SessionID  string `json:"sessionId"`
	IPAddress  string `json:"ipAddress,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	DeviceID   string `json:"deviceId,omitempty"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	Current    bool   `json:"current"`
}

// AccountPermissionSummary is the current user's IAM-resolved permission summary.
type AccountPermissionSummary struct {
	ApplicationID  string   `json:"applicationId"`
	OrganizationID string   `json:"organizationId,omitempty"`
	Roles          []string `json:"roles"`
	Permissions    []string `json:"permissions"`
}

// PermissionCheckResponse is returned by current-user permission checks.
type PermissionCheckResponse struct {
	ApplicationID  string   `json:"applicationId"`
	OrganizationID string   `json:"organizationId,omitempty"`
	Permission     string   `json:"permission"`
	Allowed        bool     `json:"allowed"`
	Roles          []string `json:"roles"`
}

// OrganizationSwitchResponse is returned after requesting a current Organization switch.
type OrganizationSwitchResponse struct {
	OrganizationID       string `json:"organizationId"`
	Continuation         string `json:"continuation"`
	TokenRefreshRequired bool   `json:"tokenRefreshRequired"`
	Message              string `json:"message,omitempty"`
}

// PublicOrganizationInvitationPreview is the safe public invitation preview.
type PublicOrganizationInvitationPreview struct {
	ApplicationID    string `json:"applicationId"`
	ApplicationName  string `json:"applicationName"`
	OrganizationID   string `json:"organizationId"`
	OrganizationName string `json:"organizationName"`
	InviteeEmail     string `json:"inviteeEmail"`
	Role             string `json:"role"`
	Status           string `json:"status"`
	ExpiresAt        string `json:"expiresAt"`
}

// PublicOrganizationInvitationAcceptResponse is the invitation accept result.
type PublicOrganizationInvitationAcceptResponse struct {
	Status           string `json:"status"`
	Continuation     string `json:"continuation,omitempty"`
	ApplicationID    string `json:"applicationId"`
	OrganizationID   string `json:"organizationId"`
	OrganizationName string `json:"organizationName"`
	Role             string `json:"role"`
	AcceptedAt       string `json:"acceptedAt,omitempty"`
}

// GetMe calls GET /api/v1/auth/me/profile with the user's bearer access token. It is
// uncached; use SDK.GetMe for the short-TTL profile cache. The returned
// Metadata is profile metadata, not authorization attributes.
func (c *Client) GetMe(ctx context.Context, accessToken string) (*UserProfile, error) {
	return c.GetAccountProfile(ctx, accessToken)
}

// GetAccountProfile calls GET /api/v1/auth/me/profile with the user's bearer token.
func (c *Client) GetAccountProfile(ctx context.Context, accessToken string) (*UserProfile, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	var out UserProfile
	if err := c.doJSONBearerRetry(ctx, http.MethodGet, "/api/v1/auth/me/profile", token, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateAccountProfile calls PATCH /api/v1/auth/me/profile with safe scalar profile fields.
func (c *Client) UpdateAccountProfile(ctx context.Context, accessToken string, input AccountUpdateProfileRequest) (*UserProfile, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	var out UserProfile
	if err := c.doJSONBearerRetry(ctx, http.MethodPatch, "/api/v1/auth/me/profile", token, input, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAccountSecuritySummary calls GET /api/v1/auth/me/security with the user's bearer token.
func (c *Client) GetAccountSecuritySummary(ctx context.Context, accessToken string) (*AccountSecuritySummary, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	var out AccountSecuritySummary
	if err := c.doJSONBearerRetry(ctx, http.MethodGet, "/api/v1/auth/me/security", token, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendEmailVerification starts the opaque public email verification send flow.
func (c *Client) SendEmailVerification(ctx context.Context, email string) (*EmailVerificationResponse, error) {
	if strings.TrimSpace(email) == "" {
		return nil, errors.New("iam: email is required")
	}
	body := map[string]string{"email": email, "client_id": c.cfg.ClientID}
	var out EmailVerificationResponse
	if err := c.doJSONNoAuthRetry(ctx, http.MethodPost, "/api/v1/auth/email/verification/send", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyEmail verifies a public email-verification token.
func (c *Client) VerifyEmail(ctx context.Context, token string) (*EmailVerificationResponse, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("iam: verification token is required")
	}
	var out EmailVerificationResponse
	if err := c.doJSONNoAuthRetry(ctx, http.MethodPost, "/api/v1/auth/email/verification/verify", map[string]string{"token": token}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChangePassword calls the authenticated password-change endpoint.
func (c *Client) ChangePassword(ctx context.Context, accessToken string, input PasswordChangeRequest) error {
	token := normalizeBearer(accessToken)
	if token == "" {
		return errors.New("iam: access token is required")
	}
	return c.doJSONBearerRetry(ctx, http.MethodPost, "/api/v1/auth/password/change", token, input, nil)
}

// RequestPasswordReset starts the opaque public forgot-password flow.
func (c *Client) RequestPasswordReset(ctx context.Context, email, redirectURI string) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("iam: email is required")
	}
	body := map[string]string{"email": email, "client_id": c.cfg.ClientID}
	if strings.TrimSpace(redirectURI) != "" {
		body["redirect_uri"] = redirectURI
	}
	return c.doJSONNoAuthRetry(ctx, http.MethodPost, "/api/v1/auth/password/forgot", body, nil)
}

// ResetPassword completes the public password reset flow.
func (c *Client) ResetPassword(ctx context.Context, token, newPassword string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("iam: reset token is required")
	}
	return c.doJSONNoAuthRetry(ctx, http.MethodPost, "/api/v1/auth/password/reset", map[string]string{"token": token, "newPassword": newPassword}, nil)
}

// ListAccountSessions lists the current user's active sessions.
func (c *Client) ListAccountSessions(ctx context.Context, accessToken string) ([]SessionView, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	var out []SessionView
	if err := c.doJSONBearerRetry(ctx, http.MethodGet, "/api/v1/auth/sessions", token, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeAccountSession revokes one session owned by the current user.
func (c *Client) RevokeAccountSession(ctx context.Context, accessToken, sessionID string) error {
	token := normalizeBearer(accessToken)
	if token == "" {
		return errors.New("iam: access token is required")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("iam: session id is required")
	}
	return c.doJSONBearerRetry(ctx, http.MethodDelete, "/api/v1/auth/sessions/"+url.PathEscape(sessionID), token, nil, nil)
}

// RevokeOtherAccountSessions revokes all sessions except the current token's sid.
func (c *Client) RevokeOtherAccountSessions(ctx context.Context, accessToken string) error {
	token := normalizeBearer(accessToken)
	if token == "" {
		return errors.New("iam: access token is required")
	}
	return c.doJSONBearerRetry(ctx, http.MethodDelete, "/api/v1/auth/sessions", token, nil, nil)
}

// LogoutAccount blacklists the current token/session and optionally revokes a refresh token.
func (c *Client) LogoutAccount(ctx context.Context, accessToken, refreshToken string) error {
	token := normalizeBearer(accessToken)
	if token == "" {
		return errors.New("iam: access token is required")
	}
	var body any
	if strings.TrimSpace(refreshToken) != "" {
		body = map[string]string{"refresh_token": refreshToken}
	}
	return c.doJSONBearerRetry(ctx, http.MethodPost, "/api/v1/auth/logout", token, body, nil)
}

// ListAccountOrganizations calls GET /api/v1/auth/me/organizations.
func (c *Client) ListAccountOrganizations(ctx context.Context, accessToken string) ([]AccountOrganization, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	var out []AccountOrganization
	if err := c.doJSONBearerRetry(ctx, http.MethodGet, "/api/v1/auth/me/organizations", token, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetCurrentAccountOrganization calls GET /api/v1/auth/me/organizations/current.
func (c *Client) GetCurrentAccountOrganization(ctx context.Context, accessToken string) (*AccountOrganization, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	var out *AccountOrganization
	if err := c.doJSONBearerRetry(ctx, http.MethodGet, "/api/v1/auth/me/organizations/current", token, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SwitchAccountOrganization validates membership and returns the server continuation.
func (c *Client) SwitchAccountOrganization(ctx context.Context, accessToken, organizationID string) (*OrganizationSwitchResponse, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	if strings.TrimSpace(organizationID) == "" {
		return nil, errors.New("iam: organization id is required")
	}
	var out OrganizationSwitchResponse
	body := map[string]string{"organizationId": organizationID}
	if err := c.doJSONBearerRetry(ctx, http.MethodPost, "/api/v1/auth/me/organizations/current", token, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HasAccountOrganizationMembership derives membership from the Organization list.
func (c *Client) HasAccountOrganizationMembership(ctx context.Context, accessToken, organizationID string) (bool, error) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return false, errors.New("iam: organization id is required")
	}
	orgs, err := c.ListAccountOrganizations(ctx, accessToken)
	if err != nil {
		return false, err
	}
	for _, org := range orgs {
		if org.OrganizationID == organizationID {
			return true, nil
		}
	}
	return false, nil
}

// GetAccountPermissionSummary resolves current-user permissions in the active or explicit Organization context.
func (c *Client) GetAccountPermissionSummary(ctx context.Context, accessToken, organizationID string) (*AccountPermissionSummary, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	path := "/api/v1/auth/me/permissions"
	if strings.TrimSpace(organizationID) != "" {
		path += "?organizationId=" + url.QueryEscape(strings.TrimSpace(organizationID))
	}
	var out AccountPermissionSummary
	if err := c.doJSONBearerRetry(ctx, http.MethodGet, path, token, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckAccountPermission checks one permission through IAM. Wildcard semantics are backend-owned.
func (c *Client) CheckAccountPermission(ctx context.Context, accessToken, permission, organizationID string) (*PermissionCheckResponse, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return nil, errors.New("iam: permission is required")
	}
	body := map[string]string{"permission": permission}
	if strings.TrimSpace(organizationID) != "" {
		body["organizationId"] = strings.TrimSpace(organizationID)
	}
	var out PermissionCheckResponse
	if err := c.doJSONBearerRetry(ctx, http.MethodPost, "/api/v1/auth/me/permissions:check", token, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewOrganizationInvitation calls the public invitation preview endpoint without bearer auth.
func (c *Client) PreviewOrganizationInvitation(ctx context.Context, invitationToken string) (*PublicOrganizationInvitationPreview, error) {
	token := strings.TrimSpace(invitationToken)
	if token == "" {
		return nil, errors.New("iam: invitation token is required")
	}
	var out PublicOrganizationInvitationPreview
	path := "/api/v1/auth/organization-invitations/" + url.PathEscape(token)
	if err := c.doJSONNoAuthRetry(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AcceptOrganizationInvitation calls the public invitation accept endpoint. Pass an empty
// accessToken to receive IAM's login-required continuation when unauthenticated.
func (c *Client) AcceptOrganizationInvitation(ctx context.Context, invitationToken, accessToken string) (*PublicOrganizationInvitationAcceptResponse, error) {
	token := strings.TrimSpace(invitationToken)
	if token == "" {
		return nil, errors.New("iam: invitation token is required")
	}
	var out PublicOrganizationInvitationAcceptResponse
	path := "/api/v1/auth/organization-invitations/" + url.PathEscape(token) + "/accept"
	bearer := normalizeBearer(accessToken)
	var err error
	if bearer == "" {
		err = c.doJSONNoAuthRetry(ctx, http.MethodPost, path, map[string]any{}, &out)
	} else {
		err = c.doJSONBearerRetry(ctx, http.MethodPost, path, bearer, map[string]any{}, &out)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKS returns the raw JWKS JSON body served by the issuer's well-known
// endpoint. Used by the jwt sub-package.
func (c *Client) JWKS(ctx context.Context, jwksURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("iam: jwks fetch failed: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// APIError is returned for non-2xx responses from the IAM server.
type APIError struct {
	Status int
	Body   string
}

type strictJSONResponseError struct{ cause error }

func (e *strictJSONResponseError) Error() string { return e.cause.Error() }
func (e *strictJSONResponseError) Unwrap() error { return e.cause }

func (e *APIError) Error() string { return fmt.Sprintf("iam api: %d %s", e.Status, e.Body) }

// IsRetryable reports whether the error should trigger retries.
func (e *APIError) IsRetryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

func (c *Client) doJSONRetry(ctx context.Context, method, path string, body any, out any) error {
	op := func() error { return c.doJSON(ctx, method, path, body, out) }
	b := backoff.WithContext(backoff.WithMaxRetries(exponentialBackoff(), uint64(c.cfg.MaxRetries)), ctx)
	return backoff.Retry(func() error {
		err := op()
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.IsRetryable() {
			return backoff.Permanent(err)
		}
		return err
	}, b)
}

func (c *Client) doJSONStrictRetry(ctx context.Context, method, path string, body any, out any) error {
	op := func() error { return c.doJSONStrict(ctx, method, path, body, out) }
	b := backoff.WithContext(backoff.WithMaxRetries(exponentialBackoff(), uint64(c.cfg.MaxRetries)), ctx)
	return backoff.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return backoff.Permanent(err)
		}
		err := op()
		if err == nil {
			return nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return backoff.Permanent(err)
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if apiErr.IsRetryable() {
				return err
			}
			return backoff.Permanent(err)
		}
		var strictErr *strictJSONResponseError
		if errors.As(err, &strictErr) {
			return backoff.Permanent(err)
		}
		return err
	}, b)
}

func (c *Client) doJSONNoAuthRetry(ctx context.Context, method, path string, body any, out any) error {
	op := func() error { return c.doJSONWithAuth(ctx, method, path, body, out, func(*http.Request) {}) }
	b := backoff.WithContext(backoff.WithMaxRetries(exponentialBackoff(), uint64(c.cfg.MaxRetries)), ctx)
	return backoff.Retry(func() error {
		err := op()
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.IsRetryable() {
			return backoff.Permanent(err)
		}
		return err
	}, b)
}

func (c *Client) doJSONBearerRetry(ctx context.Context, method, path, token string, body any, out any) error {
	op := func() error { return c.doJSONBearer(ctx, method, path, token, body, out) }
	b := backoff.WithContext(backoff.WithMaxRetries(exponentialBackoff(), uint64(c.cfg.MaxRetries)), ctx)
	return backoff.Retry(func() error {
		err := op()
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.IsRetryable() {
			return backoff.Permanent(err)
		}
		return err
	}, b)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	return c.doJSONWithAuth(ctx, method, path, body, out, c.signRequest)
}

func (c *Client) doJSONStrict(ctx context.Context, method, path string, body any, out any) error {
	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint()+path, buf)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	c.signRequest(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	if err := decodeStrictJSON(raw, out); err != nil {
		return &strictJSONResponseError{cause: err}
	}
	return nil
}

func (c *Client) doJSONBearer(ctx context.Context, method, path, token string, body any, out any) error {
	return c.doJSONWithAuth(ctx, method, path, body, out, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	})
}

func (c *Client) doJSONWithAuth(ctx context.Context, method, path string, body any, out any, sign func(*http.Request)) error {
	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint()+path, buf)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	sign(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return &APIError{Status: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) signRequest(req *http.Request) {
	if c.cfg.ClientID != "" {
		req.Header.Set("X-IAM-Client-Id", c.cfg.ClientID)
	}
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	}
}

func normalizeBearer(accessToken string) string {
	token := strings.TrimSpace(accessToken)
	if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	return token
}

func exponentialBackoff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 200 * time.Millisecond
	b.MaxInterval = 2 * time.Second
	b.MaxElapsedTime = 15 * time.Second
	return b
}
