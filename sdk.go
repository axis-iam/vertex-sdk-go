package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/axis-iam/vertex-sdk-go/authz"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
	"github.com/axis-iam/vertex-sdk-go/middleware"
	"github.com/dgraph-io/ristretto/v2"
)

// SDK is the high-level composite used by applications. It bundles a
// *Client, a JWT verifier, and a permission resolver.
//
// Applications typically construct an SDK once at startup, install its
// Authenticate middleware on the router and use RequirePerm on individual
// routes.
type SDK struct {
	cfg             *SDKConfig
	client          *Client
	verifier        *iamjwt.Verifier
	resolver        authz.Resolver
	profileCache    *ristretto.Cache[string, *UserProfile]
	profileCacheTTL time.Duration
}

// New constructs an SDK from cfg. It:
//
//  1. validates cfg
//  2. creates an IAM client
//  3. performs OIDC discovery to obtain jwks_uri
//  4. builds the JWT verifier and HTTP-backed permission resolver
func New(cfg *SDKConfig) (*SDK, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return buildSDK(cfg, client)
}

func buildSDK(cfg *SDKConfig, client *Client) (*SDK, error) {
	jwksURL, err := discoverJWKS(context.Background(), client)
	if err != nil {
		return nil, fmt.Errorf("iam: oidc discovery: %w", err)
	}
	jwks, err := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{
		URL:     jwksURL,
		Client:  client.HTTP(),
		Refresh: cfg.JWKSRefresh,
	})
	if err != nil {
		return nil, err
	}
	verifier, err := iamjwt.NewVerifier(iamjwt.VerifierOptions{
		JWKS:     jwks,
		Issuer:   cfg.Issuer,
		Audience: cfg.Audience,
	})
	if err != nil {
		return nil, err
	}
	resolver, err := authz.NewHttpResolver(resolverShim{client}, authz.HttpResolverOptions{
		TTL:        cfg.PermissionCacheTTL,
		MaxEntries: cfg.PermissionCacheMax,
		FailOpen:   cfg.FailMode == FailOpen,
	})
	if err != nil {
		return nil, err
	}
	profileCache, err := newUserProfileCache(cfg)
	if err != nil {
		return nil, err
	}
	return &SDK{
		cfg:             cfg,
		client:          client,
		verifier:        verifier,
		resolver:        resolver,
		profileCache:    profileCache,
		profileCacheTTL: cfg.UserProfileCacheTTL,
	}, nil
}

// Client returns the low-level HTTP client.
func (s *SDK) Client() *Client { return s.client }

// Resolver returns the permission resolver.
func (s *SDK) Resolver() authz.Resolver { return s.resolver }

// Verifier returns the JWT verifier.
func (s *SDK) Verifier() *iamjwt.Verifier { return s.verifier }

// FromContext returns the authenticated IAM user carried by ctx, if any.
func FromContext(ctx context.Context) *authz.User { return authz.FromContext(ctx) }

// MustUser returns the authenticated IAM user or authz.ErrUnauthenticated.
func MustUser(ctx context.Context) (*authz.User, error) {
	u := authz.FromContext(ctx)
	if u == nil {
		return nil, authz.ErrUnauthenticated
	}
	return u, nil
}

// UserProfileOption configures SDK.GetMe profile lookup behavior.
type UserProfileOption func(*userProfileOptions)

type userProfileOptions struct {
	bypassCache bool
}

// BypassProfileCache forces SDK.GetMe to call IAM even if a cached profile
// exists. The fresh result replaces the cached entry.
func BypassProfileCache() UserProfileOption {
	return func(o *userProfileOptions) { o.bypassCache = true }
}

// GetMe returns the current user's latest profile from GET /api/v1/auth/me.
// It uses a short local cache keyed by request user id when available, or by a
// SHA-256 digest of the bearer token otherwise. Authorization checks should use
// FromContext and resolved permissions instead of this profile response. Profile
// metadata is not App User authorization attributes.
func (s *SDK) GetMe(ctx context.Context, accessToken string, opts ...UserProfileOption) (*UserProfile, error) {
	var options userProfileOptions
	for _, fn := range opts {
		fn(&options)
	}
	if s.profileCache == nil {
		return s.client.GetMe(ctx, accessToken)
	}
	key := profileCacheKey(ctx, accessToken)
	if !options.bypassCache {
		if cached, ok := s.profileCache.Get(key); ok {
			return cached, nil
		}
	}
	profile, err := s.client.GetMe(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	s.profileCache.SetWithTTL(key, profile, 1, s.profileCacheTTL)
	s.profileCache.Wait()
	return profile, nil
}

// UpdateAccountProfile updates safe scalar profile fields for the current user.
func (s *SDK) UpdateAccountProfile(ctx context.Context, accessToken string, input AccountUpdateProfileRequest) (*UserProfile, error) {
	if s.profileCache != nil {
		s.profileCache.Del(profileCacheKey(ctx, accessToken))
	}
	return s.client.UpdateAccountProfile(ctx, accessToken, input)
}

// GetAccountSecuritySummary returns a secret-free current-user security summary.
func (s *SDK) GetAccountSecuritySummary(ctx context.Context, accessToken string) (*AccountSecuritySummary, error) {
	return s.client.GetAccountSecuritySummary(ctx, accessToken)
}

// SendEmailVerification starts the opaque public email verification send flow.
func (s *SDK) SendEmailVerification(ctx context.Context, email string) (*EmailVerificationResponse, error) {
	return s.client.SendEmailVerification(ctx, email)
}

// VerifyEmail verifies a public email-verification token.
func (s *SDK) VerifyEmail(ctx context.Context, token string) (*EmailVerificationResponse, error) {
	return s.client.VerifyEmail(ctx, token)
}

// ChangePassword changes the current user's password with bearer auth.
func (s *SDK) ChangePassword(ctx context.Context, accessToken string, input PasswordChangeRequest) error {
	return s.client.ChangePassword(ctx, accessToken, input)
}

// RequestPasswordReset starts the opaque public forgot-password flow.
func (s *SDK) RequestPasswordReset(ctx context.Context, email, redirectURI string) error {
	return s.client.RequestPasswordReset(ctx, email, redirectURI)
}

// ResetPassword completes the public password reset flow.
func (s *SDK) ResetPassword(ctx context.Context, token, newPassword string) error {
	return s.client.ResetPassword(ctx, token, newPassword)
}

// ListAccountSessions lists the current user's active sessions.
func (s *SDK) ListAccountSessions(ctx context.Context, accessToken string) ([]SessionView, error) {
	return s.client.ListAccountSessions(ctx, accessToken)
}

// RevokeAccountSession revokes one session owned by the current user.
func (s *SDK) RevokeAccountSession(ctx context.Context, accessToken, sessionID string) error {
	return s.client.RevokeAccountSession(ctx, accessToken, sessionID)
}

// RevokeOtherAccountSessions revokes all sessions except the current token's sid.
func (s *SDK) RevokeOtherAccountSessions(ctx context.Context, accessToken string) error {
	return s.client.RevokeOtherAccountSessions(ctx, accessToken)
}

// LogoutAccount logs out the current token/session and optionally revokes a refresh token.
func (s *SDK) LogoutAccount(ctx context.Context, accessToken, refreshToken string) error {
	return s.client.LogoutAccount(ctx, accessToken, refreshToken)
}

// ListAccountOrganizations lists the current user's Application-scoped Organizations.
func (s *SDK) ListAccountOrganizations(ctx context.Context, accessToken string) ([]AccountOrganization, error) {
	return s.client.ListAccountOrganizations(ctx, accessToken)
}

// GetCurrentAccountOrganization returns the selected Organization context, if any.
func (s *SDK) GetCurrentAccountOrganization(ctx context.Context, accessToken string) (*AccountOrganization, error) {
	return s.client.GetCurrentAccountOrganization(ctx, accessToken)
}

// SwitchAccountOrganization validates membership and returns a refresh/reauth continuation.
func (s *SDK) SwitchAccountOrganization(ctx context.Context, accessToken, organizationID string) (*OrganizationSwitchResponse, error) {
	return s.client.SwitchAccountOrganization(ctx, accessToken, organizationID)
}

// HasAccountOrganizationMembership derives membership from the Organization list.
func (s *SDK) HasAccountOrganizationMembership(ctx context.Context, accessToken, organizationID string) (bool, error) {
	return s.client.HasAccountOrganizationMembership(ctx, accessToken, organizationID)
}

// GetAccountPermissionSummary resolves current-user permissions in IAM.
func (s *SDK) GetAccountPermissionSummary(ctx context.Context, accessToken, organizationID string) (*AccountPermissionSummary, error) {
	return s.client.GetAccountPermissionSummary(ctx, accessToken, organizationID)
}

// CheckAccountPermission checks one permission through IAM.
func (s *SDK) CheckAccountPermission(ctx context.Context, accessToken, permission, organizationID string) (*PermissionCheckResponse, error) {
	return s.client.CheckAccountPermission(ctx, accessToken, permission, organizationID)
}

// PreviewOrganizationInvitation returns safe public invitation metadata without bearer auth.
func (s *SDK) PreviewOrganizationInvitation(ctx context.Context, invitationToken string) (*PublicOrganizationInvitationPreview, error) {
	return s.client.PreviewOrganizationInvitation(ctx, invitationToken)
}

// AcceptOrganizationInvitation accepts or continues a public Organization invitation flow.
func (s *SDK) AcceptOrganizationInvitation(ctx context.Context, invitationToken, accessToken string) (*PublicOrganizationInvitationAcceptResponse, error) {
	return s.client.AcceptOrganizationInvitation(ctx, invitationToken, accessToken)
}

// AuthOption configures the Authenticate middleware.
type AuthOption func(*middleware.AuthConfig)

// WithAuthResponder substitutes the ErrorResponder used when authentication
// fails.
func WithAuthResponder(r middleware.ErrorResponder) AuthOption {
	return func(c *middleware.AuthConfig) { c.Responder = r }
}

// Authenticate returns a net/http middleware that validates the bearer JWT
// and injects an authz.User into the request context.
func (s *SDK) Authenticate(opts ...AuthOption) func(http.Handler) http.Handler {
	cfg := middleware.AuthConfig{
		Verifier: s.verifier,
		Resolver: s.resolver,
		ClientID: s.cfg.ClientID,
	}
	for _, fn := range opts {
		fn(&cfg)
	}
	return middleware.Auth(cfg)
}

// RequirePerm is shorthand for middleware.RequirePerm using this SDK.
func (s *SDK) RequirePerm(perm authz.PermissionKey, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequirePerm(perm, opts...)
}

// RequireAnyPerm is shorthand for middleware.RequireAnyPerm using this SDK.
func (s *SDK) RequireAnyPerm(perms []authz.PermissionKey, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireAnyPerm(perms, opts...)
}

// RequireAllPerms is shorthand for middleware.RequireAllPerms using this SDK.
func (s *SDK) RequireAllPerms(perms []authz.PermissionKey, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireAllPerms(perms, opts...)
}

// RequireStepUp is shorthand for middleware.RequireStepUp using this SDK.
func (s *SDK) RequireStepUp(acr string, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireStepUp(acr, opts...)
}

// RequireNoImpersonation is shorthand for middleware.RequireNoImpersonation using this SDK.
func (s *SDK) RequireNoImpersonation(opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireNoImpersonation(opts...)
}

// ----- discovery -----

type oidcConfiguration struct {
	JWKSURI string `json:"jwks_uri"`
}

func discoverJWKS(ctx context.Context, client *Client) (string, error) {
	url := strings.TrimRight(client.Endpoint(), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.HTTP().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("openid discovery: %s", resp.Status)
	}
	var oc oidcConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&oc); err != nil {
		return "", err
	}
	if oc.JWKSURI == "" {
		return "", errors.New("openid discovery: jwks_uri missing")
	}
	return oc.JWKSURI, nil
}

func newUserProfileCache(cfg *SDKConfig) (*ristretto.Cache[string, *UserProfile], error) {
	if cfg.DisableUserProfileCache {
		return nil, nil
	}
	return ristretto.NewCache(&ristretto.Config[string, *UserProfile]{
		NumCounters: cfg.UserProfileCacheMax * 10,
		MaxCost:     cfg.UserProfileCacheMax,
		BufferItems: 64,
	})
}

func profileCacheKey(ctx context.Context, accessToken string) string {
	if u := authz.FromContext(ctx); u != nil && u.Subject != "" {
		return "user:" + u.AppID + ":" + u.Subject
	}
	sum := sha256.Sum256([]byte(normalizeBearer(accessToken)))
	return "token:" + hex.EncodeToString(sum[:])
}

// ----- resolver shim -----

type resolverShim struct{ c *Client }

func (s resolverShim) ResolvePermissions(ctx context.Context, clientID string, roles []string) (*authz.ResolvePermissionsResponse, error) {
	resp, err := s.c.ResolvePermissions(ctx, clientID, roles)
	if err != nil {
		return nil, err
	}
	return &authz.ResolvePermissionsResponse{Permissions: resp.Permissions}, nil
}
