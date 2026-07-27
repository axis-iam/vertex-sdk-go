package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// PortalOpenAPIReadScope is the explicit client_credentials scope for read calls.
	PortalOpenAPIReadScope PortalOpenAPIScope = "portal:openapi:read"
	// PortalOpenAPIWriteScope is the explicit client_credentials scope for write calls.
	PortalOpenAPIWriteScope PortalOpenAPIScope = "portal:openapi:write"
	// RegistrationGrantsReadScope is required for registration-grant list and detail requests.
	RegistrationGrantsReadScope PortalOpenAPIScope = "registration_grants:read"
	// RegistrationGrantsWriteScope is required for registration-grant create and lifecycle requests.
	RegistrationGrantsWriteScope PortalOpenAPIScope = "registration_grants:write"
	// RegistrationGrantsRedemptionsReadScope is required for redemption-history requests.
	RegistrationGrantsRedemptionsReadScope PortalOpenAPIScope = "registration_grants:redemptions:read"
	// OrganizationsReadScope is required for Organization list and detail requests.
	OrganizationsReadScope PortalOpenAPIScope = "organizations:read"
	// OrganizationsWriteScope is required for Organization create, update, and delete requests.
	OrganizationsWriteScope PortalOpenAPIScope = "organizations:write"
	// OrganizationInvitationsReadScope is required for Organization invitation list and detail requests.
	OrganizationInvitationsReadScope PortalOpenAPIScope = "organization_invitations:read"
	// OrganizationInvitationsWriteScope is required for Organization invitation lifecycle requests.
	OrganizationInvitationsWriteScope PortalOpenAPIScope = "organization_invitations:write"
	// OrganizationMembersReadScope is required for Organization member list and detail requests.
	OrganizationMembersReadScope PortalOpenAPIScope = "organization_members:read"
	// OrganizationMembersWriteScope is required for Organization member role and removal requests.
	OrganizationMembersWriteScope PortalOpenAPIScope = "organization_members:write"
	// RolesReadScope is required for role list and detail requests.
	RolesReadScope PortalOpenAPIScope = "roles:read"
	// RolesWriteScope is required for role lifecycle requests.
	RolesWriteScope PortalOpenAPIScope = "roles:write"
	// PermissionsReadScope is required for permission list and detail requests.
	PermissionsReadScope PortalOpenAPIScope = "permissions:read"
	// PermissionsWriteScope is required for permission lifecycle requests.
	PermissionsWriteScope PortalOpenAPIScope = "permissions:write"
	// RolePermissionsReadScope is required for role binding list requests.
	RolePermissionsReadScope PortalOpenAPIScope = "role_permissions:read"
	// RolePermissionsWriteScope is required for role binding replacement.
	RolePermissionsWriteScope PortalOpenAPIScope = "role_permissions:write"
	// UserRolesReadScope is required for user assignment list requests.
	UserRolesReadScope PortalOpenAPIScope = "user_roles:read"
	// UserRolesWriteScope is required for user assignment lifecycle requests.
	UserRolesWriteScope PortalOpenAPIScope = "user_roles:write"
)

const (
	defaultPortalOpenAPITimeout   = 5 * time.Second
	defaultPortalOpenAPITokenSkew = 30 * time.Second
)

var (
	// ErrPortalOpenAPIConfig identifies invalid Portal Open API client configuration.
	ErrPortalOpenAPIConfig = errors.New("iam portal open api: config error")
	// ErrPortalOpenAPIToken identifies token acquisition or token response failures.
	ErrPortalOpenAPIToken = errors.New("iam portal open api: token error")
	// ErrPortalOpenAPIRequest identifies Portal resource request failures.
	ErrPortalOpenAPIRequest = errors.New("iam portal open api: request error")
)

// PortalOpenAPIScope is one of the explicit M2M scopes supported by iam-portal.
type PortalOpenAPIScope string

// PortalOpenAPIClientConfig configures the server-side confidential client for
// iam-portal /open/v1/** requests.
type PortalOpenAPIClientConfig struct {
	// Issuer is the IAM issuer/auth server base URL. Tokens are requested from
	// {Issuer}/oauth2/token.
	Issuer string
	// PortalEndpoint is the iam-portal base URL used for /open/v1/** resource requests.
	PortalEndpoint string
	// ClientID is the M2M confidential ApplicationClient.clientId.
	ClientID string
	// ClientSecret is the M2M confidential ApplicationClient secret. Never expose
	// it to browser or native client code.
	ClientSecret string
	// Timeout is applied when HTTPClient is nil. Default 5s.
	Timeout time.Duration
	// TokenSkew is subtracted from expires_in before caching. Default 30s.
	TokenSkew time.Duration
	// HTTPClient optionally overrides the HTTP transport. If nil, a client with
	// Timeout is created.
	HTTPClient *http.Client
}

// PortalOpenAPIMachineToken is a cached machine token for one explicit scope.
type PortalOpenAPIMachineToken struct {
	AccessToken string
	Scope       PortalOpenAPIScope
	ExpiresAt   time.Time
}

// PortalOpenAPITokenError describes a failed /oauth2/token request or invalid token response.
type PortalOpenAPITokenError struct {
	Status int
	Code   string
	Body   string
}

func (e *PortalOpenAPITokenError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("iam portal open api token: %s: %d %s", e.Code, e.Status, e.Body)
	}
	return fmt.Sprintf("iam portal open api token: %s", e.Code)
}

// Unwrap lets callers use errors.Is(err, ErrPortalOpenAPIToken).
func (e *PortalOpenAPITokenError) Unwrap() error { return ErrPortalOpenAPIToken }

// PortalOpenAPIError describes a failed Portal /open/v1/** resource request.
type PortalOpenAPIError struct {
	Status     int
	Code       string
	Body       string
	RetryAfter string
}

func (e *PortalOpenAPIError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("iam portal open api request: %s: %d %s", e.Code, e.Status, e.Body)
	}
	return fmt.Sprintf("iam portal open api request: %s", e.Code)
}

// Unwrap lets callers use errors.Is(err, ErrPortalOpenAPIRequest).
func (e *PortalOpenAPIError) Unwrap() error { return ErrPortalOpenAPIRequest }

// PortalOpenAPIClient is a server-side M2M client for iam-portal /open/v1/**.
//
// It obtains client_credentials machine tokens with explicit
// portal:openapi:read or portal:openapi:write scope, caches read/write tokens
// separately, and sends only Authorization: Bearer <machine_token> to Portal
// resource endpoints.
type PortalOpenAPIClient struct {
	issuer         string
	portalEndpoint string
	clientID       string
	clientSecret   string
	tokenSkew      time.Duration
	http           *http.Client

	mu         sync.Mutex
	tokenCache map[PortalOpenAPIScope]PortalOpenAPIMachineToken
}

// NewPortalOpenAPIClient constructs a server-side confidential Portal Open API client.
func NewPortalOpenAPIClient(cfg PortalOpenAPIClientConfig) (*PortalOpenAPIClient, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	portalEndpoint := strings.TrimRight(strings.TrimSpace(cfg.PortalEndpoint), "/")
	clientID := strings.TrimSpace(cfg.ClientID)
	clientSecret := strings.TrimSpace(cfg.ClientSecret)
	if issuer == "" {
		return nil, fmt.Errorf("%w: Issuer is required", ErrPortalOpenAPIConfig)
	}
	if portalEndpoint == "" {
		return nil, fmt.Errorf("%w: PortalEndpoint is required", ErrPortalOpenAPIConfig)
	}
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("%w: ClientID and ClientSecret are required for M2M confidential client", ErrPortalOpenAPIConfig)
	}
	if cfg.TokenSkew < 0 {
		return nil, fmt.Errorf("%w: TokenSkew must be non-negative", ErrPortalOpenAPIConfig)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultPortalOpenAPITimeout
	}
	tokenSkew := cfg.TokenSkew
	if tokenSkew == 0 {
		tokenSkew = defaultPortalOpenAPITokenSkew
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &PortalOpenAPIClient{
		issuer:         issuer,
		portalEndpoint: portalEndpoint,
		clientID:       clientID,
		clientSecret:   clientSecret,
		tokenSkew:      tokenSkew,
		http:           httpClient,
		tokenCache:     map[PortalOpenAPIScope]PortalOpenAPIMachineToken{},
	}, nil
}

// GetMachineToken returns a cached or freshly requested machine token for an explicit scope.
func (c *PortalOpenAPIClient) GetMachineToken(ctx context.Context, scope PortalOpenAPIScope) (*PortalOpenAPIMachineToken, error) {
	if err := validatePortalOpenAPIScope(scope); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.tokenCache[scope]; ok && cached.ExpiresAt.After(time.Now()) {
		token := cached
		return &token, nil
	}
	token, err := c.requestMachineToken(ctx, scope)
	if err != nil {
		return nil, err
	}
	c.tokenCache[scope] = *token
	return token, nil
}

// ClearTokenCache clears cached read/write tokens, or only one scope when provided.
func (c *PortalOpenAPIClient) ClearTokenCache(scopes ...PortalOpenAPIScope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(scopes) == 0 {
		clear(c.tokenCache)
		return
	}
	for _, scope := range scopes {
		delete(c.tokenCache, scope)
	}
}

// RequestJSON calls a Portal /open/v1/** JSON endpoint with a bearer machine token.
//
// GET uses portal:openapi:read. POST, PUT, PATCH, and DELETE use
// portal:openapi:write. The resource request never sends Basic auth,
// X-IAM-Client-Id, X-Application-Id, or X-App-Key.
func (c *PortalOpenAPIClient) RequestJSON(ctx context.Context, method, path string, body any, out any) error {
	normalizedMethod, err := normalizePortalOpenAPIMethod(method)
	if err != nil {
		return err
	}
	return c.requestJSONWithScope(ctx, normalizedMethod, path, portalOpenAPIScopeForMethod(normalizedMethod), body, out)
}

func (c *PortalOpenAPIClient) requestJSONWithScope(
	ctx context.Context, method, path string, scope PortalOpenAPIScope, body any, out any,
) error {
	_, err := c.requestJSONWithScopeAndHeaders(ctx, method, path, scope, body, out, nil)
	return err
}

func (c *PortalOpenAPIClient) requestJSONWithScopeAndHeaders(
	ctx context.Context,
	method, path string,
	scope PortalOpenAPIScope,
	body any,
	out any,
	extraHeaders http.Header,
) (http.Header, error) {
	normalizedMethod, err := normalizePortalOpenAPIMethod(method)
	if err != nil {
		return nil, err
	}
	resourceURL, err := c.portalURL(path)
	if err != nil {
		return nil, err
	}
	if err := validatePortalOpenAPIScope(scope); err != nil {
		return nil, err
	}
	if err := validatePortalOpenAPIHeaders(extraHeaders); err != nil {
		return nil, err
	}
	token, err := c.GetMachineToken(ctx, scope)
	if err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, normalizedMethod, resourceURL, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, values := range extraHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, portalOpenAPIErrorFromResponse(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Header.Clone(), nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	return resp.Header.Clone(), nil
}

func (c *PortalOpenAPIClient) requestMachineToken(ctx context.Context, scope PortalOpenAPIScope) (*PortalOpenAPIMachineToken, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", string(scope))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &payload)
	}
	if resp.StatusCode >= 400 {
		code := firstString(payload, "error", "code", "errorCode")
		if code == "" {
			code = "token_request_failed"
		}
		return nil, &PortalOpenAPITokenError{
			Status: resp.StatusCode,
			Code:   code,
			Body:   string(raw),
		}
	}
	accessToken := strings.TrimSpace(firstString(payload, "access_token"))
	if accessToken == "" {
		return nil, &PortalOpenAPITokenError{Status: resp.StatusCode, Code: "missing_bearer_token", Body: string(raw)}
	}
	if !strings.EqualFold(firstString(payload, "token_type"), "bearer") {
		return nil, &PortalOpenAPITokenError{Status: resp.StatusCode, Code: "missing_bearer_token", Body: string(raw)}
	}
	expiresIn, ok := numberFromJSON(payload["expires_in"])
	if !ok || expiresIn <= 0 {
		return nil, &PortalOpenAPITokenError{Status: resp.StatusCode, Code: "invalid_token_response", Body: string(raw)}
	}
	responseScope := firstString(payload, "scope")
	if responseScope == "" {
		responseScope = string(scope)
	}
	if !stringFields(strings.Fields(responseScope)).contains(string(scope)) {
		return nil, &PortalOpenAPITokenError{Status: resp.StatusCode, Code: "invalid_scope", Body: string(raw)}
	}
	ttl := time.Duration(math.Max(expiresIn-c.tokenSkew.Seconds(), 0) * float64(time.Second))
	return &PortalOpenAPIMachineToken{
		AccessToken: accessToken,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(ttl),
	}, nil
}

func (c *PortalOpenAPIClient) portalURL(path string) (string, error) {
	if !strings.HasPrefix(path, "/open/v1/") {
		return "", &PortalOpenAPIError{Code: "invalid_portal_path", Body: path}
	}
	return c.portalEndpoint + path, nil
}

func validatePortalOpenAPIScope(scope PortalOpenAPIScope) error {
	switch scope {
	case PortalOpenAPIReadScope, PortalOpenAPIWriteScope, RegistrationGrantsReadScope,
		RegistrationGrantsWriteScope, RegistrationGrantsRedemptionsReadScope,
		OrganizationsReadScope, OrganizationsWriteScope,
		OrganizationInvitationsReadScope, OrganizationInvitationsWriteScope,
		OrganizationMembersReadScope, OrganizationMembersWriteScope:
		return nil
	case RolesReadScope, RolesWriteScope, PermissionsReadScope, PermissionsWriteScope,
		RolePermissionsReadScope, RolePermissionsWriteScope, UserRolesReadScope, UserRolesWriteScope:
		return nil
	case "":
		return &PortalOpenAPITokenError{Code: "invalid_scope", Body: "Portal Open API token requests require an explicit scope"}
	default:
		return &PortalOpenAPITokenError{Code: "invalid_scope", Body: string(scope)}
	}
}

func normalizePortalOpenAPIMethod(method string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(method))
	switch normalized {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return normalized, nil
	default:
		return "", &PortalOpenAPIError{Code: "invalid_portal_method", Body: method}
	}
}

func portalOpenAPIScopeForMethod(method string) PortalOpenAPIScope {
	if method == http.MethodGet {
		return PortalOpenAPIReadScope
	}
	return PortalOpenAPIWriteScope
}

func portalOpenAPIErrorFromResponse(resp *http.Response) error {
	raw, _ := io.ReadAll(resp.Body)
	payload := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &payload)
	}
	code := firstString(payload, "code", "error", "errorCode")
	if code == "" {
		code = fmt.Sprintf("HTTP_%d", resp.StatusCode)
	}
	return &PortalOpenAPIError{
		Status:     resp.StatusCode,
		Code:       code,
		Body:       string(raw),
		RetryAfter: resp.Header.Get("Retry-After"),
	}
}

func validatePortalOpenAPIHeaders(headers http.Header) error {
	for key := range headers {
		switch strings.ToLower(key) {
		case "authorization", "x-iam-client-id", "x-application-id", "x-app-key":
			return &PortalOpenAPIError{Code: "invalid_portal_header", Body: key}
		}
	}
	return nil
}

func firstString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func numberFromJSON(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

type stringFields []string

func (fields stringFields) contains(value string) bool {
	for _, field := range fields {
		if field == value {
			return true
		}
	}
	return false
}
