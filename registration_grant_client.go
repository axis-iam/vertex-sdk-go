package iam

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

var registrationGrantUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[157][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// RegistrationGrantType is one safe registration-grant type returned by the API.
type RegistrationGrantType string

const (
	RegistrationGrantEmailLink     RegistrationGrantType = "EMAIL_LINK"
	RegistrationGrantAccessCode    RegistrationGrantType = "ACCESS_CODE"
	RegistrationGrantOrgInvitation RegistrationGrantType = "ORG_INVITATION"
)

// RegistrationGrantStatus is a safe lifecycle status returned by iam-portal.
type RegistrationGrantStatus string

const (
	RegistrationGrantActive   RegistrationGrantStatus = "ACTIVE"
	RegistrationGrantPaused   RegistrationGrantStatus = "PAUSED"
	RegistrationGrantRedeemed RegistrationGrantStatus = "REDEEMED"
	RegistrationGrantExpired  RegistrationGrantStatus = "EXPIRED"
	RegistrationGrantRevoked  RegistrationGrantStatus = "REVOKED"
)

// RegistrationGrant is a safe grant detail. It never contains a raw proof.
type RegistrationGrant struct {
	ID            string                  `json:"id"`
	Type          RegistrationGrantType   `json:"type"`
	Status        RegistrationGrantStatus `json:"status"`
	DisplayName   *string                 `json:"displayName"`
	AllowedEmail  *string                 `json:"allowedEmail"`
	AllowedDomain *string                 `json:"allowedDomain"`
	ExpiresAt     *string                 `json:"expiresAt"`
	MaxUses       *int                    `json:"maxUses"`
	UsedCount     int                     `json:"usedCount"`
	SourceType    string                  `json:"sourceType"`
	CreatedAt     string                  `json:"createdAt"`
	UpdatedAt     string                  `json:"updatedAt"`
	RevokedAt     *string                 `json:"revokedAt"`
	RevokeReason  *string                 `json:"revokeReason"`
}

// CreateRegistrationGrantRequest describes a manual EMAIL_LINK or ACCESS_CODE grant.
type CreateRegistrationGrantType string

const (
	CreateRegistrationGrantEmailLink  CreateRegistrationGrantType = "EMAIL_LINK"
	CreateRegistrationGrantAccessCode CreateRegistrationGrantType = "ACCESS_CODE"
)

type CreateRegistrationGrantRequest struct {
	Type          CreateRegistrationGrantType `json:"type"`
	DisplayName   *string                     `json:"displayName,omitempty"`
	AllowedEmail  *string                     `json:"allowedEmail,omitempty"`
	AllowedDomain *string                     `json:"allowedDomain,omitempty"`
	ExpiresAt     *string                     `json:"expiresAt,omitempty"`
	MaxUses       *int                        `json:"maxUses,omitempty"`
}

// CreatedRegistrationGrant contains the one-time raw proof returned only by create.
type CreatedRegistrationGrant struct {
	Grant                  RegistrationGrant `json:"grant"`
	RegistrationGrantToken *string           `json:"registrationGrantToken"`
	RegistrationAccessCode *string           `json:"registrationAccessCode"`
}

// RegistrationGrantListOptions filters the grant list using the API's page parameters.
type RegistrationGrantListOptions struct {
	Type   *RegistrationGrantType
	Status *RegistrationGrantStatus
	Search *string
	Page   *int
	Size   *int
}

// RegistrationGrantPageMetadata is the nested Spring PagedModel metadata.
type RegistrationGrantPageMetadata struct {
	Size          int   `json:"size"`
	Number        int   `json:"number"`
	TotalElements int64 `json:"totalElements"`
	TotalPages    int   `json:"totalPages"`
}

// RegistrationGrantPage is a page of safe registration grants.
type RegistrationGrantPage struct {
	Content []RegistrationGrant           `json:"content"`
	Page    RegistrationGrantPageMetadata `json:"page"`
}

// RegistrationGrantRedemption is a safe masked redemption-history entry.
type RegistrationGrantRedemption struct {
	ID            string  `json:"id"`
	Result        string  `json:"result"`
	Email         *string `json:"email"`
	AuthMethod    *string `json:"authMethod"`
	IDPID         *string `json:"idpId"`
	ClientID      *string `json:"clientId"`
	RedeemedAt    string  `json:"redeemedAt"`
	FailureReason *string `json:"failureReason"`
}

// RegistrationGrantRedemptionPage is a page of safe masked redemption history.
type RegistrationGrantRedemptionPage struct {
	Content []RegistrationGrantRedemption `json:"content"`
	Page    RegistrationGrantPageMetadata `json:"page"`
}

// ListRegistrationGrants lists grants using only registration_grants:read.
func (c *PortalOpenAPIClient) ListRegistrationGrants(ctx context.Context, options RegistrationGrantListOptions) (*RegistrationGrantPage, error) {
	var response RegistrationGrantPage
	err := c.requestJSONWithScope(ctx, http.MethodGet, "/open/v1/registration-grants"+registrationGrantQuery(options), RegistrationGrantsReadScope, nil, &response)
	return &response, err
}

// CreateRegistrationGrant creates an EMAIL_LINK or ACCESS_CODE grant with exactly one matching proof.
func (c *PortalOpenAPIClient) CreateRegistrationGrant(ctx context.Context, request CreateRegistrationGrantRequest) (*CreatedRegistrationGrant, error) {
	if request.Type != CreateRegistrationGrantEmailLink && request.Type != CreateRegistrationGrantAccessCode {
		return nil, invalidRegistrationGrantResponse()
	}
	var response CreatedRegistrationGrant
	if err := c.requestJSONWithScope(ctx, http.MethodPost, "/open/v1/registration-grants", RegistrationGrantsWriteScope, request, &response); err != nil {
		return nil, err
	}
	if err := response.validate(); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetRegistrationGrant returns a safe grant detail using registration_grants:read.
func (c *PortalOpenAPIClient) GetRegistrationGrant(ctx context.Context, grantID string) (*RegistrationGrant, error) {
	return c.registrationGrantLifecycle(ctx, http.MethodGet, grantID, "", RegistrationGrantsReadScope, nil)
}

// PauseRegistrationGrant pauses a grant using registration_grants:write.
func (c *PortalOpenAPIClient) PauseRegistrationGrant(ctx context.Context, grantID string) (*RegistrationGrant, error) {
	return c.registrationGrantLifecycle(ctx, http.MethodPost, grantID, "/pause", RegistrationGrantsWriteScope, nil)
}

// ResumeRegistrationGrant resumes a grant using registration_grants:write.
func (c *PortalOpenAPIClient) ResumeRegistrationGrant(ctx context.Context, grantID string) (*RegistrationGrant, error) {
	return c.registrationGrantLifecycle(ctx, http.MethodPost, grantID, "/resume", RegistrationGrantsWriteScope, nil)
}

// RevokeRegistrationGrant revokes a grant using registration_grants:write. Reason is optional.
func (c *PortalOpenAPIClient) RevokeRegistrationGrant(ctx context.Context, grantID string, reason *string) (*RegistrationGrant, error) {
	var body any
	if reason != nil {
		body = struct {
			Reason string `json:"reason"`
		}{Reason: *reason}
	}
	return c.registrationGrantLifecycle(ctx, http.MethodPost, grantID, "/revoke", RegistrationGrantsWriteScope, body)
}

// ListRegistrationGrantRedemptions lists masked history using its dedicated exact scope.
func (c *PortalOpenAPIClient) ListRegistrationGrantRedemptions(ctx context.Context, grantID string, page, size *int) (*RegistrationGrantRedemptionPage, error) {
	path, err := registrationGrantPath(grantID)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	if page != nil {
		values.Set("page", strconv.Itoa(*page))
	}
	if size != nil {
		values.Set("size", strconv.Itoa(*size))
	}
	if encoded := values.Encode(); encoded != "" {
		path += "/redemptions?" + encoded
	} else {
		path += "/redemptions"
	}
	var response RegistrationGrantRedemptionPage
	if err := c.requestJSONWithScope(ctx, http.MethodGet, path, RegistrationGrantsRedemptionsReadScope, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *PortalOpenAPIClient) registrationGrantLifecycle(ctx context.Context, method, grantID, suffix string, scope PortalOpenAPIScope, body any) (*RegistrationGrant, error) {
	path, err := registrationGrantPath(grantID)
	if err != nil {
		return nil, err
	}
	var response RegistrationGrant
	if err := c.requestJSONWithScope(ctx, method, path+suffix, scope, body, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (response CreatedRegistrationGrant) validate() error {
	hasToken := response.RegistrationGrantToken != nil && *response.RegistrationGrantToken != ""
	hasCode := response.RegistrationAccessCode != nil && *response.RegistrationAccessCode != ""
	if hasToken == hasCode || (response.Grant.Type == RegistrationGrantEmailLink && !hasToken) || (response.Grant.Type == RegistrationGrantAccessCode && !hasCode) || (response.Grant.Type != RegistrationGrantEmailLink && response.Grant.Type != RegistrationGrantAccessCode) {
		return invalidRegistrationGrantResponse()
	}
	return nil
}

func registrationGrantPath(grantID string) (string, error) {
	if !registrationGrantUUID.MatchString(grantID) {
		return "", &PortalOpenAPIError{Code: "invalid_registration_grant_id"}
	}
	return "/open/v1/registration-grants/" + url.PathEscape(grantID), nil
}

func registrationGrantQuery(options RegistrationGrantListOptions) string {
	values := url.Values{}
	if options.Type != nil {
		values.Set("type", string(*options.Type))
	}
	if options.Status != nil {
		values.Set("status", string(*options.Status))
	}
	if options.Search != nil {
		values.Set("search", *options.Search)
	}
	if options.Page != nil {
		values.Set("page", strconv.Itoa(*options.Page))
	}
	if options.Size != nil {
		values.Set("size", strconv.Itoa(*options.Size))
	}
	if encoded := values.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

func invalidRegistrationGrantResponse() error {
	return fmt.Errorf("%w: invalid_registration_grant_response", ErrPortalOpenAPIRequest)
}
