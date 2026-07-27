package iam

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

var organizationManagementUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// OrganizationMemberRole is the Organization role returned and accepted by the Open API.
type OrganizationMemberRole string

const (
	OrganizationMemberRoleOwner  OrganizationMemberRole = "OWNER"
	OrganizationMemberRoleAdmin  OrganizationMemberRole = "ADMIN"
	OrganizationMemberRoleMember OrganizationMemberRole = "MEMBER"
)

// OrganizationInvitationStatus is an Organization invitation lifecycle state.
type OrganizationInvitationStatus string

const (
	OrganizationInvitationPending   OrganizationInvitationStatus = "PENDING"
	OrganizationInvitationAccepted  OrganizationInvitationStatus = "ACCEPTED"
	OrganizationInvitationCancelled OrganizationInvitationStatus = "CANCELLED"
	OrganizationInvitationExpired   OrganizationInvitationStatus = "EXPIRED"
)

// OrganizationInvitationDeliveryStatus is the invitation email delivery outcome.
type OrganizationInvitationDeliveryStatus string

const (
	OrganizationInvitationDeliveryNotRequested OrganizationInvitationDeliveryStatus = "NOT_REQUESTED"
	OrganizationInvitationDeliverySent         OrganizationInvitationDeliveryStatus = "SENT"
	OrganizationInvitationDeliveryFailed       OrganizationInvitationDeliveryStatus = "FAILED"
)

// OrganizationSortDirection controls Organization list sorting.
type OrganizationSortDirection string

const (
	OrganizationSortAscending  OrganizationSortDirection = "ASC"
	OrganizationSortDescending OrganizationSortDirection = "DESC"
)

// Organization is an Application-bound Organization. ETag is populated for create, get, and update responses.
type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Version   int64  `json:"version"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	ETag      string `json:"-"`
}

// CreateOrganizationRequest is the strict Organization create payload.
type CreateOrganizationRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// UpdateOrganizationRequest is the strict PATCH payload. Nil fields are omitted.
type UpdateOrganizationRequest struct {
	Name *string `json:"name,omitempty"`
	Slug *string `json:"slug,omitempty"`
}

// OrganizationCreateOptions carries an optional Idempotency-Key for exactly-once creates.
type OrganizationCreateOptions struct {
	IdempotencyKey string
}

// OrganizationIfMatchOptions carries an optional quoted ETag/version precondition.
type OrganizationIfMatchOptions struct {
	IfMatch string
}

// OrganizationListOptions filters, pages, and sorts Organization results.
type OrganizationListOptions struct {
	Search    *string
	Page      *int
	Size      *int
	Sort      []string
	Direction []OrganizationSortDirection
}

// OrganizationPageMetadata is the nested Spring PagedModel metadata.
type OrganizationPageMetadata struct {
	Size          int   `json:"size"`
	Number        int   `json:"number"`
	TotalElements int64 `json:"totalElements"`
	TotalPages    int   `json:"totalPages"`
}

// OrganizationPage is a page of Application-bound Organizations.
type OrganizationPage struct {
	Content []Organization           `json:"content"`
	Page    OrganizationPageMetadata `json:"page"`
}

// OrganizationInvitation is a safe invitation detail. It never contains a redemption proof.
type OrganizationInvitation struct {
	ID             string                               `json:"id"`
	Email          string                               `json:"email"`
	Role           OrganizationMemberRole               `json:"role"`
	Status         OrganizationInvitationStatus         `json:"status"`
	DeliveryStatus OrganizationInvitationDeliveryStatus `json:"deliveryStatus"`
	ExpiresAt      string                               `json:"expiresAt"`
	CreatedAt      string                               `json:"createdAt"`
	UpdatedAt      string                               `json:"updatedAt"`
}

// CreateOrganizationInvitationRequest is the strict invitation create payload.
type CreateOrganizationInvitationRequest struct {
	Email     string                  `json:"email"`
	Role      *OrganizationMemberRole `json:"role,omitempty"`
	SendEmail *bool                   `json:"sendEmail,omitempty"`
}

// OrganizationInvitationListOptions filters invitation lifecycle state and pages results.
type OrganizationInvitationListOptions struct {
	Status *OrganizationInvitationStatus
	Page   *int
	Size   *int
}

// OrganizationInvitationPage is a page of invitation details and delivery states.
type OrganizationInvitationPage struct {
	Content []OrganizationInvitation `json:"content"`
	Page    OrganizationPageMetadata `json:"page"`
}

// OrganizationMember is an Organization membership detail, including its optimistic-lock version.
type OrganizationMember struct {
	MembershipID string                 `json:"membershipId"`
	UserID       string                 `json:"userId"`
	Email        string                 `json:"email"`
	DisplayName  string                 `json:"displayName"`
	Role         OrganizationMemberRole `json:"role"`
	JoinedAt     string                 `json:"joinedAt"`
	UpdatedAt    string                 `json:"updatedAt"`
	Version      int64                  `json:"version"`
}

// OrganizationMemberListOptions filters and pages Organization members.
type OrganizationMemberListOptions struct {
	Search *string
	Page   *int
	Size   *int
}

// OrganizationMemberPage is a page of Organization membership details.
type OrganizationMemberPage struct {
	Content []OrganizationMember     `json:"content"`
	Page    OrganizationPageMetadata `json:"page"`
}

// ListOrganizations uses only organizations:read.
func (c *PortalOpenAPIClient) ListOrganizations(ctx context.Context, options OrganizationListOptions) (*OrganizationPage, error) {
	var response OrganizationPage
	err := c.requestJSONWithScope(ctx, http.MethodGet, "/open/v1/organizations"+organizationQuery(options), OrganizationsReadScope, nil, &response)
	return &response, err
}

// CreateOrganization uses only organizations:write and applies Idempotency-Key when supplied.
func (c *PortalOpenAPIClient) CreateOrganization(ctx context.Context, request CreateOrganizationRequest, options *OrganizationCreateOptions) (*Organization, error) {
	var response Organization
	headers, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, "/open/v1/organizations", OrganizationsWriteScope, request, &response, idempotencyHeader(options))
	if err != nil {
		return nil, err
	}
	response.ETag = headers.Get("ETag")
	return &response, nil
}

// GetOrganization uses only organizations:read and exposes the returned ETag.
func (c *PortalOpenAPIClient) GetOrganization(ctx context.Context, organizationID string) (*Organization, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return nil, err
	}
	var response Organization
	headers, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodGet, path, OrganizationsReadScope, nil, &response, nil)
	if err != nil {
		return nil, err
	}
	response.ETag = headers.Get("ETag")
	return &response, nil
}

// UpdateOrganization uses only organizations:write and applies If-Match when supplied.
func (c *PortalOpenAPIClient) UpdateOrganization(ctx context.Context, organizationID string, request UpdateOrganizationRequest, options *OrganizationIfMatchOptions) (*Organization, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return nil, err
	}
	var response Organization
	headers, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPatch, path, OrganizationsWriteScope, request, &response, ifMatchHeader(options))
	if err != nil {
		return nil, err
	}
	response.ETag = headers.Get("ETag")
	return &response, nil
}

// DeleteOrganization uses only organizations:write and applies If-Match when supplied.
func (c *PortalOpenAPIClient) DeleteOrganization(ctx context.Context, organizationID string, options *OrganizationIfMatchOptions) error {
	path, err := organizationPath(organizationID)
	if err != nil {
		return err
	}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodDelete, path, OrganizationsWriteScope, nil, nil, ifMatchHeader(options))
	return err
}

// ListOrganizationInvitations uses only organization_invitations:read.
func (c *PortalOpenAPIClient) ListOrganizationInvitations(ctx context.Context, organizationID string, options OrganizationInvitationListOptions) (*OrganizationInvitationPage, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return nil, err
	}
	var response OrganizationInvitationPage
	err = c.requestJSONWithScope(ctx, http.MethodGet, path+"/invitations"+organizationInvitationQuery(options), OrganizationInvitationsReadScope, nil, &response)
	return &response, err
}

// CreateOrganizationInvitation uses only organization_invitations:write and applies Idempotency-Key when supplied.
func (c *PortalOpenAPIClient) CreateOrganizationInvitation(ctx context.Context, organizationID string, request CreateOrganizationInvitationRequest, options *OrganizationCreateOptions) (*OrganizationInvitation, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return nil, err
	}
	var response OrganizationInvitation
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, path+"/invitations", OrganizationInvitationsWriteScope, request, &response, idempotencyHeader(options))
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// GetOrganizationInvitation uses only organization_invitations:read.
func (c *PortalOpenAPIClient) GetOrganizationInvitation(ctx context.Context, organizationID, invitationID string) (*OrganizationInvitation, error) {
	path, err := organizationInvitationPath(organizationID, invitationID)
	if err != nil {
		return nil, err
	}
	var response OrganizationInvitation
	err = c.requestJSONWithScope(ctx, http.MethodGet, path, OrganizationInvitationsReadScope, nil, &response)
	return &response, err
}

// ResendOrganizationInvitation uses only organization_invitations:write. Retry-After is preserved on PortalOpenAPIError.
func (c *PortalOpenAPIClient) ResendOrganizationInvitation(ctx context.Context, organizationID, invitationID string) (*OrganizationInvitation, error) {
	path, err := organizationInvitationPath(organizationID, invitationID)
	if err != nil {
		return nil, err
	}
	var response OrganizationInvitation
	err = c.requestJSONWithScope(ctx, http.MethodPost, path+"/resend", OrganizationInvitationsWriteScope, nil, &response)
	return &response, err
}

// CancelOrganizationInvitation uses only organization_invitations:write. Portal owns terminal-state/idempotency semantics.
func (c *PortalOpenAPIClient) CancelOrganizationInvitation(ctx context.Context, organizationID, invitationID string) error {
	path, err := organizationInvitationPath(organizationID, invitationID)
	if err != nil {
		return err
	}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodDelete, path, OrganizationInvitationsWriteScope, nil, nil, nil)
	return err
}

// ListOrganizationMembers uses only organization_members:read.
func (c *PortalOpenAPIClient) ListOrganizationMembers(ctx context.Context, organizationID string, options OrganizationMemberListOptions) (*OrganizationMemberPage, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return nil, err
	}
	var response OrganizationMemberPage
	err = c.requestJSONWithScope(ctx, http.MethodGet, path+"/members"+organizationMemberQuery(options), OrganizationMembersReadScope, nil, &response)
	return &response, err
}

// GetOrganizationMember uses only organization_members:read.
func (c *PortalOpenAPIClient) GetOrganizationMember(ctx context.Context, organizationID, membershipID string) (*OrganizationMember, error) {
	path, err := organizationMemberPath(organizationID, membershipID)
	if err != nil {
		return nil, err
	}
	var response OrganizationMember
	err = c.requestJSONWithScope(ctx, http.MethodGet, path, OrganizationMembersReadScope, nil, &response)
	return &response, err
}

// UpdateOrganizationMemberRole uses only organization_members:write and applies If-Match when supplied.
func (c *PortalOpenAPIClient) UpdateOrganizationMemberRole(ctx context.Context, organizationID, membershipID string, role OrganizationMemberRole, options *OrganizationIfMatchOptions) (*OrganizationMember, error) {
	path, err := organizationMemberPath(organizationID, membershipID)
	if err != nil {
		return nil, err
	}
	var response OrganizationMember
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodPatch, path, OrganizationMembersWriteScope, struct {
		Role OrganizationMemberRole `json:"role"`
	}{Role: role}, &response, ifMatchHeader(options))
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// RemoveOrganizationMember uses only organization_members:write. Last-owner conflicts remain typed Portal errors.
func (c *PortalOpenAPIClient) RemoveOrganizationMember(ctx context.Context, organizationID, membershipID string) error {
	path, err := organizationMemberPath(organizationID, membershipID)
	if err != nil {
		return err
	}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodDelete, path, OrganizationMembersWriteScope, nil, nil, nil)
	return err
}

func organizationPath(organizationID string) (string, error) {
	segment, err := organizationManagementIDSegment(organizationID, "organization")
	if err != nil {
		return "", err
	}
	return "/open/v1/organizations/" + segment, nil
}

func organizationInvitationPath(organizationID, invitationID string) (string, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return "", err
	}
	segment, err := organizationManagementIDSegment(invitationID, "invitation")
	if err != nil {
		return "", err
	}
	return path + "/invitations/" + segment, nil
}

func organizationMemberPath(organizationID, membershipID string) (string, error) {
	path, err := organizationPath(organizationID)
	if err != nil {
		return "", err
	}
	segment, err := organizationManagementIDSegment(membershipID, "membership")
	if err != nil {
		return "", err
	}
	return path + "/members/" + segment, nil
}

func organizationManagementIDSegment(value, resource string) (string, error) {
	if !organizationManagementUUID.MatchString(value) {
		return "", &PortalOpenAPIError{Code: "invalid_" + resource + "_id"}
	}
	return url.PathEscape(value), nil
}

func organizationQuery(options OrganizationListOptions) string {
	values := url.Values{}
	if options.Search != nil {
		values.Set("search", *options.Search)
	}
	if options.Page != nil {
		values.Set("page", strconv.Itoa(*options.Page))
	}
	if options.Size != nil {
		values.Set("size", strconv.Itoa(*options.Size))
	}
	for _, sort := range options.Sort {
		values.Add("sort", sort)
	}
	for _, direction := range options.Direction {
		values.Add("direction", string(direction))
	}
	return queryString(values)
}

func organizationInvitationQuery(options OrganizationInvitationListOptions) string {
	values := url.Values{}
	if options.Status != nil {
		values.Set("status", string(*options.Status))
	}
	if options.Page != nil {
		values.Set("page", strconv.Itoa(*options.Page))
	}
	if options.Size != nil {
		values.Set("size", strconv.Itoa(*options.Size))
	}
	return queryString(values)
}

func organizationMemberQuery(options OrganizationMemberListOptions) string {
	values := url.Values{}
	if options.Search != nil {
		values.Set("search", *options.Search)
	}
	if options.Page != nil {
		values.Set("page", strconv.Itoa(*options.Page))
	}
	if options.Size != nil {
		values.Set("size", strconv.Itoa(*options.Size))
	}
	return queryString(values)
}

func queryString(values url.Values) string {
	if encoded := values.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

func idempotencyHeader(options *OrganizationCreateOptions) http.Header {
	if options == nil || options.IdempotencyKey == "" {
		return nil
	}
	headers := http.Header{}
	headers.Set("Idempotency-Key", options.IdempotencyKey)
	return headers
}

func ifMatchHeader(options *OrganizationIfMatchOptions) http.Header {
	if options == nil || options.IfMatch == "" {
		return nil
	}
	headers := http.Header{}
	headers.Set("If-Match", options.IfMatch)
	return headers
}
