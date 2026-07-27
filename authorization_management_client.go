package iam

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuthorizationPageOptions selects a zero-based page with a maximum size of 100.
type AuthorizationPageOptions struct {
	Page *int
	Size *int
}

// AuthorizationCreateOptions carries an optional retry-safe Idempotency-Key.
type AuthorizationCreateOptions struct{ IdempotencyKey string }

// AuthorizationPageMetadata is the nested Spring PagedModel metadata.
type AuthorizationPageMetadata struct {
	Size          int   `json:"size"`
	Number        int   `json:"number"`
	TotalElements int64 `json:"totalElements"`
	TotalPages    int   `json:"totalPages"`
}

// Role is an Application-scoped role and its strong response ETag.
type Role struct {
	ID          string  `json:"id"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	System      bool    `json:"system"`
	Version     int64   `json:"version"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
	ETag        string  `json:"-"`
}

// RolePage is a deterministic page of roles.
type RolePage struct {
	Content []Role                    `json:"content"`
	Page    AuthorizationPageMetadata `json:"page"`
}

// CreateRoleRequest is the strict role create payload.
type CreateRoleRequest struct {
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// UpdateRoleRequest is the strict role PATCH payload.
type UpdateRoleRequest struct {
	Key         *string `json:"key,omitempty"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// Permission is a canonical resource:action grant and its response ETag.
type Permission struct {
	ID          string  `json:"id"`
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Source      string  `json:"source"`
	Version     int64   `json:"version"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
	ETag        string  `json:"-"`
}

// PermissionPage is a deterministic page of permissions.
type PermissionPage struct {
	Content []Permission              `json:"content"`
	Page    AuthorizationPageMetadata `json:"page"`
}

// CreatePermissionRequest is the strict canonical permission create payload.
type CreatePermissionRequest struct {
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// UpdatePermissionRequest is the strict permission PATCH payload.
type UpdatePermissionRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// RolePermissionBinding describes one persisted role-permission mapping.
type RolePermissionBinding struct {
	RoleID       string `json:"roleId"`
	PermissionID string `json:"permissionId"`
	CreatedAt    string `json:"createdAt"`
}

// RolePermissionBindingPage is a page of mappings plus the role ETag.
type RolePermissionBindingPage struct {
	Content []RolePermissionBinding   `json:"content"`
	Page    AuthorizationPageMetadata `json:"page"`
	ETag    string                    `json:"-"`
}

// RolePermissionSet is the replacement result and new role version/ETag.
type RolePermissionSet struct {
	RoleID        string   `json:"roleId"`
	PermissionIDs []string `json:"permissionIds"`
	Version       int64    `json:"version"`
	ETag          string   `json:"-"`
}

// UserRoleCondition carries the optional assignment expression and description.
type UserRoleCondition struct {
	Expression  *string `json:"expression"`
	Description *string `json:"description"`
}

// UserRoleAssignment is an Application-scoped assignment with optimistic-lock state.
type UserRoleAssignment struct {
	ID                   string  `json:"id"`
	UserID               string  `json:"userId"`
	RoleID               string  `json:"roleId"`
	OrganizationID       *string `json:"organizationId"`
	ConditionExpression  *string `json:"conditionExpression"`
	ConditionDescription *string `json:"conditionDescription"`
	Version              int64   `json:"version"`
	CreatedAt            string  `json:"createdAt"`
	UpdatedAt            string  `json:"updatedAt"`
	ETag                 string  `json:"-"`
}

// UserRoleAssignmentPage is a deterministic page of assignments.
type UserRoleAssignmentPage struct {
	Content []UserRoleAssignment      `json:"content"`
	Page    AuthorizationPageMetadata `json:"page"`
}

type authorizationPageWire struct {
	Size          *int   `json:"size"`
	Number        *int   `json:"number"`
	TotalElements *int64 `json:"totalElements"`
	TotalPages    *int   `json:"totalPages"`
}

func (v *authorizationPageWire) value() (AuthorizationPageMetadata, error) {
	if v == nil || v.Size == nil || v.Number == nil || v.TotalElements == nil || v.TotalPages == nil {
		return AuthorizationPageMetadata{}, invalidAuthorizationResponse()
	}
	return AuthorizationPageMetadata{Size: *v.Size, Number: *v.Number, TotalElements: *v.TotalElements, TotalPages: *v.TotalPages}, nil
}

type roleWire struct {
	ID          string  `json:"id"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	System      *bool   `json:"system"`
	Version     *int64  `json:"version"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
}

func (v roleWire) value() (Role, error) {
	if v.System == nil || v.Version == nil {
		return Role{}, invalidAuthorizationResponse()
	}
	return Role{ID: v.ID, Key: v.Key, Name: v.Name, Description: v.Description, System: *v.System, Version: *v.Version, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}, nil
}

type permissionWire struct {
	ID          string  `json:"id"`
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Source      string  `json:"source"`
	Version     *int64  `json:"version"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
}

func (v permissionWire) value() (Permission, error) {
	if v.Version == nil {
		return Permission{}, invalidAuthorizationResponse()
	}
	return Permission{ID: v.ID, Resource: v.Resource, Action: v.Action, Key: v.Key, Name: v.Name, Description: v.Description, Source: v.Source, Version: *v.Version, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}, nil
}

type rolePermissionSetWire struct {
	RoleID        string   `json:"roleId"`
	PermissionIDs []string `json:"permissionIds"`
	Version       *int64   `json:"version"`
}

func (v rolePermissionSetWire) value() (RolePermissionSet, error) {
	if v.Version == nil {
		return RolePermissionSet{}, invalidAuthorizationResponse()
	}
	return RolePermissionSet{RoleID: v.RoleID, PermissionIDs: v.PermissionIDs, Version: *v.Version}, nil
}

type userRoleAssignmentWire struct {
	ID                   string  `json:"id"`
	UserID               string  `json:"userId"`
	RoleID               string  `json:"roleId"`
	OrganizationID       *string `json:"organizationId"`
	ConditionExpression  *string `json:"conditionExpression"`
	ConditionDescription *string `json:"conditionDescription"`
	Version              *int64  `json:"version"`
	CreatedAt            string  `json:"createdAt"`
	UpdatedAt            string  `json:"updatedAt"`
}

func (v userRoleAssignmentWire) value() (UserRoleAssignment, error) {
	if v.Version == nil {
		return UserRoleAssignment{}, invalidAuthorizationResponse()
	}
	return UserRoleAssignment{ID: v.ID, UserID: v.UserID, RoleID: v.RoleID, OrganizationID: v.OrganizationID, ConditionExpression: v.ConditionExpression, ConditionDescription: v.ConditionDescription, Version: *v.Version, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}, nil
}

// CreateUserRoleRequest is the typed POST assignment payload.
type CreateUserRoleRequest struct {
	RoleID    string             `json:"roleId"`
	Condition *UserRoleCondition `json:"condition,omitempty"`
}

// UpdateUserRoleRequest replaces an assignment condition.
type UpdateUserRoleRequest struct {
	Condition *UserRoleCondition `json:"condition"`
}

// ListRoles uses only roles:read.
func (c *PortalOpenAPIClient) ListRoles(ctx context.Context, options AuthorizationPageOptions) (*RolePage, error) {
	if err := validateAuthorizationPageOptions(options); err != nil {
		return nil, err
	}
	var raw struct {
		Content *[]roleWire            `json:"content"`
		Page    *authorizationPageWire `json:"page"`
	}
	err := c.requestJSONWithScope(ctx, http.MethodGet, "/open/v1/roles"+authorizationPageQuery(options), RolesReadScope, nil, &raw)
	if err != nil || raw.Content == nil {
		if err != nil {
			return nil, err
		}
		return nil, invalidAuthorizationResponse()
	}
	page, err := raw.Page.value()
	if err != nil {
		return nil, err
	}
	content := make([]Role, len(*raw.Content))
	for index, item := range *raw.Content {
		if content[index], err = item.value(); err != nil {
			return nil, err
		}
	}
	out := RolePage{Content: content, Page: page}
	if err = validateAuthorizationPage(nil, len(out.Content), out.Page); err == nil {
		for _, item := range out.Content {
			if err = validateRoleItem(item); err != nil {
				break
			}
		}
	}
	return &out, err
}

// GetRole uses only roles:read and exposes the returned ETag.
func (c *PortalOpenAPIClient) GetRole(ctx context.Context, id string) (*Role, error) {
	path, err := authorizationPath("roles", "role", id)
	if err != nil {
		return nil, err
	}
	var raw roleWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodGet, path, RolesReadScope, nil, &raw, nil)
	var out Role
	if err == nil {
		out, err = raw.value()
	}
	return roleWithETagForID(&out, h, err, id)
}

// CreateRole uses only roles:write and applies Idempotency-Key when supplied.
func (c *PortalOpenAPIClient) CreateRole(ctx context.Context, req CreateRoleRequest, options *AuthorizationCreateOptions) (*Role, error) {
	var raw roleWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, "/open/v1/roles", RolesWriteScope, req, &raw, authorizationIdempotencyHeader(options))
	var out Role
	if err == nil {
		out, err = raw.value()
	}
	return roleWithETag(&out, h, err)
}

// UpdateRole uses only roles:write and requires a strong If-Match ETag.
func (c *PortalOpenAPIClient) UpdateRole(ctx context.Context, id string, req UpdateRoleRequest, ifMatch string) (*Role, error) {
	if err := validateIfMatch(ifMatch); err != nil {
		return nil, err
	}
	path, err := authorizationPath("roles", "role", id)
	if err != nil {
		return nil, err
	}
	var raw roleWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPatch, path, RolesWriteScope, req, &raw, authorizationIfMatchHeader(ifMatch))
	var out Role
	if err == nil {
		out, err = raw.value()
	}
	return roleWithETagForID(&out, h, err, id)
}

// DeleteRole uses only roles:write and requires a strong If-Match ETag.
func (c *PortalOpenAPIClient) DeleteRole(ctx context.Context, id, ifMatch string) error {
	if err := validateIfMatch(ifMatch); err != nil {
		return err
	}
	path, err := authorizationPath("roles", "role", id)
	if err != nil {
		return err
	}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodDelete, path, RolesWriteScope, nil, nil, authorizationIfMatchHeader(ifMatch))
	return err
}

// ListPermissions uses only permissions:read.
func (c *PortalOpenAPIClient) ListPermissions(ctx context.Context, options AuthorizationPageOptions) (*PermissionPage, error) {
	if err := validateAuthorizationPageOptions(options); err != nil {
		return nil, err
	}
	var raw struct {
		Content *[]permissionWire      `json:"content"`
		Page    *authorizationPageWire `json:"page"`
	}
	err := c.requestJSONWithScope(ctx, http.MethodGet, "/open/v1/permissions"+authorizationPageQuery(options), PermissionsReadScope, nil, &raw)
	if err != nil || raw.Content == nil {
		if err != nil {
			return nil, err
		}
		return nil, invalidAuthorizationResponse()
	}
	page, err := raw.Page.value()
	if err != nil {
		return nil, err
	}
	content := make([]Permission, len(*raw.Content))
	for index, item := range *raw.Content {
		if content[index], err = item.value(); err != nil {
			return nil, err
		}
	}
	out := PermissionPage{Content: content, Page: page}
	err = validatePermissionPage(out)
	return &out, err
}

// GetPermission uses only permissions:read and exposes the returned ETag.
func (c *PortalOpenAPIClient) GetPermission(ctx context.Context, id string) (*Permission, error) {
	path, err := authorizationPath("permissions", "permission", id)
	if err != nil {
		return nil, err
	}
	var raw permissionWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodGet, path, PermissionsReadScope, nil, &raw, nil)
	var out Permission
	if err == nil {
		out, err = raw.value()
	}
	return permissionWithETagForID(&out, h, err, id)
}

// CreatePermission uses only permissions:write and validates canonical grant grammar.
func (c *PortalOpenAPIClient) CreatePermission(ctx context.Context, req CreatePermissionRequest, options *AuthorizationCreateOptions) (*Permission, error) {
	if err := validatePermissionGrant(req.Resource, req.Action); err != nil {
		return nil, err
	}
	var raw permissionWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, "/open/v1/permissions", PermissionsWriteScope, req, &raw, authorizationIdempotencyHeader(options))
	var out Permission
	if err == nil {
		out, err = raw.value()
	}
	return permissionWithETag(&out, h, err)
}

// UpdatePermission uses only permissions:write and requires a strong If-Match ETag.
func (c *PortalOpenAPIClient) UpdatePermission(ctx context.Context, id string, req UpdatePermissionRequest, ifMatch string) (*Permission, error) {
	if err := validateIfMatch(ifMatch); err != nil {
		return nil, err
	}
	path, err := authorizationPath("permissions", "permission", id)
	if err != nil {
		return nil, err
	}
	var raw permissionWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPatch, path, PermissionsWriteScope, req, &raw, authorizationIfMatchHeader(ifMatch))
	var out Permission
	if err == nil {
		out, err = raw.value()
	}
	return permissionWithETagForID(&out, h, err, id)
}

// DeletePermission uses only permissions:write and requires a strong If-Match ETag.
func (c *PortalOpenAPIClient) DeletePermission(ctx context.Context, id, ifMatch string) error {
	if err := validateIfMatch(ifMatch); err != nil {
		return err
	}
	path, err := authorizationPath("permissions", "permission", id)
	if err != nil {
		return err
	}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodDelete, path, PermissionsWriteScope, nil, nil, authorizationIfMatchHeader(ifMatch))
	return err
}

// ListRolePermissions uses only role_permissions:read and exposes the role ETag.
func (c *PortalOpenAPIClient) ListRolePermissions(ctx context.Context, roleID string, options AuthorizationPageOptions) (*RolePermissionBindingPage, error) {
	if err := validateAuthorizationPageOptions(options); err != nil {
		return nil, err
	}
	path, err := authorizationPath("roles", "role", roleID)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Content *[]RolePermissionBinding `json:"content"`
		Page    *authorizationPageWire   `json:"page"`
	}
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodGet, path+"/permissions"+authorizationPageQuery(options), RolePermissionsReadScope, nil, &raw, nil)
	if err == nil && raw.Content == nil {
		err = invalidAuthorizationResponse()
	}
	out := RolePermissionBindingPage{}
	if err == nil {
		out.Content = *raw.Content
		out.Page, err = raw.Page.value()
	}
	if err == nil {
		out.ETag, err = strongETag(h)
	}
	if err == nil {
		err = validateAuthorizationPage(nil, len(out.Content), out.Page)
	}
	if err == nil {
		for _, item := range out.Content {
			if err = validateRolePermissionBindingForRole(item, roleID); err != nil {
				break
			}
		}
	}
	return &out, err
}

// ReplaceRolePermissions uses only role_permissions:write and requires If-Match.
func (c *PortalOpenAPIClient) ReplaceRolePermissions(ctx context.Context, roleID string, permissionIDs []string, ifMatch string) (*RolePermissionSet, error) {
	if err := validateIfMatch(ifMatch); err != nil {
		return nil, err
	}
	path, err := authorizationPath("roles", "role", roleID)
	if err != nil {
		return nil, err
	}
	for _, id := range permissionIDs {
		if _, err = authorizationID(id, "permission"); err != nil {
			return nil, err
		}
	}
	var raw rolePermissionSetWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPut, path+"/permissions", RolePermissionsWriteScope, struct {
		PermissionIDs []string `json:"permissionIds"`
	}{permissionIDs}, &raw, authorizationIfMatchHeader(ifMatch))
	var out RolePermissionSet
	if err == nil {
		out, err = raw.value()
	}
	if err == nil {
		out.ETag, err = strongETag(h)
	}
	if err == nil {
		err = validateRolePermissionSetForRole(out, roleID)
	}
	return &out, err
}

// ListUserRoles uses only user_roles:read.
func (c *PortalOpenAPIClient) ListUserRoles(ctx context.Context, userID string, options AuthorizationPageOptions) (*UserRoleAssignmentPage, error) {
	if err := validateAuthorizationPageOptions(options); err != nil {
		return nil, err
	}
	path, err := userRolePath(userID)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Content *[]userRoleAssignmentWire `json:"content"`
		Page    *authorizationPageWire    `json:"page"`
	}
	err = c.requestJSONWithScope(ctx, http.MethodGet, path+authorizationPageQuery(options), UserRolesReadScope, nil, &raw)
	if err != nil || raw.Content == nil {
		if err != nil {
			return nil, err
		}
		return nil, invalidAuthorizationResponse()
	}
	page, err := raw.Page.value()
	if err != nil {
		return nil, err
	}
	content := make([]UserRoleAssignment, len(*raw.Content))
	for index, item := range *raw.Content {
		if content[index], err = item.value(); err != nil {
			return nil, err
		}
	}
	out := UserRoleAssignmentPage{Content: content, Page: page}
	if err == nil {
		err = validateAuthorizationPage(nil, len(out.Content), out.Page)
	}
	if err == nil {
		for _, item := range out.Content {
			if err = validateUserRoleAssignmentForUser(item, userID); err != nil {
				break
			}
		}
	}
	return &out, err
}

// CreateUserRole uses only user_roles:write and the typed POST assignment route.
func (c *PortalOpenAPIClient) CreateUserRole(ctx context.Context, userID string, req CreateUserRoleRequest, options *AuthorizationCreateOptions) (*UserRoleAssignment, error) {
	path, err := userRolePath(userID)
	if err != nil {
		return nil, err
	}
	if _, err = authorizationID(req.RoleID, "role"); err != nil {
		return nil, err
	}
	var raw userRoleAssignmentWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, path, UserRolesWriteScope, req, &raw, authorizationIdempotencyHeader(options))
	var out UserRoleAssignment
	if err == nil {
		out, err = raw.value()
	}
	return assignmentWithETagForCreate(&out, h, err, userID, req.RoleID)
}

// UpdateUserRole uses only user_roles:write and requires If-Match.
func (c *PortalOpenAPIClient) UpdateUserRole(ctx context.Context, userID, assignmentID string, req UpdateUserRoleRequest, ifMatch string) (*UserRoleAssignment, error) {
	if err := validateIfMatch(ifMatch); err != nil {
		return nil, err
	}
	path, err := userRolePath(userID)
	if err != nil {
		return nil, err
	}
	segment, err := authorizationID(assignmentID, "assignment")
	if err != nil {
		return nil, err
	}
	var raw userRoleAssignmentWire
	h, err := c.requestJSONWithScopeAndHeaders(ctx, http.MethodPatch, path+"/"+segment, UserRolesWriteScope, req, &raw, authorizationIfMatchHeader(ifMatch))
	var out UserRoleAssignment
	if err == nil {
		out, err = raw.value()
	}
	return assignmentWithETagForUpdate(&out, h, err, userID, assignmentID)
}

// DeleteUserRole uses only user_roles:write and requires If-Match.
func (c *PortalOpenAPIClient) DeleteUserRole(ctx context.Context, userID, assignmentID, ifMatch string) error {
	if err := validateIfMatch(ifMatch); err != nil {
		return err
	}
	path, err := userRolePath(userID)
	if err != nil {
		return err
	}
	segment, err := authorizationID(assignmentID, "assignment")
	if err != nil {
		return err
	}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodDelete, path+"/"+segment, UserRolesWriteScope, nil, nil, authorizationIfMatchHeader(ifMatch))
	return err
}

var permissionGrantSegment = regexp.MustCompile(`^(?:\*|[a-z0-9_-]{1,128})$`)
var strongETagPattern = regexp.MustCompile(`^"[0-9]+"$`)
var canonicalAuthorizationUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func validatePermissionGrant(resource, action string) error {
	if !permissionGrantSegment.MatchString(resource) || !permissionGrantSegment.MatchString(action) || (resource == "*" && action != "*") {
		return &PortalOpenAPIError{Code: "invalid_permission_key"}
	}
	return nil
}
func authorizationPageQuery(o AuthorizationPageOptions) string {
	page, size := 0, 20
	if o.Page != nil {
		page = *o.Page
	}
	if o.Size != nil {
		size = *o.Size
	}
	v := url.Values{}
	v.Set("page", strconv.Itoa(page))
	v.Set("size", strconv.Itoa(size))
	return "?" + v.Encode()
}
func validateAuthorizationPageOptions(o AuthorizationPageOptions) error {
	page, size := 0, 20
	if o.Page != nil {
		page = *o.Page
	}
	if o.Size != nil {
		size = *o.Size
	}
	if page < 0 || size < 1 || size > 100 {
		return invalidAuthorizationResponse()
	}
	return nil
}
func authorizationID(id, resource string) (string, error) {
	if !organizationManagementUUID.MatchString(id) {
		return "", &PortalOpenAPIError{Code: "invalid_" + resource + "_id"}
	}
	return url.PathEscape(id), nil
}
func authorizationPath(collection, resource, id string) (string, error) {
	segment, err := authorizationID(id, resource)
	return "/open/v1/" + collection + "/" + segment, err
}
func userRolePath(userID string) (string, error) {
	segment, err := authorizationID(userID, "user")
	return "/open/v1/users/" + segment + "/roles", err
}
func authorizationIdempotencyHeader(o *AuthorizationCreateOptions) http.Header {
	if o == nil || o.IdempotencyKey == "" {
		return nil
	}
	h := http.Header{}
	h.Set("Idempotency-Key", o.IdempotencyKey)
	return h
}
func authorizationIfMatchHeader(etag string) http.Header {
	h := http.Header{}
	h.Set("If-Match", etag)
	return h
}
func strongETag(h http.Header) (string, error) {
	etag := h.Get("ETag")
	if !strongETagPattern.MatchString(etag) {
		return "", invalidAuthorizationResponse()
	}
	return etag, nil
}
func validateIfMatch(value string) error {
	if !strongETagPattern.MatchString(value) {
		return invalidAuthorizationResponse()
	}
	return nil
}
func invalidAuthorizationResponse() error {
	return &PortalOpenAPIError{Code: "invalid_authorization_response"}
}
func validateAuthorizationPage(err error, count int, p AuthorizationPageMetadata) error {
	if err != nil {
		return err
	}
	if p.Size < 1 || p.Size > 100 {
		return invalidAuthorizationResponse()
	}
	expectedPages := int(p.TotalElements / int64(p.Size))
	if p.TotalElements%int64(p.Size) != 0 {
		expectedPages++
	}
	expectedContent := 0
	if p.TotalElements > 0 {
		remaining := p.TotalElements - int64(p.Number)*int64(p.Size)
		expectedContent = min(p.Size, int(remaining))
	}
	if p.Number < 0 || p.TotalElements < 0 || p.TotalPages != expectedPages ||
		count > p.Size || int64(count) > p.TotalElements ||
		(p.TotalElements == 0 && p.Number != 0) || (p.TotalElements > 0 && p.Number >= p.TotalPages) ||
		count != expectedContent {
		return invalidAuthorizationResponse()
	}
	return nil
}
func roleWithETag(v *Role, h http.Header, err error) (*Role, error) {
	if err != nil {
		return nil, err
	}
	v.ETag, err = strongETag(h)
	if err == nil {
		err = validateRoleItem(*v)
	}
	return v, err
}
func roleWithETagForID(v *Role, h http.Header, err error, expectedID string) (*Role, error) {
	result, err := roleWithETag(v, h, err)
	if err == nil && result.ID != expectedID {
		return result, invalidAuthorizationResponse()
	}
	return result, err
}
func permissionWithETag(v *Permission, h http.Header, err error) (*Permission, error) {
	if err != nil {
		return nil, err
	}
	v.ETag, err = strongETag(h)
	if err == nil {
		err = validatePermissionItem(*v)
	}
	return v, err
}
func permissionWithETagForID(v *Permission, h http.Header, err error, expectedID string) (*Permission, error) {
	result, err := permissionWithETag(v, h, err)
	if err == nil && result.ID != expectedID {
		return result, invalidAuthorizationResponse()
	}
	return result, err
}
func validatePermissionPage(p PermissionPage) error {
	if err := validateAuthorizationPage(nil, len(p.Content), p.Page); err != nil {
		return err
	}
	for _, item := range p.Content {
		if err := validatePermissionItem(item); err != nil {
			return err
		}
	}
	return nil
}
func assignmentWithETag(v *UserRoleAssignment, h http.Header, err error) (*UserRoleAssignment, error) {
	if err != nil {
		return nil, err
	}
	v.ETag, err = strongETag(h)
	if err == nil {
		err = validateUserRoleAssignmentItem(*v)
	}
	return v, err
}
func assignmentWithETagForCreate(v *UserRoleAssignment, h http.Header, err error, userID, roleID string) (*UserRoleAssignment, error) {
	result, err := assignmentWithETag(v, h, err)
	if err == nil && (result.UserID != userID || result.RoleID != roleID) {
		return result, invalidAuthorizationResponse()
	}
	return result, err
}
func assignmentWithETagForUpdate(v *UserRoleAssignment, h http.Header, err error, userID, assignmentID string) (*UserRoleAssignment, error) {
	result, err := assignmentWithETag(v, h, err)
	if err == nil && (result.UserID != userID || result.ID != assignmentID) {
		return result, invalidAuthorizationResponse()
	}
	return result, err
}

func validateRoleItem(v Role) error {
	if !canonicalAuthorizationUUID.MatchString(v.ID) || strings.TrimSpace(v.Key) == "" || strings.TrimSpace(v.Name) == "" ||
		!validAuthorizationTimestamp(v.CreatedAt) || !validAuthorizationTimestamp(v.UpdatedAt) {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validatePermissionItem(v Permission) error {
	if !canonicalAuthorizationUUID.MatchString(v.ID) || validatePermissionGrant(v.Resource, v.Action) != nil ||
		v.Key != v.Resource+":"+v.Action || strings.TrimSpace(v.Name) == "" ||
		(v.Source != "CODE" && v.Source != "MANUAL") ||
		!validAuthorizationTimestamp(v.CreatedAt) || !validAuthorizationTimestamp(v.UpdatedAt) {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validateRolePermissionBindingItem(v RolePermissionBinding) error {
	if !canonicalAuthorizationUUID.MatchString(v.RoleID) || !canonicalAuthorizationUUID.MatchString(v.PermissionID) ||
		!validAuthorizationTimestamp(v.CreatedAt) {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validateRolePermissionBindingForRole(v RolePermissionBinding, roleID string) error {
	if validateRolePermissionBindingItem(v) != nil || v.RoleID != roleID {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validateRolePermissionSetItem(v RolePermissionSet) error {
	if !canonicalAuthorizationUUID.MatchString(v.RoleID) || v.PermissionIDs == nil {
		return invalidAuthorizationResponse()
	}
	for _, id := range v.PermissionIDs {
		if !canonicalAuthorizationUUID.MatchString(id) {
			return invalidAuthorizationResponse()
		}
	}
	return nil
}
func validateRolePermissionSetForRole(v RolePermissionSet, roleID string) error {
	if validateRolePermissionSetItem(v) != nil || v.RoleID != roleID {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validateUserRoleAssignmentItem(v UserRoleAssignment) error {
	if !canonicalAuthorizationUUID.MatchString(v.ID) || !canonicalAuthorizationUUID.MatchString(v.UserID) ||
		!canonicalAuthorizationUUID.MatchString(v.RoleID) ||
		v.OrganizationID != nil && !canonicalAuthorizationUUID.MatchString(*v.OrganizationID) ||
		!validAuthorizationTimestamp(v.CreatedAt) || !validAuthorizationTimestamp(v.UpdatedAt) {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validateUserRoleAssignmentForUser(v UserRoleAssignment, userID string) error {
	if validateUserRoleAssignmentItem(v) != nil || v.UserID != userID {
		return invalidAuthorizationResponse()
	}
	return nil
}
func validAuthorizationTimestamp(value string) bool {
	if !strings.HasSuffix(value, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}
