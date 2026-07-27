package iam

import (
	"net/http"
	"testing"
)

func TestAuthorizationManagementContractValidation(t *testing.T) {
	for _, vector := range []struct {
		resource string
		action   string
		valid    bool
	}{{"orders", "read", true}, {"orders", "*", true}, {"*", "*", true}, {"*", "read", false}, {"Orders", "read", false}, {"orders", "read:all", false}, {" orders", "read", false}} {
		err := validatePermissionGrant(vector.resource, vector.action)
		if (err == nil) != vector.valid {
			t.Fatalf("validatePermissionGrant(%q, %q) error = %v", vector.resource, vector.action, err)
		}
	}
	if _, err := strongETag(mapHeader("ETag", `"7"`)); err != nil {
		t.Fatalf("strong ETag rejected: %v", err)
	}
	if _, err := strongETag(mapHeader("ETag", `W/"7"`)); err == nil {
		t.Fatal("weak ETag accepted")
	}
	if err := validateIfMatch(`W/"7"`); err == nil {
		t.Fatal("weak If-Match accepted")
	}
	if got := authorizationPageQuery(AuthorizationPageOptions{}); got != "?page=0&size=20" {
		t.Fatalf("default query = %q", got)
	}
}

func TestAuthorizationExactScopesAreSupportedIndependently(t *testing.T) {
	for _, scope := range []PortalOpenAPIScope{RolesReadScope, RolesWriteScope, PermissionsReadScope,
		PermissionsWriteScope, RolePermissionsReadScope, RolePermissionsWriteScope, UserRolesReadScope, UserRolesWriteScope} {
		if err := validatePortalOpenAPIScope(scope); err != nil {
			t.Fatalf("scope %q rejected: %v", scope, err)
		}
	}
	if err := validatePortalOpenAPIScope(PortalOpenAPIScope("portal:openapi:read-write")); err == nil {
		t.Fatal("unknown broad scope accepted")
	}
}

func TestAuthorizationResponseValidatorsFailClosed(t *testing.T) {
	validTime := "2026-07-15T00:00:00Z"
	validRole := Role{ID: "123e4567-e89b-42d3-a456-426614174000", Key: "admin", Name: "Admin", Version: 1, CreatedAt: validTime, UpdatedAt: validTime}
	for name, role := range map[string]Role{
		"uuid":      {ID: "not-a-uuid", Key: "admin", Name: "Admin", CreatedAt: validTime, UpdatedAt: validTime},
		"timestamp": {ID: validRole.ID, Key: "admin", Name: "Admin", CreatedAt: "yesterday", UpdatedAt: validTime},
	} {
		t.Run("role_"+name, func(t *testing.T) {
			if err := validateRoleItem(role); err == nil {
				t.Fatal("malformed role accepted")
			}
		})
	}
	permission := Permission{ID: "223e4567-e89b-42d3-a456-426614174000", Resource: "orders", Action: "read", Key: "orders:read", Name: "Read", Source: "CUSTOM", CreatedAt: validTime, UpdatedAt: validTime}
	if err := validatePermissionItem(permission); err == nil {
		t.Fatal("invalid permission source accepted")
	}
	binding := RolePermissionBinding{RoleID: "not-a-uuid", PermissionID: permission.ID, CreatedAt: validTime}
	if err := validateRolePermissionBindingItem(binding); err == nil {
		t.Fatal("malformed binding accepted")
	}
	validBinding := RolePermissionBinding{RoleID: validRole.ID, PermissionID: permission.ID, CreatedAt: validTime}
	if err := validateRolePermissionBindingForRole(validBinding, "523e4567-e89b-42d3-a456-426614174000"); err == nil {
		t.Fatal("binding for another role accepted")
	}
	assignment := UserRoleAssignment{ID: "423e4567-e89b-42d3-a456-426614174000", UserID: "323e4567-e89b-42d3-a456-426614174000", RoleID: "not-a-uuid", CreatedAt: validTime, UpdatedAt: validTime}
	if err := validateUserRoleAssignmentItem(assignment); err == nil {
		t.Fatal("malformed assignment accepted")
	}
	validAssignment := UserRoleAssignment{ID: assignment.ID, UserID: assignment.UserID, RoleID: validRole.ID, CreatedAt: validTime, UpdatedAt: validTime}
	if err := validateUserRoleAssignmentForUser(validAssignment, "623e4567-e89b-42d3-a456-426614174000"); err == nil {
		t.Fatal("assignment for another user accepted")
	}
	for _, page := range []AuthorizationPageMetadata{{Size: 0}, {Size: 101}, {Size: 1, TotalElements: 0, TotalPages: 0}, {Size: 1, Number: 1, TotalElements: 1, TotalPages: 1}, {Size: 2, TotalElements: 2, TotalPages: 1}} {
		if err := validateAuthorizationPage(nil, 1, page); err == nil {
			t.Fatalf("malformed page accepted: %+v", page)
		}
	}
}

func TestAuthorizationWireScalarsDistinguishMissingFromZero(t *testing.T) {
	zero, twenty := 0, 20
	zero64 := int64(0)
	validPage := authorizationPageWire{Size: &twenty, Number: &zero, TotalElements: &zero64, TotalPages: &zero}
	if page, err := validPage.value(); err != nil || page.Number != 0 || page.TotalElements != 0 || page.TotalPages != 0 {
		t.Fatalf("valid zero page rejected: page=%+v err=%v", page, err)
	}
	for name, page := range map[string]authorizationPageWire{
		"number":        {Size: &twenty, TotalElements: &zero64, TotalPages: &zero},
		"totalElements": {Size: &twenty, Number: &zero, TotalPages: &zero},
		"totalPages":    {Size: &twenty, Number: &zero, TotalElements: &zero64},
	} {
		t.Run("page_missing_"+name, func(t *testing.T) {
			if _, err := page.value(); err == nil {
				t.Fatal("missing page scalar accepted")
			}
		})
	}
	falseValue := false
	validTime := "2026-07-15T00:00:00Z"
	if role, err := (roleWire{ID: "123e4567-e89b-42d3-a456-426614174000", Key: "admin", Name: "Admin", System: &falseValue, Version: &zero64, CreatedAt: validTime, UpdatedAt: validTime}).value(); err != nil || role.System || role.Version != 0 {
		t.Fatalf("valid false/version zero role rejected: role=%+v err=%v", role, err)
	}
	if _, err := (roleWire{System: &falseValue}).value(); err == nil {
		t.Fatal("role missing version accepted")
	}
	if _, err := (roleWire{Version: &zero64}).value(); err == nil {
		t.Fatal("role missing system accepted")
	}
	if _, err := (permissionWire{}).value(); err == nil {
		t.Fatal("permission missing version accepted")
	}
	if _, err := (rolePermissionSetWire{}).value(); err == nil {
		t.Fatal("role-permission set missing version accepted")
	}
	if _, err := (userRoleAssignmentWire{}).value(); err == nil {
		t.Fatal("assignment missing version accepted")
	}
}

func mapHeader(key, value string) http.Header {
	header := http.Header{}
	header.Set(key, value)
	return header
}
