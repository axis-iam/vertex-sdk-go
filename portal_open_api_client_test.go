package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
)

func TestPortalOpenAPIClient_TokenScopesCacheAndHeaders(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	client := newPortalOpenAPITestClient(t, server.URL, 0)

	var getOut map[string]string
	if err := client.RequestJSON(context.Background(), http.MethodGet, "/open/v1/stats", nil, &getOut); err != nil {
		t.Fatal(err)
	}
	if err := client.RequestJSON(context.Background(), http.MethodGet, "/open/v1/stats", nil, &getOut); err != nil {
		t.Fatal(err)
	}
	var postOut map[string]string
	if err := client.RequestJSON(context.Background(), http.MethodPost, "/open/v1/roles", map[string]string{"name": "admin"}, &postOut); err != nil {
		t.Fatal(err)
	}

	if got := server.tokenCalls[iam.PortalOpenAPIReadScope]; got != 1 {
		t.Fatalf("read token calls = %d, want 1", got)
	}
	if got := server.tokenCalls[iam.PortalOpenAPIWriteScope]; got != 1 {
		t.Fatalf("write token calls = %d, want 1", got)
	}
	if got := len(server.tokenRequests); got != 2 {
		t.Fatalf("token requests = %d, want 2", got)
	}
	for _, req := range server.tokenRequests {
		if req.grantType != "client_credentials" {
			t.Fatalf("token grant_type = %q", req.grantType)
		}
		if req.basicUser != "m2m-client" || req.basicPass != "secret" {
			t.Fatalf("token Basic auth = %q:%q", req.basicUser, req.basicPass)
		}
		if !strings.HasPrefix(req.contentType, "application/x-www-form-urlencoded") {
			t.Fatalf("token content-type = %q", req.contentType)
		}
	}
	if len(server.portalRequests) != 3 {
		t.Fatalf("portal requests = %d, want 3", len(server.portalRequests))
	}
	if server.portalRequests[0].authorization != "Bearer token-portal:openapi:read-1" {
		t.Fatalf("GET auth header = %q", server.portalRequests[0].authorization)
	}
	if server.portalRequests[1].authorization != "Bearer token-portal:openapi:read-1" {
		t.Fatalf("cached GET auth header = %q", server.portalRequests[1].authorization)
	}
	if server.portalRequests[2].authorization != "Bearer token-portal:openapi:write-1" {
		t.Fatalf("POST auth header = %q", server.portalRequests[2].authorization)
	}
	for _, req := range server.portalRequests {
		if req.basicAuth {
			t.Fatal("Portal resource request used Basic auth")
		}
		if req.xIAMClientID != "" || req.xApplicationID != "" || req.xAppKey != "" {
			t.Fatalf("Portal resource request leaked forbidden headers: %+v", req)
		}
	}
}

func TestPortalOpenAPIClient_WriteMethodsUseWriteScope(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	client := newPortalOpenAPITestClient(t, server.URL, 0)

	if err := client.RequestJSON(context.Background(), http.MethodPut, "/open/v1/roles/role-1", map[string]string{"name": "admin"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.RequestJSON(context.Background(), http.MethodPatch, "/open/v1/roles/role-1", map[string]string{"name": "editor"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.RequestJSON(context.Background(), http.MethodDelete, "/open/v1/roles/role-1", nil, nil); err != nil {
		t.Fatal(err)
	}

	if got := server.tokenCalls[iam.PortalOpenAPIWriteScope]; got != 1 {
		t.Fatalf("write token calls = %d, want 1", got)
	}
	if got := server.tokenCalls[iam.PortalOpenAPIReadScope]; got != 0 {
		t.Fatalf("read token calls = %d, want 0", got)
	}
	if got := len(server.portalRequests); got != 3 {
		t.Fatalf("portal requests = %d, want 3", got)
	}
	for i, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := server.portalRequests[i]
		if req.method != method {
			t.Fatalf("portal method[%d] = %q, want %q", i, req.method, method)
		}
		if req.authorization != "Bearer token-portal:openapi:write-1" {
			t.Fatalf("portal auth[%d] = %q", i, req.authorization)
		}
	}
}

func TestPortalOpenAPIClient_RegistrationGrantHelpersUseExactScopes(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	client := newPortalOpenAPITestClient(t, server.URL, 0)
	ctx := context.Background()

	if _, err := client.ListRegistrationGrants(ctx, iam.RegistrationGrantListOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRegistrationGrant(ctx, iam.CreateRegistrationGrantRequest{Type: iam.CreateRegistrationGrantEmailLink}); !errors.Is(err, iam.ErrPortalOpenAPIRequest) {
		t.Fatalf("malformed create response error = %v", err)
	}
	if _, err := client.ListRegistrationGrantRedemptions(ctx, "123e4567-e89b-12d3-a456-426614174000", nil, nil); err != nil {
		t.Fatal(err)
	}

	if server.tokenCalls[iam.RegistrationGrantsReadScope] != 1 || server.tokenCalls[iam.RegistrationGrantsWriteScope] != 1 || server.tokenCalls[iam.RegistrationGrantsRedemptionsReadScope] != 1 {
		t.Fatalf("registration-grant token calls = %#v", server.tokenCalls)
	}
}

func TestPortalOpenAPIClient_RegistrationGrantListEncodesFiltersAndParsesOrgInvitation(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	orgInvitation := iam.RegistrationGrantOrgInvitation
	active := iam.RegistrationGrantActive
	search := "a+b & c"
	page, size := 2, 25
	server.portalResponse = func(request portalOpenAPIResourceRequest) (int, any) {
		if request.path != "/open/v1/registration-grants" || request.rawQuery != "page=2&search=a%2Bb+%26+c&size=25&status=ACTIVE&type=ORG_INVITATION" {
			t.Fatalf("unexpected list request: %+v", request)
		}
		return http.StatusOK, map[string]any{"content": []any{registrationGrantJSON("ORG_INVITATION")}, "page": registrationGrantPageJSON(25, 2)}
	}
	client := newPortalOpenAPITestClient(t, server.URL, 0)

	result, err := client.ListRegistrationGrants(context.Background(), iam.RegistrationGrantListOptions{Type: &orgInvitation, Status: &active, Search: &search, Page: &page, Size: &size})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 || result.Content[0].Type != iam.RegistrationGrantOrgInvitation {
		t.Fatalf("ORG_INVITATION page = %#v", result)
	}
	if got := server.tokenCalls[iam.RegistrationGrantsReadScope]; got != 1 {
		t.Fatalf("read token calls = %d", got)
	}
}

func TestPortalOpenAPIClient_RegistrationGrantCreateAcceptsNullNonmatchingProof(t *testing.T) {
	for _, test := range []struct {
		name      string
		typeValue iam.CreateRegistrationGrantType
		grantType string
		response  map[string]any
	}{
		{"email link", iam.CreateRegistrationGrantEmailLink, "EMAIL_LINK", map[string]any{"registrationGrantToken": "fake-one-time-proof", "registrationAccessCode": nil}},
		{"access code", iam.CreateRegistrationGrantAccessCode, "ACCESS_CODE", map[string]any{"registrationGrantToken": nil, "registrationAccessCode": "fake-one-time-proof"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newPortalOpenAPITestServer(t, 120)
			defer server.Close()
			server.portalResponse = func(request portalOpenAPIResourceRequest) (int, any) {
				if request.method != http.MethodPost || request.path != "/open/v1/registration-grants" || request.body != `{"type":"`+string(test.typeValue)+`"}` {
					t.Fatalf("unexpected create request: %+v", request)
				}
				body := map[string]any{"grant": registrationGrantJSON(test.grantType)}
				for key, value := range test.response {
					body[key] = value
				}
				return http.StatusCreated, body
			}
			created, err := newPortalOpenAPITestClient(t, server.URL, 0).CreateRegistrationGrant(context.Background(), iam.CreateRegistrationGrantRequest{Type: test.typeValue})
			if err != nil {
				t.Fatal(err)
			}
			if created.Grant.Type != iam.RegistrationGrantType(test.grantType) {
				t.Fatalf("created grant = %#v", created)
			}
			if test.typeValue == iam.CreateRegistrationGrantEmailLink && (created.RegistrationGrantToken == nil || created.RegistrationAccessCode != nil) {
				t.Fatalf("email proof = %#v", created)
			}
			if test.typeValue == iam.CreateRegistrationGrantAccessCode && (created.RegistrationAccessCode == nil || created.RegistrationGrantToken != nil) {
				t.Fatalf("code proof = %#v", created)
			}
		})
	}
}

func TestPortalOpenAPIClient_RegistrationGrantCreateRejectsInvalidProofContracts(t *testing.T) {
	for _, test := range []struct {
		grantType string
		proofs    map[string]any
	}{
		{"EMAIL_LINK", map[string]any{"registrationGrantToken": nil, "registrationAccessCode": nil}},
		{"EMAIL_LINK", map[string]any{"registrationGrantToken": "fake-token", "registrationAccessCode": "fake-code"}},
		{"EMAIL_LINK", map[string]any{"registrationGrantToken": "", "registrationAccessCode": nil}},
		{"EMAIL_LINK", map[string]any{"registrationGrantToken": nil, "registrationAccessCode": "fake-code"}},
		{"ORG_INVITATION", map[string]any{"registrationGrantToken": "fake-token", "registrationAccessCode": nil}},
	} {
		server := newPortalOpenAPITestServer(t, 120)
		server.portalResponse = func(_ portalOpenAPIResourceRequest) (int, any) {
			body := map[string]any{"grant": registrationGrantJSON(test.grantType)}
			for key, value := range test.proofs {
				body[key] = value
			}
			return http.StatusCreated, body
		}
		_, err := newPortalOpenAPITestClient(t, server.URL, 0).CreateRegistrationGrant(context.Background(), iam.CreateRegistrationGrantRequest{Type: iam.CreateRegistrationGrantEmailLink})
		server.Close()
		if !errors.Is(err, iam.ErrPortalOpenAPIRequest) || strings.Contains(err.Error(), "fake-token") || strings.Contains(err.Error(), "fake-code") {
			t.Fatalf("invalid proof error = %v", err)
		}
	}
}

func TestPortalOpenAPIClient_RegistrationGrantDetailLifecycleRevokeAndRedemptionVectors(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	id := "019f4cca-88f8-7e77-a67d-4a6a2a68b803"
	server.portalResponse = func(request portalOpenAPIResourceRequest) (int, any) {
		if strings.HasSuffix(request.path, "/redemptions") {
			return http.StatusOK, map[string]any{"content": []any{}, "page": registrationGrantPageJSON(10, 1)}
		}
		return http.StatusOK, registrationGrantJSON("ORG_INVITATION")
	}
	client := newPortalOpenAPITestClient(t, server.URL, 0)
	if detail, err := client.GetRegistrationGrant(context.Background(), id); err != nil || detail.Type != iam.RegistrationGrantOrgInvitation {
		t.Fatalf("detail = %#v, %v", detail, err)
	}
	if _, err := client.PauseRegistrationGrant(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResumeRegistrationGrant(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RevokeRegistrationGrant(context.Background(), id, nil); err != nil {
		t.Fatal(err)
	}
	reason := "expired request"
	if _, err := client.RevokeRegistrationGrant(context.Background(), id, &reason); err != nil {
		t.Fatal(err)
	}
	page, size := 1, 10
	if _, err := client.ListRegistrationGrantRedemptions(context.Background(), id, &page, &size); err != nil {
		t.Fatal(err)
	}

	got := server.portalRequests
	want := []struct{ method, path, query, body string }{
		{http.MethodGet, "/open/v1/registration-grants/" + id, "", ""},
		{http.MethodPost, "/open/v1/registration-grants/" + id + "/pause", "", ""},
		{http.MethodPost, "/open/v1/registration-grants/" + id + "/resume", "", ""},
		{http.MethodPost, "/open/v1/registration-grants/" + id + "/revoke", "", ""},
		{http.MethodPost, "/open/v1/registration-grants/" + id + "/revoke", "", `{"reason":"expired request"}`},
		{http.MethodGet, "/open/v1/registration-grants/" + id + "/redemptions", "page=1&size=10", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("requests = %#v", got)
	}
	for index, expected := range want {
		if got[index].method != expected.method || got[index].path != expected.path || got[index].rawQuery != expected.query || got[index].body != expected.body {
			t.Fatalf("request[%d] = %+v, want %+v", index, got[index], expected)
		}
	}
	if server.tokenCalls[iam.RegistrationGrantsReadScope] != 1 || server.tokenCalls[iam.RegistrationGrantsWriteScope] != 1 || server.tokenCalls[iam.RegistrationGrantsRedemptionsReadScope] != 1 {
		t.Fatalf("scope calls = %#v", server.tokenCalls)
	}
}

func TestPortalOpenAPIClient_RegistrationGrantUUIDv7AndBackendErrors(t *testing.T) {
	t.Run("UUIDv7 and noncanonical local failure", func(t *testing.T) {
		server := newPortalOpenAPITestServer(t, 120)
		defer server.Close()
		server.portalResponse = func(_ portalOpenAPIResourceRequest) (int, any) {
			return http.StatusOK, registrationGrantJSON("EMAIL_LINK")
		}
		client := newPortalOpenAPITestClient(t, server.URL, 0)
		if _, err := client.GetRegistrationGrant(context.Background(), "019f4cca-88f8-7e77-a67d-4a6a2a68b803"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.GetRegistrationGrant(context.Background(), "019f4cca88f87e77a67d4a6a2a68b803"); !errors.Is(err, iam.ErrPortalOpenAPIRequest) {
			t.Fatalf("noncanonical UUID error = %v", err)
		}
		if len(server.portalRequests) != 1 {
			t.Fatalf("resource calls = %d", len(server.portalRequests))
		}
	})
	t.Run("403 404 and 409 propagate", func(t *testing.T) {
		for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusConflict} {
			server := newPortalOpenAPITestServer(t, 120)
			server.portalResponse = func(_ portalOpenAPIResourceRequest) (int, any) {
				return status, map[string]any{"error": "CONTRACT_ERROR", "message": "safe error"}
			}
			_, err := newPortalOpenAPITestClient(t, server.URL, 0).GetRegistrationGrant(context.Background(), "019f4cca-88f8-7e77-a67d-4a6a2a68b803")
			server.Close()
			var portalErr *iam.PortalOpenAPIError
			if !errors.As(err, &portalErr) || portalErr.Status != status || portalErr.Code != "CONTRACT_ERROR" {
				t.Fatalf("status %d error = %#v", status, err)
			}
		}
	})
}

func TestPortalOpenAPIClient_RegistrationGrantExactScopeCacheIsolation(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	client := newPortalOpenAPITestClient(t, server.URL, 0)
	for _, scope := range []iam.PortalOpenAPIScope{iam.RegistrationGrantsReadScope, iam.RegistrationGrantsWriteScope, iam.RegistrationGrantsRedemptionsReadScope} {
		if _, err := client.GetMachineToken(context.Background(), scope); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []iam.PortalOpenAPIScope{iam.RegistrationGrantsReadScope, iam.RegistrationGrantsWriteScope, iam.RegistrationGrantsRedemptionsReadScope} {
		if _, err := client.GetMachineToken(context.Background(), scope); err != nil {
			t.Fatal(err)
		}
	}
	if len(server.tokenRequests) != 3 {
		t.Fatalf("token requests = %#v", server.tokenRequests)
	}
}

func TestPortalOpenAPIClient_OrganizationManagementHelpersUseExactScopesAndConditionalHeaders(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	server.portalResponseHeaders = http.Header{"ETag": []string{`"7"`}}
	organizationID := "123e4567-e89b-42d3-a456-426614174000"
	invitationID := "223e4567-e89b-42d3-a456-426614174000"
	membershipID := "323e4567-e89b-42d3-a456-426614174000"
	server.portalResponse = func(request portalOpenAPIResourceRequest) (int, any) {
		switch {
		case request.path == "/open/v1/organizations" && request.method == http.MethodGet:
			return http.StatusOK, map[string]any{"content": []any{organizationJSON(organizationID)}, "page": organizationPageJSON(10, 1)}
		case strings.HasSuffix(request.path, "/invitations"):
			if request.method == http.MethodGet {
				return http.StatusOK, map[string]any{"content": []any{organizationInvitationJSON(invitationID)}, "page": organizationPageJSON(10, 1)}
			}
			return http.StatusCreated, organizationInvitationJSON(invitationID)
		case strings.Contains(request.path, "/invitations/"):
			if request.method == http.MethodDelete {
				return http.StatusNoContent, nil
			}
			return http.StatusOK, organizationInvitationJSON(invitationID)
		case strings.HasSuffix(request.path, "/members") && request.method == http.MethodGet:
			return http.StatusOK, map[string]any{"content": []any{organizationMemberJSON(membershipID)}, "page": organizationPageJSON(10, 1)}
		case strings.Contains(request.path, "/members/"):
			if request.method == http.MethodDelete {
				return http.StatusNoContent, nil
			}
			return http.StatusOK, organizationMemberJSON(membershipID)
		case request.method == http.MethodDelete:
			return http.StatusNoContent, nil
		default:
			return http.StatusOK, organizationJSON(organizationID)
		}
	}
	client := newPortalOpenAPITestClient(t, server.URL, 0)
	ctx := context.Background()
	search := "acme & co"
	page, size := 1, 10
	if _, err := client.ListOrganizations(ctx, iam.OrganizationListOptions{
		Search: &search, Page: &page, Size: &size,
		Sort: []string{"name", "slug"}, Direction: []iam.OrganizationSortDirection{iam.OrganizationSortAscending, iam.OrganizationSortDescending},
	}); err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateOrganization(ctx, iam.CreateOrganizationRequest{Name: "Acme", Slug: "acme"}, &iam.OrganizationCreateOptions{IdempotencyKey: "org-create-1"})
	if err != nil || created.ETag != `"7"` {
		t.Fatalf("created organization = %#v, %v", created, err)
	}
	if _, err := client.GetOrganization(ctx, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateOrganization(ctx, organizationID, iam.UpdateOrganizationRequest{Name: ptr("Acme Inc.")}, &iam.OrganizationIfMatchOptions{IfMatch: `"7"`}); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteOrganization(ctx, organizationID, &iam.OrganizationIfMatchOptions{IfMatch: `"8"`}); err != nil {
		t.Fatal(err)
	}
	pending := iam.OrganizationInvitationPending
	if _, err := client.ListOrganizationInvitations(ctx, organizationID, iam.OrganizationInvitationListOptions{Status: &pending, Page: &page, Size: &size}); err != nil {
		t.Fatal(err)
	}
	admin := iam.OrganizationMemberRoleAdmin
	if _, err := client.CreateOrganizationInvitation(ctx, organizationID, iam.CreateOrganizationInvitationRequest{Email: "member@example.test", Role: &admin}, &iam.OrganizationCreateOptions{IdempotencyKey: "invite-create-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetOrganizationInvitation(ctx, organizationID, invitationID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResendOrganizationInvitation(ctx, organizationID, invitationID); err != nil {
		t.Fatal(err)
	}
	if err := client.CancelOrganizationInvitation(ctx, organizationID, invitationID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListOrganizationMembers(ctx, organizationID, iam.OrganizationMemberListOptions{Search: ptr("member"), Page: &page, Size: &size}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetOrganizationMember(ctx, organizationID, membershipID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateOrganizationMemberRole(ctx, organizationID, membershipID, iam.OrganizationMemberRoleAdmin, &iam.OrganizationIfMatchOptions{IfMatch: `"2"`}); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveOrganizationMember(ctx, organizationID, membershipID); err != nil {
		t.Fatal(err)
	}

	for _, scope := range []iam.PortalOpenAPIScope{
		iam.OrganizationsReadScope, iam.OrganizationsWriteScope,
		iam.OrganizationInvitationsReadScope, iam.OrganizationInvitationsWriteScope,
		iam.OrganizationMembersReadScope, iam.OrganizationMembersWriteScope,
	} {
		if server.tokenCalls[scope] != 1 {
			t.Fatalf("scope %s token calls = %d", scope, server.tokenCalls[scope])
		}
	}
	requests := server.portalRequests
	if requests[0].rawQuery != "direction=ASC&direction=DESC&page=1&search=acme+%26+co&size=10&sort=name&sort=slug" {
		t.Fatalf("organization list query = %q", requests[0].rawQuery)
	}
	if requests[1].idempotencyKey != "org-create-1" || requests[3].ifMatch != `"7"` || requests[4].ifMatch != `"8"` {
		t.Fatalf("organization conditional headers = %#v", requests[:5])
	}
	if requests[6].idempotencyKey != "invite-create-1" || requests[12].ifMatch != `"2"` {
		t.Fatalf("invitation/member headers = %#v", requests)
	}
	if requests[7].path != "/open/v1/organizations/"+organizationID+"/invitations/"+invitationID || requests[10].path != "/open/v1/organizations/"+organizationID+"/members" {
		t.Fatalf("organization management paths = %#v", requests)
	}
}

func TestPortalOpenAPIClient_OrganizationInvitationRetryAndLastOwnerErrorsAreTyped(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	organizationID := "123e4567-e89b-42d3-a456-426614174000"
	invitationID := "223e4567-e89b-42d3-a456-426614174000"
	membershipID := "323e4567-e89b-42d3-a456-426614174000"
	server.portalResponseHeaders = http.Header{"Retry-After": []string{"30"}}
	server.portalResponse = func(request portalOpenAPIResourceRequest) (int, any) {
		if strings.HasSuffix(request.path, "/resend") {
			return http.StatusTooManyRequests, map[string]any{"error": "CONFLICT", "message": "terminal invitation"}
		}
		return http.StatusBadRequest, map[string]any{"error": "BAD_REQUEST", "message": "Cannot remove the last OWNER"}
	}
	client := newPortalOpenAPITestClient(t, server.URL, 0)
	_, err := client.ResendOrganizationInvitation(context.Background(), organizationID, invitationID)
	var portalErr *iam.PortalOpenAPIError
	if !errors.As(err, &portalErr) || portalErr.Status != http.StatusTooManyRequests || portalErr.RetryAfter != "30" {
		t.Fatalf("retry error = %#v", err)
	}
	_, err = client.GetMachineToken(context.Background(), iam.OrganizationMembersWriteScope)
	if err != nil {
		t.Fatal(err)
	}
	err = client.RemoveOrganizationMember(context.Background(), organizationID, membershipID)
	if !errors.As(err, &portalErr) || portalErr.Status != http.StatusBadRequest || portalErr.Code != "BAD_REQUEST" {
		t.Fatalf("last owner error = %#v", err)
	}
}

func TestPortalOpenAPIClient_StaleTokenRefresh(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 1)
	defer server.Close()
	client := newPortalOpenAPITestClient(t, server.URL, 2*time.Second)

	if _, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIReadScope); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIReadScope); err != nil {
		t.Fatal(err)
	}
	if got := server.tokenCalls[iam.PortalOpenAPIReadScope]; got != 2 {
		t.Fatalf("read token calls = %d, want stale refresh to call twice", got)
	}
	if got := server.tokenCalls[iam.PortalOpenAPIWriteScope]; got != 0 {
		t.Fatalf("write token calls = %d, want 0", got)
	}
}

func TestPortalOpenAPIClient_PathAndMethodGuard(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	client := newPortalOpenAPITestClient(t, server.URL, 0)

	err := client.RequestJSON(context.Background(), http.MethodGet, "/api/v1/auth/me", nil, nil)
	if !errors.Is(err, iam.ErrPortalOpenAPIRequest) {
		t.Fatalf("path guard error = %v", err)
	}
	err = client.RequestJSON(context.Background(), http.MethodHead, "/open/v1/stats", nil, nil)
	if !errors.Is(err, iam.ErrPortalOpenAPIRequest) {
		t.Fatalf("method guard error = %v", err)
	}
	if got := len(server.tokenRequests); got != 0 {
		t.Fatalf("token calls after guard failures = %d, want 0", got)
	}
}

func TestPortalOpenAPIClient_TokenErrors(t *testing.T) {
	t.Run("unsupported scope", func(t *testing.T) {
		server := newPortalOpenAPITestServer(t, 120)
		defer server.Close()
		client := newPortalOpenAPITestClient(t, server.URL, 0)

		_, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIScope("openid"))
		if !errors.Is(err, iam.ErrPortalOpenAPIToken) {
			t.Fatalf("unsupported scope error = %v", err)
		}
		if got := len(server.tokenRequests); got != 0 {
			t.Fatalf("token calls = %d, want 0", got)
		}
	})

	t.Run("empty scope", func(t *testing.T) {
		server := newPortalOpenAPITestServer(t, 120)
		defer server.Close()
		client := newPortalOpenAPITestClient(t, server.URL, 0)

		_, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIScope(""))
		if !errors.Is(err, iam.ErrPortalOpenAPIToken) {
			t.Fatalf("empty scope error = %v", err)
		}
		if got := len(server.tokenRequests); got != 0 {
			t.Fatalf("token calls = %d, want 0", got)
		}
	})

	t.Run("token endpoint invalid scope", func(t *testing.T) {
		server := newPortalOpenAPITestServer(t, 120)
		server.tokenStatus = http.StatusBadRequest
		server.tokenError = "invalid_scope"
		defer server.Close()
		client := newPortalOpenAPITestClient(t, server.URL, 0)

		_, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIReadScope)
		if !errors.Is(err, iam.ErrPortalOpenAPIToken) {
			t.Fatalf("token endpoint error = %v", err)
		}
		var tokenErr *iam.PortalOpenAPITokenError
		if !errors.As(err, &tokenErr) || tokenErr.Code != "invalid_scope" || tokenErr.Status != http.StatusBadRequest {
			t.Fatalf("bad token error: %#v", err)
		}
	})

	t.Run("missing requested response scope", func(t *testing.T) {
		server := newPortalOpenAPITestServer(t, 120)
		server.overrideResponseScope = string(iam.PortalOpenAPIReadScope)
		defer server.Close()
		client := newPortalOpenAPITestClient(t, server.URL, 0)

		_, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIWriteScope)
		if !errors.Is(err, iam.ErrPortalOpenAPIToken) {
			t.Fatalf("response scope error = %v", err)
		}
		var tokenErr *iam.PortalOpenAPITokenError
		if !errors.As(err, &tokenErr) || tokenErr.Code != "invalid_scope" {
			t.Fatalf("bad token error: %#v", err)
		}
	})
}

func TestPortalOpenAPIClient_UsesIamTestTokenEndpoint(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	client, err := iam.NewPortalOpenAPIClient(iam.PortalOpenAPIClientConfig{
		Issuer:         srv.URL,
		PortalEndpoint: srv.URL,
		ClientID:       "m2m-client",
		ClientSecret:   "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := client.GetMachineToken(context.Background(), iam.PortalOpenAPIReadScope)
	if err != nil {
		t.Fatal(err)
	}
	if token.Scope != iam.PortalOpenAPIReadScope || !strings.Contains(token.AccessToken, string(iam.PortalOpenAPIReadScope)) {
		t.Fatalf("bad token: %+v", token)
	}
	if got := srv.TokenCalls(string(iam.PortalOpenAPIReadScope)); got != 1 {
		t.Fatalf("mock token calls = %d, want 1", got)
	}
}

func TestNewPortalOpenAPIClient_ConfigValidation(t *testing.T) {
	_, err := iam.NewPortalOpenAPIClient(iam.PortalOpenAPIClientConfig{})
	if !errors.Is(err, iam.ErrPortalOpenAPIConfig) {
		t.Fatalf("config error = %v", err)
	}
	_, err = iam.NewPortalOpenAPIClient(iam.PortalOpenAPIClientConfig{
		Issuer:         "https://iam.example.com",
		PortalEndpoint: "https://portal.example.com",
		ClientID:       "client",
		ClientSecret:   "secret",
		TokenSkew:      -time.Second,
	})
	if !errors.Is(err, iam.ErrPortalOpenAPIConfig) {
		t.Fatalf("negative skew error = %v", err)
	}
}

func TestAuthorizationManagementBindsObjectIdentityAndRequiresPageScalars(t *testing.T) {
	server := newPortalOpenAPITestServer(t, 120)
	defer server.Close()
	server.portalResponseHeaders = http.Header{"ETag": []string{`"1"`}}
	var response any
	server.portalResponse = func(portalOpenAPIResourceRequest) (int, any) { return http.StatusOK, response }
	client := newPortalOpenAPITestClient(t, server.URL, 0)
	ctx := context.Background()
	roleID := "123e4567-e89b-42d3-a456-426614174000"
	permissionID := "223e4567-e89b-42d3-a456-426614174000"
	userID := "323e4567-e89b-42d3-a456-426614174000"
	assignmentID := "423e4567-e89b-42d3-a456-426614174000"
	wrongID := "523e4567-e89b-42d3-a456-426614174000"
	timestamp := "2026-07-15T00:00:00Z"
	assertInvalid := func(_ any, err error) {
		t.Helper()
		var portalErr *iam.PortalOpenAPIError
		if !errors.As(err, &portalErr) || portalErr.Code != "invalid_authorization_response" {
			t.Fatalf("error = %v, want stable invalid_authorization_response", err)
		}
	}

	response = map[string]any{"id": wrongID, "key": "admin", "name": "Admin", "description": nil, "system": false, "version": 0, "createdAt": timestamp, "updatedAt": timestamp}
	assertInvalid(client.GetRole(ctx, roleID))
	assertInvalid(client.UpdateRole(ctx, roleID, iam.UpdateRoleRequest{}, `"0"`))
	response = map[string]any{"id": wrongID, "resource": "orders", "action": "read", "key": "orders:read", "name": "Read", "description": nil, "source": "MANUAL", "version": 0, "createdAt": timestamp, "updatedAt": timestamp}
	assertInvalid(client.GetPermission(ctx, permissionID))
	assertInvalid(client.UpdatePermission(ctx, permissionID, iam.UpdatePermissionRequest{}, `"0"`))
	response = map[string]any{"roleId": wrongID, "permissionIds": []string{permissionID}, "version": 0}
	assertInvalid(client.ReplaceRolePermissions(ctx, roleID, []string{permissionID}, `"0"`))
	assignment := map[string]any{"id": assignmentID, "userId": userID, "roleId": roleID, "organizationId": nil, "conditionExpression": nil, "conditionDescription": nil, "version": 0, "createdAt": timestamp, "updatedAt": timestamp}
	response = cloneMap(assignment, "userId", wrongID)
	assertInvalid(client.CreateUserRole(ctx, userID, iam.CreateUserRoleRequest{RoleID: roleID}, nil))
	response = cloneMap(assignment, "roleId", wrongID)
	assertInvalid(client.CreateUserRole(ctx, userID, iam.CreateUserRoleRequest{RoleID: roleID}, nil))
	response = cloneMap(assignment, "userId", wrongID)
	assertInvalid(client.UpdateUserRole(ctx, userID, assignmentID, iam.UpdateUserRoleRequest{}, `"0"`))
	response = cloneMap(assignment, "id", wrongID)
	assertInvalid(client.UpdateUserRole(ctx, userID, assignmentID, iam.UpdateUserRoleRequest{}, `"0"`))
	response = map[string]any{"content": []any{}, "page": map[string]any{"size": 20}}
	assertInvalid(client.ListRoles(ctx, iam.AuthorizationPageOptions{}))
	validRole := map[string]any{"id": roleID, "key": "admin", "name": "Admin", "description": nil, "system": false, "version": 0, "createdAt": timestamp, "updatedAt": timestamp}
	response = withoutKey(validRole, "system")
	assertInvalid(client.GetRole(ctx, roleID))
	response = withoutKey(validRole, "version")
	assertInvalid(client.GetRole(ctx, roleID))
	validPermission := map[string]any{"id": permissionID, "resource": "orders", "action": "read", "key": "orders:read", "name": "Read", "description": nil, "source": "MANUAL", "version": 0, "createdAt": timestamp, "updatedAt": timestamp}
	response = withoutKey(validPermission, "version")
	assertInvalid(client.GetPermission(ctx, permissionID))
	response = map[string]any{"roleId": roleID, "permissionIds": []string{permissionID}}
	assertInvalid(client.ReplaceRolePermissions(ctx, roleID, []string{permissionID}, `"0"`))
	response = withoutKey(assignment, "version")
	assertInvalid(client.CreateUserRole(ctx, userID, iam.CreateUserRoleRequest{RoleID: roleID}, nil))

	response = validRole
	if role, err := client.GetRole(ctx, roleID); err != nil || role.System || role.Version != 0 {
		t.Fatalf("valid false/version zero role rejected: role=%+v err=%v", role, err)
	}
	response = validPermission
	if permission, err := client.GetPermission(ctx, permissionID); err != nil || permission.Version != 0 {
		t.Fatalf("valid permission version zero rejected: permission=%+v err=%v", permission, err)
	}
	response = map[string]any{"roleId": roleID, "permissionIds": []string{permissionID}, "version": 0}
	if result, err := client.ReplaceRolePermissions(ctx, roleID, []string{permissionID}, `"0"`); err != nil || result.Version != 0 {
		t.Fatalf("valid role-permission version zero rejected: result=%+v err=%v", result, err)
	}
	response = assignment
	if result, err := client.CreateUserRole(ctx, userID, iam.CreateUserRoleRequest{RoleID: roleID}, nil); err != nil || result.Version != 0 {
		t.Fatalf("valid assignment version zero rejected: result=%+v err=%v", result, err)
	}
	response = map[string]any{"content": []any{}, "page": map[string]any{"size": 20, "number": 0, "totalElements": 0, "totalPages": 0}}
	if _, err := client.ListRoles(ctx, iam.AuthorizationPageOptions{}); err != nil {
		t.Fatalf("valid empty page rejected: %v", err)
	}
}

func cloneMap(source map[string]any, key string, value any) map[string]any {
	result := make(map[string]any, len(source))
	for name, item := range source {
		result[name] = item
	}
	result[key] = value
	return result
}

func withoutKey(source map[string]any, key string) map[string]any {
	result := make(map[string]any, len(source)-1)
	for name, item := range source {
		if name != key {
			result[name] = item
		}
	}
	return result
}

type portalOpenAPITestServer struct {
	*httptest.Server

	mu                    sync.Mutex
	expiresIn             int
	tokenStatus           int
	tokenError            string
	overrideResponseScope string
	portalResponse        func(portalOpenAPIResourceRequest) (int, any)
	portalResponseHeaders http.Header
	tokenCalls            map[iam.PortalOpenAPIScope]int
	tokenRequests         []portalOpenAPITokenRequest
	portalRequests        []portalOpenAPIResourceRequest
}

type portalOpenAPITokenRequest struct {
	scope       iam.PortalOpenAPIScope
	grantType   string
	basicUser   string
	basicPass   string
	contentType string
}

type portalOpenAPIResourceRequest struct {
	method          string
	path            string
	authorization   string
	basicAuth       bool
	xIAMClientID    string
	xApplicationID  string
	xAppKey         string
	idempotencyKey  string
	ifMatch         string
	contentType     string
	requestBodySeen bool
	rawQuery        string
	body            string
}

func newPortalOpenAPITestServer(t *testing.T, expiresIn int) *portalOpenAPITestServer {
	t.Helper()
	s := &portalOpenAPITestServer{
		expiresIn:  expiresIn,
		tokenCalls: map[iam.PortalOpenAPIScope]int{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func newPortalOpenAPITestClient(t *testing.T, endpoint string, tokenSkew time.Duration) *iam.PortalOpenAPIClient {
	t.Helper()
	client, err := iam.NewPortalOpenAPIClient(iam.PortalOpenAPIClientConfig{
		Issuer:         endpoint + "/",
		PortalEndpoint: endpoint + "/",
		ClientID:       "m2m-client",
		ClientSecret:   "secret",
		TokenSkew:      tokenSkew,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (s *portalOpenAPITestServer) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/oauth2/token":
		s.handleToken(w, r)
	case strings.HasPrefix(r.URL.Path, "/open/v1/"):
		s.handlePortal(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *portalOpenAPITestServer) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	user, pass, _ := r.BasicAuth()
	scope := iam.PortalOpenAPIScope(r.Form.Get("scope"))
	s.mu.Lock()
	s.tokenCalls[scope]++
	call := s.tokenCalls[scope]
	s.tokenRequests = append(s.tokenRequests, portalOpenAPITokenRequest{
		scope:       scope,
		grantType:   r.Form.Get("grant_type"),
		basicUser:   user,
		basicPass:   pass,
		contentType: r.Header.Get("Content-Type"),
	})
	tokenStatus := s.tokenStatus
	tokenError := s.tokenError
	responseScope := s.overrideResponseScope
	s.mu.Unlock()

	if tokenStatus != 0 {
		writePortalOpenAPIJSON(w, tokenStatus, map[string]any{"error": tokenError})
		return
	}
	if r.Method != http.MethodPost || user != "m2m-client" || pass != "secret" {
		writePortalOpenAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	if r.Form.Get("grant_type") != "client_credentials" || scope == "" {
		writePortalOpenAPIJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
		return
	}
	if responseScope == "" {
		responseScope = string(scope)
	}
	writePortalOpenAPIJSON(w, http.StatusOK, map[string]any{
		"access_token": "token-" + string(scope) + "-" + strconv.Itoa(call),
		"token_type":   "Bearer",
		"expires_in":   s.expiresIn,
		"scope":        responseScope,
	})
}

func (s *portalOpenAPITestServer) handlePortal(w http.ResponseWriter, r *http.Request) {
	_, _, basic := r.BasicAuth()
	rawBody, _ := io.ReadAll(r.Body)
	var body any
	_ = json.Unmarshal(rawBody, &body)
	s.mu.Lock()
	s.portalRequests = append(s.portalRequests, portalOpenAPIResourceRequest{
		method:          r.Method,
		path:            r.URL.Path,
		authorization:   r.Header.Get("Authorization"),
		basicAuth:       basic,
		xIAMClientID:    r.Header.Get("X-IAM-Client-Id"),
		xApplicationID:  r.Header.Get("X-Application-Id"),
		xAppKey:         r.Header.Get("X-App-Key"),
		idempotencyKey:  r.Header.Get("Idempotency-Key"),
		ifMatch:         r.Header.Get("If-Match"),
		contentType:     r.Header.Get("Content-Type"),
		requestBodySeen: body != nil,
		rawQuery:        r.URL.RawQuery,
		body:            string(rawBody),
	})
	portalResponse := s.portalResponse
	portalResponseHeaders := s.portalResponseHeaders.Clone()
	s.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		writePortalOpenAPIJSON(w, http.StatusUnauthorized, map[string]any{"code": "OPEN_API_MACHINE_TOKEN_REQUIRED"})
		return
	}
	if portalResponse != nil {
		status, response := portalResponse(s.portalRequests[len(s.portalRequests)-1])
		for key, values := range portalResponseHeaders {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		writePortalOpenAPIJSON(w, status, response)
		return
	}
	writePortalOpenAPIJSON(w, http.StatusOK, map[string]any{"ok": "true"})
}

func ptr(value string) *string {
	return &value
}

func organizationJSON(id string) map[string]any {
	return map[string]any{"id": id, "name": "Acme", "slug": "acme", "version": 7, "createdAt": "2026-07-12T00:00:00Z", "updatedAt": "2026-07-12T00:00:00Z"}
}

func organizationPageJSON(size, number int) map[string]any {
	return map[string]any{"size": size, "number": number, "totalElements": 1, "totalPages": 1}
}

func organizationInvitationJSON(id string) map[string]any {
	return map[string]any{"id": id, "email": "member@example.test", "role": "ADMIN", "status": "PENDING", "deliveryStatus": "SENT", "expiresAt": "2026-07-19T00:00:00Z", "createdAt": "2026-07-12T00:00:00Z", "updatedAt": "2026-07-12T00:00:00Z"}
}

func organizationMemberJSON(id string) map[string]any {
	return map[string]any{"membershipId": id, "userId": "423e4567-e89b-42d3-a456-426614174000", "email": "member@example.test", "displayName": "Member", "role": "ADMIN", "joinedAt": "2026-07-12T00:00:00Z", "updatedAt": "2026-07-12T00:00:00Z", "version": 2}
}

func registrationGrantJSON(grantType string) map[string]any {
	return map[string]any{"id": "019f4cca-88f8-7e77-a67d-4a6a2a68b803", "type": grantType, "status": "ACTIVE", "displayName": nil, "allowedEmail": nil, "allowedDomain": nil, "expiresAt": nil, "maxUses": nil, "usedCount": 0, "sourceType": "API", "createdAt": "2026-07-11T00:00:00Z", "updatedAt": "2026-07-11T00:00:00Z", "revokedAt": nil, "revokeReason": nil}
}

func registrationGrantPageJSON(size, number int) map[string]any {
	return map[string]any{"size": size, "number": number, "totalElements": 0, "totalPages": 0}
}

func writePortalOpenAPIJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
