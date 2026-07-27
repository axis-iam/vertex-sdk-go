package iam_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
)

func newSDK(t *testing.T) (*iam.SDK, *iamtest.MockServer) {
	t.Helper()
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.WithAudience("my-app").Given("admin", "posts:*", "users:read")

	sdk, err := iam.New(&iam.SDKConfig{
		Endpoint:     srv.URL,
		ClientID:     "my-app",
		ClientSecret: "shh",
	})
	if err != nil {
		t.Fatal(err)
	}
	return sdk, srv
}

func TestNew_Discovery(t *testing.T) {
	sdk, _ := newSDK(t)
	if sdk.Client() == nil || sdk.Verifier() == nil || sdk.Resolver() == nil {
		t.Fatal("SDK not fully wired")
	}
}

func TestNew_BadEndpoint(t *testing.T) {
	_, err := iam.New(&iam.SDKConfig{Endpoint: "", ClientID: "x", ClientSecret: "y"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestNew_MissingClientSecret(t *testing.T) {
	_, err := iam.New(&iam.SDKConfig{Endpoint: "https://iam.example.com", ClientID: "x"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestNew_DiscoveryFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, err := iam.New(&iam.SDKConfig{Endpoint: srv.URL, ClientID: "x", ClientSecret: "y"})
	if err == nil {
		t.Fatal("expected discovery error")
	}
}

func TestSDK_Authenticate(t *testing.T) {
	sdk, srv := newSDK(t)
	mw := sdk.Authenticate()
	tok, _ := srv.TokenFor("u1", []string{"admin"})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	reached := false
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		u := authz.FromContext(r.Context())
		if u == nil || u.Subject != "u1" {
			t.Fatalf("bad user: %+v", u)
		}
	})).ServeHTTP(rec, req)
	if !reached {
		t.Fatal("handler not called")
	}
}

func TestContextAliases(t *testing.T) {
	ctx := authz.WithUser(context.Background(), &authz.User{Subject: "u1"})
	if iam.FromContext(ctx).Subject != "u1" {
		t.Fatal("expected root FromContext alias to return user")
	}
	if u, err := iam.MustUser(ctx); err != nil || u.Subject != "u1" {
		t.Fatalf("expected MustUser success, got user=%+v err=%v", u, err)
	}
	if _, err := iam.MustUser(context.Background()); err == nil {
		t.Fatal("expected unauthenticated error")
	}
}

func TestClient_GetMe(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.GivenUserProfile("u1", iamtest.UserProfileDTO{
		UserID:        "u1",
		ApplicationID: "app-1",
		Email:         "u1@example.com",
		Username:      "alice",
		DisplayName:   "Alice",
		Status:        "ACTIVE",
		EmailVerified: true,
		Roles:         []string{"admin"},
		Metadata:      map[string]any{"displayName": "Alice"},
	})
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: srv.URL, ClientID: "my-app", ClientSecret: "shh"})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := client.GetMe(context.Background(), "Bearer access-token")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Username != "alice" || profile.Metadata["displayName"] != "Alice" {
		t.Fatalf("bad profile: %+v", profile)
	}
	if srv.MeCalls() != 1 {
		t.Fatalf("want 1 /me call, got %d", srv.MeCalls())
	}
}

func TestSDK_GetMeCachesAndBypasses(t *testing.T) {
	sdk, srv := newSDK(t)
	srv.GivenUserProfile("u1", iamtest.UserProfileDTO{
		UserID:        "u1",
		ApplicationID: "app-1",
		Email:         "u1@example.com",
		Username:      "alice",
		Status:        "ACTIVE",
		EmailVerified: true,
		Metadata:      map[string]any{},
	})
	ctx := authz.WithUser(context.Background(), &authz.User{Subject: "u1", AppID: "my-app"})

	first, err := sdk.GetMe(ctx, "access-token")
	if err != nil {
		t.Fatal(err)
	}
	srv.GivenUserProfile("u1", iamtest.UserProfileDTO{
		UserID:        "u1",
		ApplicationID: "app-1",
		Email:         "u1@example.com",
		Username:      "alice-fresh",
		Status:        "ACTIVE",
		EmailVerified: true,
		Metadata:      map[string]any{},
	})
	second, err := sdk.GetMe(ctx, "access-token")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := sdk.GetMe(ctx, "access-token", iam.BypassProfileCache())
	if err != nil {
		t.Fatal(err)
	}

	if first.Username != "alice" || second.Username != "alice" || fresh.Username != "alice-fresh" {
		t.Fatalf("unexpected usernames: first=%s second=%s fresh=%s", first.Username, second.Username, fresh.Username)
	}
	if srv.MeCalls() != 2 {
		t.Fatalf("want 2 /me calls, got %d", srv.MeCalls())
	}
}

func TestClient_AccountOrganizationHelpersBearerAndPublic(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization")+" client="+r.Header.Get("X-IAM-Client-Id"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/auth/email/verification/send":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"client_id":"my-app"`) {
				t.Fatalf("bad verification send body: %s", body)
			}
			_, _ = w.Write([]byte(`{"message":"If eligible, a verification email has been sent. Please wait before retrying.","retryAfterSeconds":60}`))
		case r.URL.Path == "/api/v1/auth/email/verification/verify":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"token":"verify-token"`) {
				t.Fatalf("bad verification body: %s", body)
			}
			_, _ = w.Write([]byte(`{"message":"Email verified","retryAfterSeconds":null}`))
		case r.URL.Path == "/api/v1/auth/password/change":
			if r.Header.Get("Authorization") != "Bearer user-token" || r.Header.Get("X-IAM-Client-Id") != "" {
				t.Fatalf("bad password change headers: %v", r.Header)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/auth/password/forgot":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"client_id":"my-app"`) {
				t.Fatalf("bad forgot body: %s", body)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/auth/password/reset":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/auth/sessions" && r.Method == http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer user-token" || r.Header.Get("X-IAM-Client-Id") != "" {
				t.Fatalf("bad session headers: %v", r.Header)
			}
			_, _ = w.Write([]byte(`[{"sessionId":"sid-current","ipAddress":"127.0.0.1","userAgent":"Go test","deviceId":null,"createdAt":"2026-07-07T00:00:00Z","lastSeenAt":"2026-07-07T01:00:00Z","current":true}]`))
		case r.URL.Path == "/api/v1/auth/sessions/sid-current" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/auth/sessions" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/auth/logout" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"refresh_token":"refresh-token"`) {
				t.Fatalf("bad logout body: %s", body)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/auth/me/permissions":
			if r.URL.Query().Get("organizationId") != "org-1" {
				t.Fatalf("bad permission summary query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"applicationId":"app-1","organizationId":"org-1","roles":["admin"],"permissions":["orders:read","orders:*"]}`))
		case r.URL.Path == "/api/v1/auth/me/permissions:check":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"permission":"orders:write"`) {
				t.Fatalf("bad permission check body: %s", body)
			}
			_, _ = w.Write([]byte(`{"applicationId":"app-1","organizationId":"org-1","permission":"orders:write","allowed":true,"roles":["admin"]}`))
		case r.URL.Path == "/api/v1/auth/me/security":
			if r.Header.Get("Authorization") != "Bearer user-token" || r.Header.Get("X-IAM-Client-Id") != "" {
				t.Fatalf("bad security headers: %v", r.Header)
			}
			_, _ = w.Write([]byte(`{"emailVerified":true,"passwordCredentialPresent":true,"mfaEnrolled":false,"totpEnrolled":false,"webAuthnEnrolled":false,"activeSessionCount":2}`))
		case r.URL.Path == "/api/v1/auth/me/organizations":
			_, _ = w.Write([]byte(`[{"organizationId":"org-1","name":"Acme","slug":"acme","role":"ADMIN","joinedAt":"2026-07-06T00:00:00Z","current":true}]`))
		case r.URL.Path == "/api/v1/auth/me/organizations/current" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"organizationId":"org-2"`) {
				t.Fatalf("bad switch body: %s", body)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"organizationId":"org-2","continuation":"REFRESH_OR_REAUTHENTICATE_WITH_ORGANIZATION","tokenRefreshRequired":true,"message":"refresh"}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/auth/organization-invitations/") && strings.HasSuffix(r.URL.Path, "/accept"):
			if r.Header.Get("Authorization") != "" {
				t.Fatalf("unauthenticated accept should not send bearer: %v", r.Header)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"LOGIN_REQUIRED","continuation":"LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT","applicationId":"app-1","organizationId":"org-1","organizationName":"Acme","role":"MEMBER"}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/auth/organization-invitations/"):
			if r.Header.Get("Authorization") != "" {
				t.Fatalf("preview should be public: %v", r.Header)
			}
			_, _ = w.Write([]byte(`{"applicationId":"app-1","applicationName":"Demo","organizationId":"org-1","organizationName":"Acme","inviteeEmail":"a***@example.com","role":"MEMBER","status":"PENDING","expiresAt":"2026-07-08T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: srv.URL, ClientID: "my-app", ClientSecret: "shh"})
	if err != nil {
		t.Fatal(err)
	}

	security, err := client.GetAccountSecuritySummary(context.Background(), "Bearer user-token")
	if err != nil || security.ActiveSessionCount != 2 {
		t.Fatalf("bad security response: %+v err=%v", security, err)
	}
	sent, err := client.SendEmailVerification(context.Background(), "user@example.com")
	if err != nil || sent.RetryAfterSeconds == nil || *sent.RetryAfterSeconds != 60 {
		t.Fatalf("bad verification send: %+v err=%v", sent, err)
	}
	verified, err := client.VerifyEmail(context.Background(), "verify-token")
	if err != nil || verified.Message != "Email verified" {
		t.Fatalf("bad verification result: %+v err=%v", verified, err)
	}
	if err := client.ChangePassword(context.Background(), "user-token", iam.PasswordChangeRequest{CurrentPassword: "old-pass", NewPassword: "new-pass"}); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if err := client.RequestPasswordReset(context.Background(), "user@example.com", "https://app.example.com/reset"); err != nil {
		t.Fatalf("request password reset: %v", err)
	}
	if err := client.ResetPassword(context.Background(), "reset-token", "new-pass"); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	sessions, err := client.ListAccountSessions(context.Background(), "user-token")
	if err != nil || len(sessions) != 1 || !sessions[0].Current {
		t.Fatalf("bad sessions: %+v err=%v", sessions, err)
	}
	if err := client.RevokeAccountSession(context.Background(), "user-token", "sid-current"); err != nil {
		t.Fatalf("revoke one: %v", err)
	}
	if err := client.RevokeOtherAccountSessions(context.Background(), "user-token"); err != nil {
		t.Fatalf("revoke other: %v", err)
	}
	if err := client.LogoutAccount(context.Background(), "user-token", "refresh-token"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	orgs, err := client.ListAccountOrganizations(context.Background(), "user-token")
	if err != nil || len(orgs) != 1 || orgs[0].OrganizationID != "org-1" {
		t.Fatalf("bad orgs: %+v err=%v", orgs, err)
	}
	switched, err := client.SwitchAccountOrganization(context.Background(), "user-token", "org-2")
	if err != nil || !switched.TokenRefreshRequired {
		t.Fatalf("bad switch: %+v err=%v", switched, err)
	}
	member, err := client.HasAccountOrganizationMembership(context.Background(), "user-token", "org-1")
	if err != nil || !member {
		t.Fatalf("bad membership: %v %v", member, err)
	}
	summary, err := client.GetAccountPermissionSummary(context.Background(), "user-token", "org-1")
	if err != nil || len(summary.Permissions) != 2 {
		t.Fatalf("bad permission summary: %+v err=%v", summary, err)
	}
	check, err := client.CheckAccountPermission(context.Background(), "user-token", "orders:write", "org-1")
	if err != nil || !check.Allowed {
		t.Fatalf("bad permission check: %+v err=%v", check, err)
	}
	preview, err := client.PreviewOrganizationInvitation(context.Background(), "public-token")
	if err != nil || preview.OrganizationName != "Acme" {
		t.Fatalf("bad preview: %+v err=%v", preview, err)
	}
	accepted, err := client.AcceptOrganizationInvitation(context.Background(), "public-token", "")
	if err != nil || accepted.Status != "LOGIN_REQUIRED" {
		t.Fatalf("bad accept: %+v err=%v", accepted, err)
	}
	if len(seen) != 17 {
		t.Fatalf("want 17 requests, got %d: %v", len(seen), seen)
	}
}

func TestSDK_RequirePerm(t *testing.T) {
	sdk, srv := newSDK(t)
	auth := sdk.Authenticate()
	requireRead := sdk.RequirePerm(authz.PermissionKey{Resource: "users", Action: "read"})

	tok, _ := srv.TokenFor("u1", []string{"admin"})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth(requireRead(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("want 204, got %d", rec.Code)
	}
}

func TestSDK_RootGuardHelpers(t *testing.T) {
	sdk, srv := newSDK(t)
	auth := sdk.Authenticate()
	guard := sdk.RequireAnyPerm([]authz.PermissionKey{
		{Resource: "posts", Action: "write"},
		{Resource: "users", Action: "read"},
	})
	guard = chain(guard, sdk.RequireAllPerms([]authz.PermissionKey{
		{Resource: "posts", Action: "read"},
		{Resource: "users", Action: "read"},
	}))
	guard = chain(guard, sdk.RequireStepUp("urn:iam:acr:mfa"))
	guard = chain(guard, sdk.RequireNoImpersonation())

	tok, _ := srv.TokenForWith("u1", []string{"admin"}, map[string]any{"acr": "urn:iam:acr:mfa"})
	req := httptest.NewRequest("POST", "/danger", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth(guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("want 204, got %d", rec.Code)
	}

	impersonated, _ := srv.TokenForWith("u2", []string{"admin"}, map[string]any{
		"acr": "urn:iam:acr:mfa",
		"act": map[string]any{"sub": "admin-actor"},
	})
	req2 := httptest.NewRequest("POST", "/danger", nil)
	req2.Header.Set("Authorization", "Bearer "+impersonated)
	rec2 := httptest.NewRecorder()
	auth(guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("should not reach") }))).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec2.Code)
	}
}

func TestSDKClient_APIError(t *testing.T) {
	// Force a 500 → ensure APIError surfaces.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = w.Write([]byte(`{"jwks_uri":"` + r.Host + `/.well-known/jwks.json"}`))
			return
		}
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: srv.URL, ClientID: "x", ClientSecret: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolvePermissions(context.Background(), "x", []string{"r"}); err == nil {
		t.Fatal("expected error")
	}
}

func chain(first, second func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return first(second(next))
	}
}
