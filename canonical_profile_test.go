package iam_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
)

func TestCanonicalProfileContract(t *testing.T) {
	t.Run("only_current_producer_fields_are_public", func(t *testing.T) {
		want := []string{"userId", "applicationId", "globalIdentityId", "email", "emailVerified", "username", "displayName", "avatarUrl", "status", "createdAt", "updatedAt", "currentOrganization"}
		for _, typ := range []reflect.Type{reflect.TypeOf(iam.UserProfile{}), reflect.TypeOf(iamtest.UserProfileDTO{})} {
			var got []string
			for i := 0; i < typ.NumField(); i++ {
				got = append(got, typ.Field(i).Tag.Get("json"))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s fields = %v; want %v", typ.Name(), got, want)
			}
			for _, name := range []string{"ID", "Roles", "Metadata"} {
				if _, exists := typ.FieldByName(name); exists {
					t.Fatalf("retired %s.%s is public", typ.Name(), name)
				}
			}
		}
		var profile iam.UserProfile
		if err := json.Unmarshal([]byte(`{"id":"legacy-id"}`), &profile); err != nil {
			t.Fatal(err)
		}
		if profile.UserID != "" {
			t.Fatal("retired id was accepted as userId")
		}
	})

	t.Run("profile_nulls_and_independent_permissions", func(t *testing.T) {
		const populated = `{"userId":"user-1","applicationId":"app-1","globalIdentityId":"identity-1","email":"user@example.com","emailVerified":true,"username":"alice","displayName":"Alice","avatarUrl":"https://example.com/avatar.png","status":"ACTIVE","createdAt":"2026-10-30T00:00:00Z","updatedAt":"2026-10-30T01:00:00Z","currentOrganization":{"organizationId":"org-1","name":"Acme","slug":"acme","role":"MEMBER","joinedAt":"2026-10-30T00:00:00Z","current":true}}`
		const nullable = `{"userId":"user-1","applicationId":"app-1","globalIdentityId":null,"email":null,"emailVerified":false,"username":null,"displayName":null,"avatarUrl":null,"status":"ACTIVE","createdAt":"2026-10-30T00:00:00Z","updatedAt":"2026-10-30T01:00:00Z","currentOrganization":null}`
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("X-IAM-Client-Id") != "" {
				t.Error("unexpected bearer/client context")
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v1/auth/me/profile":
				if calls == 1 {
					if r.Method != http.MethodGet {
						t.Error("expected GET")
					}
					_, _ = w.Write([]byte(populated))
				} else {
					if (calls == 2 && r.Method != http.MethodGet) || (calls == 3 && r.Method != http.MethodPatch) {
						t.Error("unexpected profile method")
					}
					_, _ = w.Write([]byte(nullable))
				}
			case "/api/v1/auth/me/permissions":
				_, _ = w.Write([]byte(`{"applicationId":"app-1","organizationId":null,"roles":["reader"],"permissions":["orders:read","orders:*"]}`))
			default:
				t.Errorf("unexpected endpoint %s", r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)
		client, err := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "client-1", ClientSecret: "fixture-secret"})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		profile, err := client.GetMe(ctx, "access-token")
		if err != nil {
			t.Fatal(err)
		}
		if profile.UserID != "user-1" || profile.ApplicationID != "app-1" || profile.GlobalIdentityID == nil || *profile.GlobalIdentityID != "identity-1" || profile.Email == nil || *profile.Email != "user@example.com" || !profile.EmailVerified || profile.Username == nil || *profile.Username != "alice" || profile.DisplayName == nil || *profile.DisplayName != "Alice" || profile.AvatarURL == nil || *profile.AvatarURL != "https://example.com/avatar.png" || profile.Status != "ACTIVE" || profile.CreatedAt != "2026-10-30T00:00:00Z" || profile.UpdatedAt != "2026-10-30T01:00:00Z" || profile.CurrentOrganization == nil || profile.CurrentOrganization.OrganizationID != "org-1" {
			t.Fatalf("bad canonical profile: %+v", profile)
		}
		for _, fetch := range []func() (*iam.UserProfile, error){
			func() (*iam.UserProfile, error) { return client.GetAccountProfile(ctx, "access-token") },
			func() (*iam.UserProfile, error) {
				return client.UpdateAccountProfile(ctx, "access-token", iam.AccountUpdateProfileRequest{DisplayName: "Alice"})
			},
		} {
			p, err := fetch()
			if err != nil {
				t.Fatal(err)
			}
			if p.UserID != "user-1" || p.GlobalIdentityID != nil || p.Email != nil || p.EmailVerified || p.Username != nil || p.DisplayName != nil || p.AvatarURL != nil || p.CurrentOrganization != nil {
				t.Fatalf("null projections masked: %+v", p)
			}
		}
		summary, err := client.GetAccountPermissionSummary(ctx, "access-token", "")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(summary.Roles, []string{"reader"}) || !reflect.DeepEqual(summary.Permissions, []string{"orders:read", "orders:*"}) || calls != 4 {
			t.Fatalf("bad independent permissions: %+v; calls=%d", summary, calls)
		}
	})
}
