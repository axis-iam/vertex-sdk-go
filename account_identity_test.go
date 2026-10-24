package iam_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
)

func TestIdentityProfileNullableAndStrictWrite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/me/profile" || r.Header.Get("Authorization") != "Bearer user-token" {
			t.Errorf("unexpected route/context: %s", r.URL.Path)
		}
		if r.Method == http.MethodPatch {
			data, _ := io.ReadAll(r.Body)
			var body map[string]string
			if err := json.Unmarshal(data, &body); err != nil {
				t.Error(err)
			}
			if len(body) != 1 || body["displayName"] != "Display" {
				t.Errorf("unexpected profile payload: %s", data)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"userId":"u1","applicationId":"app","email":null,"username":null,"emailVerified":false}`)
	}))
	defer server.Close()
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "client", ClientSecret: "test"})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := client.UpdateAccountProfile(context.Background(), "user-token", iam.AccountUpdateProfileRequest{DisplayName: "Display"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Email != nil || profile.Username != nil || profile.EmailVerified {
		t.Fatalf("nullable projections were masked: %#v", profile)
	}
}
