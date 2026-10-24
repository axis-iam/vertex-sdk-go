package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
)

func currentUserFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/current-user.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestCurrentUserNullableAndStrictContext(t *testing.T) {
	data := currentUserFixture(t)
	view, err := iam.ParseCurrentUser(data)
	if err != nil || view.Email != nil || !view.AuthenticationContext.WorkspaceSelectionRequired || view.AuthenticationContext.AuthTime.Format("2006-01-02T15:04:05Z07:00") != "2026-10-20T01:02:03Z" {
		t.Fatalf("invalid view: %v", err)
	}
	for _, key := range []string{"applicationId", "clientId", "sessionId", "subjectType", "workspaceId", "authTime", "impersonation", "authenticationMethods"} {
		t.Run(key, func(t *testing.T) {
			var v map[string]json.RawMessage
			_ = json.Unmarshal(data, &v)
			var c map[string]json.RawMessage
			_ = json.Unmarshal(v["authenticationContext"], &c)
			delete(c, key)
			v["authenticationContext"], _ = json.Marshal(c)
			bad, _ := json.Marshal(v)
			if _, err := iam.ParseCurrentUser(bad); err == nil {
				t.Fatal("missing context accepted")
			}
		})
	}
	for _, patch := range []string{`"authTime":"yesterday"`, `"impersonation":{"actorId":"actor"}`, `"workspaceId":"ws"`, `"organizationSlug":"unbound"`, `"subjectType":"MACHINE"`} {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(data, &v)
		var c map[string]json.RawMessage
		_ = json.Unmarshal(v["authenticationContext"], &c)
		var p map[string]json.RawMessage
		_ = json.Unmarshal([]byte("{"+patch+"}"), &p)
		for k, value := range p {
			c[k] = value
		}
		v["authenticationContext"], _ = json.Marshal(c)
		bad, _ := json.Marshal(v)
		if _, err := iam.ParseCurrentUser(bad); err == nil {
			t.Fatalf("accepted %s", patch)
		}
	}
}
func TestCurrentUserHTTPBearerAndFailure(t *testing.T) {
	data := currentUserFixture(t)
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/me" || r.Header.Get("Authorization") != "Bearer contract-fixture" || r.Header.Get("X-IAM-Client-Id") != "" {
			t.Error("invalid safe-view request")
		}
		w.WriteHeader(status)
		if status == 200 {
			_, _ = w.Write(data)
		} else {
			_, _ = w.Write([]byte(`{"message":"private"}`))
		}
	}))
	defer srv.Close()
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: srv.URL, ClientID: "test-client", ClientSecret: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if view, err := client.GetCurrentUser(context.Background(), "contract-fixture"); err != nil || view.Email != nil {
		t.Fatalf("read failed: %v", err)
	}
	for _, code := range []int{401, 403, 503} {
		status = code
		_, err := client.GetCurrentUser(context.Background(), "contract-fixture")
		var api *iam.CurrentUserError
		if !errors.As(err, &api) || api.Status != code || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe failure: %v", err)
		}
	}
}

func TestCurrentUserCancellation(t *testing.T) {
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: "http://127.0.0.1:1", ClientID: "fixture", ClientSecret: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.GetCurrentUser(ctx, "contract-fixture")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
