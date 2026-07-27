package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	iam "github.com/axis-iam/vertex-sdk-go"
)

type compatibilityRoundTripper struct {
	calls int
	fn    func(call int) (*http.Response, error)
}

func (r *compatibilityRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return r.fn(r.calls)
}

func compatibilityResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type compatibilityFixture struct {
	Snapshot struct {
		Valid     json.RawMessage `json:"valid"`
		RawReject []struct {
			Name string `json:"name"`
			Body string `json:"body"`
		} `json:"rawReject"`
		Reject []struct {
			Name string          `json:"name"`
			Body json.RawMessage `json:"body"`
		} `json:"reject"`
	} `json:"snapshot"`
	Resolve struct {
		Valid  json.RawMessage `json:"valid"`
		Reject []struct {
			Name string          `json:"name"`
			Body json.RawMessage `json:"body"`
		} `json:"reject"`
	} `json:"resolve"`
}

func TestPermissionCompatibilityExhaustsSharedRejectVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "permission-compatibility-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture compatibilityFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	t.Run("snapshot/valid-wildcard-grants", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(fixture.Snapshot.Valid) }))
		defer server.Close()
		client, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
		result, err := client.ListPermissions(context.Background(), "orders-service")
		if err != nil || len(result.Permissions) != 3 {
			t.Fatalf("valid shared snapshot rejected: result=%+v err=%v", result, err)
		}
	})
	t.Run("resolve/valid-wildcard-grants", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(fixture.Resolve.Valid) }))
		defer server.Close()
		client, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
		result, err := client.ResolvePermissions(context.Background(), "orders-service", []string{"admin"})
		if err != nil || len(result.Permissions) != 3 {
			t.Fatalf("valid shared resolve rejected: result=%+v err=%v", result, err)
		}
	})
	for _, vector := range fixture.Snapshot.Reject {
		t.Run("snapshot/"+vector.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(vector.Body) }))
			defer server.Close()
			client, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
			if _, err := client.ListPermissions(context.Background(), "orders-service"); err == nil {
				t.Fatal("invalid shared snapshot accepted")
			}
		})
	}
	for _, vector := range fixture.Snapshot.RawReject {
		t.Run("snapshot/raw/"+vector.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, vector.Body) }))
			defer server.Close()
			client, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
			if _, err := client.ListPermissions(context.Background(), "orders-service"); err == nil {
				t.Fatal("invalid shared raw snapshot accepted")
			}
		})
	}
	for _, vector := range fixture.Resolve.Reject {
		t.Run("resolve/"+vector.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(vector.Body) }))
			defer server.Close()
			client, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
			if _, err := client.ResolvePermissions(context.Background(), "orders-service", []string{"admin"}); err == nil {
				t.Fatal("invalid shared resolve accepted")
			}
		})
	}
}

func TestStrictPermissionSnapshotRetryClassification(t *testing.T) {
	valid := `{"applicationId":"123e4567-e89b-42d3-a456-426614174000","clientId":"orders-service","roles":[]}`
	tests := []struct {
		name      string
		ctx       func() (context.Context, context.CancelFunc)
		response  func(int) (*http.Response, error)
		wantCalls int
		wantError bool
	}{
		{"transport retries", backgroundContext, func(call int) (*http.Response, error) {
			if call < 3 {
				return nil, errors.New("transport unavailable")
			}
			return compatibilityResponse(200, valid), nil
		}, 3, false},
		{"server error retries", backgroundContext, func(call int) (*http.Response, error) {
			if call < 3 {
				return compatibilityResponse(500, `{}`), nil
			}
			return compatibilityResponse(200, valid), nil
		}, 3, false},
		{"rate limit retries", backgroundContext, func(call int) (*http.Response, error) {
			if call < 3 {
				return compatibilityResponse(429, `{}`), nil
			}
			return compatibilityResponse(200, valid), nil
		}, 3, false},
		{"terminal client error", backgroundContext, func(int) (*http.Response, error) { return compatibilityResponse(403, `{}`), nil }, 1, true},
		{"strict contract error", backgroundContext, func(int) (*http.Response, error) {
			return compatibilityResponse(200, `{"applicationId":"bad","clientId":"orders-service","roles":[]}`), nil
		}, 1, true},
		{"malformed JSON", backgroundContext, func(int) (*http.Response, error) {
			return compatibilityResponse(200, `{"applicationId":`), nil
		}, 1, true},
		{"canceled context", canceledContext, func(int) (*http.Response, error) { return compatibilityResponse(200, valid), nil }, 0, true},
		{"expired deadline", expiredContext, func(int) (*http.Response, error) { return compatibilityResponse(200, valid), nil }, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()
			transport := &compatibilityRoundTripper{fn: test.response}
			client, err := iam.NewClient(&iam.SDKConfig{Endpoint: "https://iam.test", ClientID: "orders-service", ClientSecret: "secret", MaxRetries: 2})
			if err != nil {
				t.Fatal(err)
			}
			client.SetHTTPClient(&http.Client{Transport: transport})
			_, err = client.ListPermissions(ctx, "orders-service")
			if (err != nil) != test.wantError || transport.calls != test.wantCalls {
				t.Fatalf("error=%v calls=%d, wantError=%v wantCalls=%d", err, transport.calls, test.wantError, test.wantCalls)
			}
		})
	}
}

func backgroundContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
func canceledContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, func() {}
}
func expiredContext() (context.Context, context.CancelFunc) {
	return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
}

func TestPermissionSnapshotStrictNestedRoles(t *testing.T) {
	tests := []struct {
		name, body string
		valid      bool
	}{
		{"nested wildcard grants", `{"applicationId":"123e4567-e89b-42d3-a456-426614174000","clientId":"orders-service","roles":[{"key":"admin","name":"Admin","permissions":["orders:read","orders:*","*:*"]}]}`, true},
		{"top-level fallback", `{"applicationId":"app","clientId":"orders-service","permissions":[]}`, false},
		{"unknown field", `{"applicationId":"app","clientId":"orders-service","roles":[],"fallback":true}`, false},
		{"duplicate role", `{"applicationId":"app","clientId":"orders-service","roles":[{"key":"admin","name":"Admin","permissions":[]},{"key":"admin","name":"Other","permissions":[]}]}`, false},
		{"duplicate permission", `{"applicationId":"app","clientId":"orders-service","roles":[{"key":"admin","name":"Admin","permissions":["orders:read","orders:read"]}]}`, false},
		{"malformed permission", `{"applicationId":"app","clientId":"orders-service","roles":[{"key":"admin","name":"Admin","permissions":["orders"]}]}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(test.body)) }))
			defer server.Close()
			client, err := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.ListPermissions(context.Background(), "orders-service")
			if test.valid && (err != nil || len(result.Permissions) != 3) {
				t.Fatalf("valid snapshot rejected: result=%+v err=%v", result, err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestPermissionCompatibilityRealBackendE2E(t *testing.T) {
	if os.Getenv("IAM_PERMISSION_COMPATIBILITY_E2E") != "1" {
		t.Skip("live fixture disabled")
	}
	clientID := os.Getenv("IAM_COMPAT_CLIENT_ID")
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: os.Getenv("IAM_COMPAT_ISSUER"), ClientID: clientID, ClientSecret: os.Getenv("IAM_COMPAT_CLIENT_SECRET")})
	if err != nil {
		t.Fatal(err)
	}
	zeroRole, err := client.ResolvePermissions(context.Background(), clientID, nil)
	if err != nil || len(zeroRole.Permissions) != 0 {
		t.Fatalf("zero-role resolve: result=%+v err=%v", zeroRole, err)
	}
	snapshot, err := client.ListPermissions(context.Background(), clientID)
	if err != nil || len(snapshot.Permissions) != 3 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	keys := map[string]bool{}
	for _, permission := range snapshot.Permissions {
		keys[permission.Resource+":"+permission.Action] = true
	}
	if !keys["orders:write"] || !keys["orders:*"] || !keys["*:*"] {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	resolved, err := client.ResolvePermissions(context.Background(), clientID, []string{"m7d_reader"})
	if err != nil || len(resolved.Permissions) != 3 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
}

func TestResolvePermissionsZeroRolesHasNoNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client, err := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "orders-service", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ResolvePermissions(context.Background(), "orders-service", nil)
	if err != nil || len(result.Permissions) != 0 || requests != 0 {
		t.Fatalf("zero-role result=%+v err=%v requests=%d", result, err, requests)
	}
}
