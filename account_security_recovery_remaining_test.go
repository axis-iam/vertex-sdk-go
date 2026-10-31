package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
)

func TestAccountSecurityRecoveryRemaining(t *testing.T) {
	const root = "/api/v1/auth/mfa"
	const id = "00000000-0000-0000-0000-000000000002"
	op := func(committed bool) map[string]any {
		state := "READY"
		var result any
		if committed {
			state = "COMMITTED"
			result = map[string]any{"completedAt": "2026-10-31T00:00:00Z", "finalLoginMethodVersion": 5, "sessionImpact": "CURRENT_SESSION_RETAINED", "recoveryCount": 5}
		}
		return map[string]any{"id": id, "type": "RECOVERY_CODES_GENERATE", "state": state, "createdAt": "2026-10-31T00:00:00Z", "expiresAt": "2026-10-31T00:10:00Z", "expectedLoginMethodVersion": 4, "proofRequirement": "SESSION", "proofOptions": []any{}, "proofSatisfied": true, "result": result}
	}
	t.Run("current-owner-and-generation-consumption", func(t *testing.T) {
		var remaining, complete, verify atomic.Int64
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/.well-known/openid-configuration" {
				io.WriteString(w, `{"jwks_uri":"`+server.URL+`/oauth2/jwks"}`)
				return
			}
			owner := r.Header.Get("Authorization")
			if owner != "Bearer owner-a" && owner != "Bearer owner-b" {
				w.WriteHeader(401)
				io.WriteString(w, `{"status":401,"error":"UNAUTHORIZED","message":"private-diagnostic"}`)
				return
			}
			switch r.URL.Path {
			case root + "/recovery-codes/remaining":
				if r.Method != "GET" || r.URL.RawQuery != "" {
					t.Error("wrong live count request")
				}
				count := remaining.Load()
				if owner == "Bearer owner-b" {
					count = 2
				}
				json.NewEncoder(w).Encode(map[string]any{"remaining": count, "future": true})
			case root + "/operations":
				if r.Header.Get("Idempotency-Key") != "retained-key" {
					t.Error("missing create key")
				}
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(op(false))
			case root + "/operations/" + id + "/complete":
				complete.Add(1)
				remaining.Store(5)
				json.NewEncoder(w).Encode(map[string]any{"operation": op(true), "delivery": "AVAILABLE", "recoveryCodes": map[string]any{"codes": []string{"fixture-0", "fixture-1", "fixture-2", "fixture-3", "fixture-4"}, "count": 5}})
			case root + "/recovery-codes/verify":
				verify.Add(1)
				remaining.Add(-1)
				io.WriteString(w, `{"verified":true}`)
			default:
				w.WriteHeader(404)
			}
		}))
		defer server.Close()
		cfg := func() *iam.SDKConfig {
			return &iam.SDKConfig{Endpoint: server.URL, ClientID: "client", ClientSecret: "fixture-secret"}
		}
		c, err := iam.NewClient(cfg())
		if err != nil {
			t.Fatal(err)
		}
		defer c.HTTP().CloseIdleConnections()
		sdk, err := iam.New(cfg())
		if err != nil {
			t.Fatal(err)
		}
		defer sdk.Client().HTTP().CloseIdleConnections()
		first, err := c.GetRecoveryCodesRemaining(context.Background(), "owner-a")
		if err != nil || first.Remaining != 0 {
			t.Fatalf("initial: %v", err)
		}
		created, err := c.CreateMFAOperation(context.Background(), "owner-a", iam.MFAOperationCreate{Type: iam.MFAOperationTypeRecoveryCodesGenerate, ExpectedLoginMethodVersion: 4}, "retained-key")
		if err != nil {
			t.Fatal(err)
		}
		generated, err := c.CompleteMFAOperation(context.Background(), "owner-a", created.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		after, err := sdk.GetRecoveryCodesRemaining(context.Background(), "owner-a")
		if err != nil || after.Remaining != 5 {
			t.Fatalf("generated count: %v", err)
		}
		req, _ := http.NewRequest("POST", server.URL+root+"/recovery-codes/verify", strings.NewReader(`{"code":"fixture-0"}`))
		req.Header.Set("Authorization", "Bearer owner-a")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		consumed, err := sdk.GetRecoveryCodesRemaining(context.Background(), "owner-a")
		if err != nil || consumed.Remaining != 4 || consumed.Remaining == *generated.Operation.Result.RecoveryCount {
			t.Fatalf("not live count: %v", err)
		}
		other, err := c.GetRecoveryCodesRemaining(context.Background(), "owner-b")
		if err != nil || other.Remaining != 2 {
			t.Fatalf("owner isolation: %v", err)
		}
		_, err = c.GetRecoveryCodesRemaining(context.Background(), "bad-owner")
		var api *iam.AccountSecurityError
		if !errors.As(err, &api) || api.Status != 401 || strings.Contains(err.Error(), "private-diagnostic") {
			t.Fatalf("typed error: %v", err)
		}
		if complete.Load() != 1 || verify.Load() != 1 {
			t.Fatal("implicit mutation replay")
		}
	})
	t.Run("known-fields-errors-and-explicit-bearer", func(t *testing.T) {
		for _, body := range []string{`{}`, `{"remaining":null}`, `{"remaining":true}`, `{"remaining":-1}`, `{"remaining":1.5}`, `{"remaining":9223372036854775808}`, `{"remaining":1,"remaining":2}`, `{"remaining":1,"codes":["not-a-live-code"]}`} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			c, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "client", ClientSecret: "fixture-secret"})
			_, err := c.GetRecoveryCodesRemaining(context.Background(), "owner-a")
			var protocol *iam.AccountSecurityProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("invalid count accepted: %v", err)
			}
			c.HTTP().CloseIdleConnections()
			server.Close()
		}
		var received atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received.Add(1)
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
			io.WriteString(w, `{"status":429,"error":"OPERATION_PROOF_RATE_LIMITED"}`)
		}))
		defer server.Close()
		c, _ := iam.NewClient(&iam.SDKConfig{Endpoint: server.URL, ClientID: "client", ClientSecret: "fixture-secret"})
		defer c.HTTP().CloseIdleConnections()
		if _, err := c.GetRecoveryCodesRemaining(context.Background(), ""); err == nil || received.Load() != 0 {
			t.Fatal("empty bearer accepted")
		}
		_, err := c.GetRecoveryCodesRemaining(context.Background(), "owner-a")
		var api *iam.AccountSecurityError
		if !errors.As(err, &api) || api.RetryAfterSeconds == nil || *api.RetryAfterSeconds != 2 || received.Load() != 1 {
			t.Fatalf("rate metadata/retry: %v", err)
		}
	})
}
