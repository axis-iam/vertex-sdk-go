package iam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAccountSecurityManagement(t *testing.T) {
	raw, err := os.ReadFile("testdata/account-security-management.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string][]json.RawMessage
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	makeClient := func(wire json.RawMessage) *Client {
		c, err := NewClient(&SDKConfig{Endpoint: "https://iam.example.test", ClientID: "client", ClientSecret: "fixture-secret"})
		if err != nil {
			t.Fatal(err)
		}
		c.SetHTTPClient(&http.Client{Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Authorization") != "Bearer current-user" {
				t.Error("missing explicit bearer")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(wire))), Request: r}, nil
		})})
		return c
	}
	t.Run("provider-target-nullable-additive", func(t *testing.T) {
		for _, wire := range vectors["validOperations"] {
			out, err := makeClient(wire).GetIdentityOperation(context.Background(), "current-user", securityFixtureID)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(wire, &fields)
			var expected *ProviderTarget
			_ = json.Unmarshal(fields["providerTarget"], &expected)
			if !reflect.DeepEqual(out.ProviderTarget, expected) {
				t.Fatal("target mismatch")
			}
		}
	})
	t.Run("provider-target-invalid-known-fields", func(t *testing.T) {
		for _, wire := range vectors["invalidOperations"] {
			_, err := makeClient(wire).GetIdentityOperation(context.Background(), "current-user", securityFixtureID)
			var protocol *AccountSecurityProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		}
	})
	t.Run("authenticated-management-snapshot", func(t *testing.T) {
		for _, wire := range vectors["validSnapshots"] {
			out, err := makeClient(wire).ListAccountIdentifiers(context.Background(), "current-user")
			if err != nil {
				t.Fatal(err)
			}
			if out.Management == nil {
				for _, i := range out.Items {
					if i.Capabilities != nil {
						t.Fatal("nullable capability synthesized")
					}
				}
				continue
			}
			if len(out.Management.Add) != 3 || len(out.Management.ProofOptions) != 4 || !out.Management.Add[IdentifierKindEmail].Allowed {
				t.Fatal("management shape")
			}
			actions := out.Items[0].Capabilities
			if len(actions) != 5 || !actions[IdentifierActionRemove].Allowed || len(actions[IdentifierActionRemove].ReplacementPrimaryIDs) != 1 {
				t.Fatal("eligible replacement/old identifier unavailable")
			}
			if got := actions[IdentifierActionTransfer].UnavailableReasons; len(got) != 1 || got[0] != IdentifierDenialIdentifierRangeRejected {
				t.Fatal("range denial missing")
			}
		}
	})
	t.Run("management-invalid-known-fields", func(t *testing.T) {
		for _, wire := range vectors["invalidSnapshots"] {
			_, err := makeClient(wire).ListAccountIdentifiers(context.Background(), "current-user")
			var protocol *AccountSecurityProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		}
	})
	t.Run("adapter-callback-replay-and-committed", func(t *testing.T) {
		count := 0
		c := makeClient(vectors["validOperations"][0])
		c.SetHTTPClient(&http.Client{Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
			count++
			index := 0
			if count == 3 {
				index = 1
			}
			if count == 1 && !strings.HasSuffix(r.URL.Path, "/provider-callback") {
				t.Error("callback path")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(vectors["validOperations"][index]))), Request: r}, nil
		})})
		first, err := c.CompleteIdentityProviderAuthorization(context.Background(), "current-user", securityFixtureID, ProviderExchange{AuthorizationID: securityFixtureID, CodeVerifier: strings.Repeat("v", 43)})
		if err != nil {
			t.Fatal(err)
		}
		replay, err := c.GetIdentityOperation(context.Background(), "current-user", securityFixtureID)
		if err != nil {
			t.Fatal(err)
		}
		committed, err := c.GetIdentityOperation(context.Background(), "current-user", securityFixtureID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 3 || !reflect.DeepEqual(first.ProviderTarget, replay.ProviderTarget) || !reflect.DeepEqual(first.ProviderTarget, committed.ProviderTarget) {
			t.Fatal("unstable target or hidden orchestration")
		}
	})
	t.Run("compatible-fields-but-no-sensitive-status-redelivery", func(t *testing.T) {
		for _, wire := range vectors["invalidMfaStatus"] {
			_, err := makeClient(wire).GetMFAOperation(context.Background(), "current-user", securityFixtureID)
			var protocol *AccountSecurityProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		}
		out, err := makeClient(vectors["validExtendedMfa"][0]).GetMFACapabilities(context.Background(), "current-user")
		if err != nil || out.LoginMethodVersion != 4 {
			t.Fatalf("incompatible future field: %v", err)
		}
	})

}
