package iam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const securityFixtureID = "00000000-0000-0000-0000-000000000001"

func securityPtr(s string) *string { return &s }

type securityContractFixture struct {
	Samples map[string]json.RawMessage `json:"samples"`
	Cases   []struct {
		Name     string          `json:"name"`
		Method   string          `json:"method"`
		Path     string          `json:"path"`
		Body     json.RawMessage `json:"body"`
		Response json.RawMessage `json:"response"`
	} `json:"cases"`
}

func loadSecurityFixture(t *testing.T) securityContractFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/account-security-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var f securityContractFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}
func TestAccountSecurityOperations(t *testing.T) {
	fixture := loadSecurityFixture(t)
	calls := []func(*Client) error{
		func(c *Client) error {
			_, err := c.ListAccountIdentifiers(context.Background(), "Bearer current-user")
			return err
		},
		func(c *Client) error {
			_, err := c.ListAccountLoginMethods(context.Background(), "Bearer current-user")
			return err
		},
		func(c *Client) error {
			_, err := c.ListLinkableIdentityProviders(context.Background(), "Bearer current-user")
			return err
		},
		func(c *Client) error {
			_, err := c.CreateIdentityOperation(context.Background(), "Bearer current-user", IdentityOperationCreate{ExpectedLoginMethodVersion: 4, Payload: AddIdentity{Identifier: LoginIdentifier{Kind: IdentifierKindEmail, Value: "new@example.test"}}}, "retained-key")
			return err
		},
		func(c *Client) error {
			_, err := c.GetIdentityOperation(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.ListIdentityTransfers(context.Background(), "Bearer current-user")
			return err
		},
		func(c *Client) error {
			_, err := c.ReauthenticateIdentityOperation(context.Background(), "Bearer current-user", securityFixtureID, PasswordReauthentication{Password: "fixture-password"})
			return err
		},
		func(c *Client) error {
			_, err := c.ChallengeIdentityOperation(context.Background(), "Bearer current-user", securityFixtureID, TargetProofMethodEmailOTP)
			return err
		},
		func(c *Client) error {
			_, err := c.ChallengeIdentityCurrentAccount(context.Background(), "Bearer current-user", securityFixtureID, securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.CompleteIdentityOperation(context.Background(), "Bearer current-user", securityFixtureID, IdentityOperationComplete{Proofs: []IdentityTargetProof{}})
			return err
		},
		func(c *Client) error {
			_, err := c.CancelIdentityOperation(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.ConfirmIdentityTransfer(context.Background(), "Bearer current-user", securityFixtureID, TransferDecisionAccept)
			return err
		},
		func(c *Client) error {
			_, err := c.AuthorizeIdentityOperation(context.Background(), "Bearer current-user", securityFixtureID, IdentityProviderAuthorize{Purpose: AuthorizationPurposeCurrentAccount, MethodID: securityPtr("identity:linked"), RedirectURI: "https://app.example.test/callback", CodeChallenge: strings.Repeat("c", 43), CodeChallengeMethod: "S256"})
			return err
		},
		func(c *Client) error {
			_, err := c.CompleteIdentityProviderAuthorization(context.Background(), "Bearer current-user", securityFixtureID, ProviderExchange{AuthorizationID: securityFixtureID, CodeVerifier: strings.Repeat("v", 43)})
			return err
		},
		func(c *Client) error {
			_, err := c.GetMFACapabilities(context.Background(), "Bearer current-user")
			return err
		},
		func(c *Client) error {
			_, err := c.CreateMFAOperation(context.Background(), "Bearer current-user", MFAOperationCreate{Type: MFAOperationTypeTOTPEnroll, ExpectedLoginMethodVersion: 4}, "retained-key")
			return err
		},
		func(c *Client) error {
			_, err := c.GetMFAOperation(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.ReauthenticateMFAOperation(context.Background(), "Bearer current-user", securityFixtureID, PasswordReauthentication{Password: "fixture-password"})
			return err
		},
		func(c *Client) error {
			_, err := c.ChallengeMFAOperation(context.Background(), "Bearer current-user", securityFixtureID, securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.AuthorizeMFAOperation(context.Background(), "Bearer current-user", securityFixtureID, MFAProviderAuthorize{MethodID: "identity:linked", RedirectURI: "https://app.example.test/callback", CodeChallenge: strings.Repeat("c", 43), CodeChallengeMethod: "S256"})
			return err
		},
		func(c *Client) error {
			_, err := c.CompleteMFAProviderAuthorization(context.Background(), "Bearer current-user", securityFixtureID, ProviderExchange{AuthorizationID: securityFixtureID, CodeVerifier: strings.Repeat("v", 43)})
			return err
		},
		func(c *Client) error {
			_, err := c.BeginTOTPEnrollmentOperation(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.CompleteMFAOperation(context.Background(), "Bearer current-user", securityFixtureID, nil)
			return err
		},
		func(c *Client) error {
			_, err := c.CancelMFAOperation(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.StartIdentityOperationStepUp(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.VerifyIdentityOperationStepUp(context.Background(), "Bearer current-user", securityFixtureID, OperationStepUpVerify{ChallengeID: "scoped-challenge", Code: "123456"})
			return err
		},
		func(c *Client) error {
			_, err := c.StartIdentityOperationWebAuthn(context.Background(), "Bearer current-user", securityFixtureID, "scoped-challenge")
			return err
		},
		func(c *Client) error {
			_, err := c.VerifyIdentityOperationWebAuthn(context.Background(), "Bearer current-user", securityFixtureID, OperationWebAuthnVerify{ChallengeID: "scoped-challenge", RequestID: "scoped-request", Credential: "fixture-credential"})
			return err
		},
		func(c *Client) error {
			_, err := c.StartMFAOperationStepUp(context.Background(), "Bearer current-user", securityFixtureID)
			return err
		},
		func(c *Client) error {
			_, err := c.VerifyMFAOperationStepUp(context.Background(), "Bearer current-user", securityFixtureID, OperationStepUpVerify{ChallengeID: "scoped-challenge", Code: "123456"})
			return err
		},
		func(c *Client) error {
			_, err := c.StartMFAOperationWebAuthn(context.Background(), "Bearer current-user", securityFixtureID, "scoped-challenge")
			return err
		},
		func(c *Client) error {
			_, err := c.VerifyMFAOperationWebAuthn(context.Background(), "Bearer current-user", securityFixtureID, OperationWebAuthnVerify{ChallengeID: "scoped-challenge", RequestID: "scoped-request", Credential: "fixture-credential"})
			return err
		},
	}
	t.Run("public-operation-matrix", func(t *testing.T) {
		for i, call := range calls {
			expected := fixture.Cases[i]
			t.Run(expected.Name, func(t *testing.T) {
				count := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					count++
					if r.Method != expected.Method || r.URL.Path != expected.Path {
						t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
					}
					if r.Header.Get("Authorization") != "Bearer current-user" {
						t.Error("current-user authorization not preserved")
					}
					if strings.Contains(r.Header.Get("Authorization"), "configured-secret") {
						t.Error("machine secret used")
					}
					if strings.HasPrefix(expected.Name, "create_") && r.Header.Get("Idempotency-Key") != "retained-key" {
						t.Error("missing stable key")
					}
					raw, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					if string(expected.Body) != "null" {
						var want, got any
						_ = json.Unmarshal(expected.Body, &want)
						if err = json.Unmarshal(raw, &got); err != nil {
							t.Error(err)
						}
						wantRaw, _ := json.Marshal(want)
						gotRaw, _ := json.Marshal(got)
						if string(wantRaw) != string(gotRaw) {
							t.Errorf("body mismatch: %s != %s", gotRaw, wantRaw)
						}
					} else if len(raw) != 0 {
						t.Error("GET has body")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(expected.Response)
				}))
				defer server.Close()
				c, err := NewClient(&SDKConfig{Endpoint: server.URL, ClientID: "configured-client", ClientSecret: "configured-secret"})
				if err != nil {
					t.Fatal(err)
				}
				if err = call(c); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("unexpected replay count %d", count)
				}
			})
		}
	})

	t.Run("actual-sensitive-lifecycle", func(t *testing.T) {
		pending := string(fixture.Samples["MfaOperation"])
		var committed map[string]any
		_ = json.Unmarshal(fixture.Samples["MfaOperation"], &committed)
		committed["type"] = "RECOVERY_CODES_GENERATE"
		committed["state"] = "COMMITTED"
		committed["result"] = map[string]any{"completedAt": "2026-10-30T00:00:00Z", "finalLoginMethodVersion": 4, "sessionImpact": "UNCHANGED", "recoveryBatchId": securityFixtureID, "recoveryCount": 1}
		committedRaw, _ := json.Marshal(committed)
		cancelled := strings.Replace(pending, `"READY"`, `"CANCELLED"`, 1)
		replies := []string{
			string(fixture.Samples["TotpBeginResult"]),
			`{"operation":` + pending + `,"delivery":"ALREADY_DELIVERED","material":null}`,
			`{"operation":` + string(committedRaw) + `,"delivery":"AVAILABLE","recoveryCodes":{"codes":["fixture-code"],"count":1}}`,
			`{"operation":` + string(committedRaw) + `,"delivery":"ALREADY_DELIVERED","recoveryCodes":null}`,
			string(committedRaw), cancelled,
		}
		count := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, replies[0])
			replies = replies[1:]
		}))
		defer server.Close()
		c, _ := NewClient(&SDKConfig{Endpoint: server.URL, ClientID: "client", ClientSecret: "secret"})
		first, err := c.BeginTOTPEnrollmentOperation(context.Background(), "token", securityFixtureID)
		if err != nil || first.Material == nil {
			t.Fatalf("first material %v", err)
		}
		again, err := c.BeginTOTPEnrollmentOperation(context.Background(), "token", securityFixtureID)
		if err != nil || again.Material != nil || again.Delivery != SensitiveDeliveryAlreadyDelivered {
			t.Fatalf("repeated material %v", err)
		}
		codes, err := c.CompleteMFAOperation(context.Background(), "token", securityFixtureID, nil)
		if err != nil || codes.RecoveryCodes == nil || codes.RecoveryCodes.Count != 1 {
			t.Fatalf("first codes %v", err)
		}
		replay, err := c.CompleteMFAOperation(context.Background(), "token", securityFixtureID, nil)
		if err != nil || replay.RecoveryCodes != nil {
			t.Fatalf("replayed codes %v", err)
		}
		recovered, err := c.GetMFAOperation(context.Background(), "new-session-same-owner", securityFixtureID)
		if err != nil || recovered.Result == nil || recovered.Result.SessionImpact != SessionImpactUnchanged {
			t.Fatalf("status recovery %v", err)
		}
		cancel, err := c.CancelMFAOperation(context.Background(), "token", securityFixtureID)
		if err != nil || cancel.State != MFAOperationStateCancelled {
			t.Fatalf("cancellation %v", err)
		}
		if count != 6 || len(replies) != 0 {
			t.Fatal("hidden requests")
		}
	})
	t.Run("payload-variants-and-counterpart-null", func(t *testing.T) {
		payloads := []IdentityPayload{AddIdentity{Identifier: LoginIdentifier{Kind: IdentifierKindEmail, Value: "new@example.test"}}, VerifyIdentity{IdentifierID: securityFixtureID}, SetPrimaryIdentity{IdentifierID: securityFixtureID}, RemoveIdentity{IdentifierID: securityFixtureID}, ReplaceIdentity{IdentifierID: securityFixtureID, Replacement: LoginIdentifier{Kind: IdentifierKindUsername, Value: "new-name"}, RemoveOld: false}, LinkIdentity{ProviderID: securityFixtureID}, UnlinkIdentity{MethodID: "identity:linked"}, TransferIdentity{IdentifierID: securityFixtureID, TargetUserID: securityFixtureID}}
		kinds := []string{"ADD", "VERIFY", "SET_PRIMARY", "REMOVE", "REPLACE", "LINK", "UNLINK", "TRANSFER"}
		for i, p := range payloads {
			r := IdentityOperationCreate{ExpectedLoginMethodVersion: 4, Payload: p}
			if err := validateSecurityRequest(r); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			_ = json.Unmarshal(raw, &body)
			var kind string
			_ = json.Unmarshal(body["type"], &kind)
			if kind != kinds[i] || len(body) != 3 || len(body["payload"]) == 0 {
				t.Fatalf("bad payload %s", raw)
			}
		}
		c, _ := NewClient(&SDKConfig{Endpoint: "https://iam.example.test", ClientID: "client", ClientSecret: "secret"})
		c.SetHTTPClient(&http.Client{Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"` + securityFixtureID + `","type":"TRANSFER","state":"COMMITTED","expiresAt":"2026-10-30T00:10:00Z","requiredProofs":[],"result":null,"completion":null,"proofOptions":[]}`)), Request: r}, nil
		})})
		o, err := c.GetIdentityOperation(context.Background(), "counterpart-user", securityFixtureID)
		if err != nil || o.Completion != nil || o.Result != nil {
			t.Fatalf("redacted participant metadata %v", err)
		}
	})
	t.Run("strict-auth-and-requests", func(t *testing.T) {
		c, err := NewClient(&SDKConfig{Endpoint: "https://iam.example.test", ClientID: "client", ClientSecret: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.GetMFACapabilities(context.Background(), ""); err == nil {
			t.Fatal("blank bearer accepted")
		}
		if _, err = c.GetMFAOperation(context.Background(), "token", "../escape"); err == nil {
			t.Fatal("path injection accepted")
		}
		if _, err = c.CreateMFAOperation(context.Background(), "token", MFAOperationCreate{Type: MFAOperationTypeTOTPEnroll}, ""); err == nil {
			t.Fatal("blank key accepted")
		}
		if _, err = c.CompleteMFAOperation(context.Background(), "token", securityFixtureID, securityPtr("")); err == nil {
			t.Fatal("empty code accepted")
		}
	})
	t.Run("strict-response-and-errors", func(t *testing.T) {
		for _, body := range []string{"{}", "null", "{} {}", `{"id":1,"id":2}`} {
			c, _ := NewClient(&SDKConfig{Endpoint: "https://iam.example.test", ClientID: "client", ClientSecret: "secret"})
			c.SetHTTPClient(&http.Client{Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})})
			_, err := c.GetMFACapabilities(context.Background(), "token")
			var protocol *AccountSecurityProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		}
		for _, delay := range []string{"60", "-1", "1.2", "99999999999999"} {
			c, _ := NewClient(&SDKConfig{Endpoint: "https://iam.example.test", ClientID: "client", ClientSecret: "secret"})
			count := 0
			c.SetHTTPClient(&http.Client{Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
				count++
				return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{delay}}, Body: io.NopCloser(strings.NewReader(`{"status":429,"error":"OPERATION_PROOF_RATE_LIMITED","message":"provider-secret"}`)), Request: r}, nil
			})})
			_, err := c.CompleteMFAOperation(context.Background(), "token", securityFixtureID, nil)
			var rejected *AccountSecurityError
			if !errors.As(err, &rejected) || rejected.Code != "OPERATION_PROOF_RATE_LIMITED" || rejected.Status != 429 {
				t.Fatalf("bad typed error %v", err)
			}
			if (delay == "60") != (rejected.RetryAfterSeconds != nil) {
				t.Fatal("bad retry delay")
			}
			if strings.Contains(err.Error(), "provider-secret") || count != 1 {
				t.Fatal("sensitive/replayed error")
			}
		}
	})
	t.Run("unknown-result-cancellation-and-no-replay", func(t *testing.T) {
		c, _ := NewClient(&SDKConfig{Endpoint: "https://iam.example.test", ClientID: "client", ClientSecret: "secret"})
		count := 0
		c.SetHTTPClient(&http.Client{Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
			count++
			if r.Method == "POST" {
				return nil, io.ErrUnexpectedEOF
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(fixture.Samples["MfaOperation"]))), Request: r}, nil
		})})
		_, err := c.CompleteMFAOperation(context.Background(), "token", securityFixtureID, nil)
		var unknown *AccountSecurityTransportError
		if !errors.As(err, &unknown) || !unknown.OutcomeUnknown {
			t.Fatalf("expected unknown result %v", err)
		}
		if _, err = c.GetMFAOperation(context.Background(), "new-session-same-owner", securityFixtureID); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatal("mutation replayed")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = c.GetMFACapabilities(ctx, "token"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost %v", err)
		}
		if count != 2 {
			t.Fatal("cancelled request sent")
		}
	})
	t.Run("sensitive-delivery-redaction", func(t *testing.T) {
		var first TOTPBeginResult
		if err := decodeStrictJSON(fixture.Samples["TotpBeginResult"], &first); err != nil {
			t.Fatal(err)
		}
		if first.Material == nil || first.Material.Secret != "fixture-material" || strings.Contains(first.String(), "fixture-material") {
			t.Fatal("bad first material delivery")
		}
		replay := `{"operation":` + string(fixture.Samples["MfaOperation"]) + `,"delivery":"ALREADY_DELIVERED","material":null}`
		var second TOTPBeginResult
		if err := decodeStrictJSON([]byte(replay), &second); err != nil {
			t.Fatal(err)
		}
		if second.Material != nil || second.Delivery != SensitiveDeliveryAlreadyDelivered {
			t.Fatal("material replay")
		}
		if strings.Contains((RecoveryCodes{Codes: []string{"fixture-code"}, Count: 1}).String(), "fixture-code") {
			t.Fatal("recovery diagnostic leak")
		}
	})
}

type securityRoundTrip func(*http.Request) (*http.Response, error)

func (f securityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
