package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testManifest() PermissionManifest {
	return PermissionManifest{ManifestID: "orders-api", Revision: "git:abc123", Permissions: []PermissionManifestDeclaration{{Resource: "posts", Action: "read", Name: "Read posts"}}}
}

func TestPreparePermissionManifestMatchesBackendFrozenVector(t *testing.T) {
	prepared, err := PreparePermissionManifest(testManifest(), PermissionManifestValidate)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Fingerprint != "bd2036720114f62abecb2850b61c165763a9cf1ee3736eab2bd59b9646aae9b5" {
		t.Fatalf("fingerprint = %s", prepared.Fingerprint)
	}
}

func TestPermissionManifestConsumesSharedVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name, Fingerprint string
			Permissions       []PermissionManifestDeclaration
		}
		LocalReject, ResponseReject []string
		Retry                       struct {
			Statuses, TerminalStatuses, ValidRetryAfterSeconds []int
			InvalidRetryAfter                                  []string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		prepared, err := PreparePermissionManifest(PermissionManifest{ManifestID: "vector", Revision: "1", Permissions: vector.Permissions}, PermissionManifestValidate)
		if err != nil || prepared.Fingerprint != vector.Fingerprint {
			t.Fatalf("vector %s: %v %s", vector.Name, err, prepared.Fingerprint)
		}
	}
	for _, name := range fixture.LocalReject {
		assertSharedLocalReject(t, name)
	}
}

func TestPermissionManifestConsumesRetryAfterVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Retry struct {
			ValidRetryAfterSeconds []int
			InvalidRetryAfter      []string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, seconds := range fixture.Retry.ValidRetryAfterSeconds {
		value := fmt.Sprint(seconds)
		if _, ok := parseManifestRetryAfter(value); !ok {
			t.Fatalf("valid Retry-After rejected: %s", value)
		}
	}
	for _, value := range fixture.Retry.InvalidRetryAfter {
		if _, ok := parseManifestRetryAfter(value); ok {
			t.Fatalf("invalid Retry-After accepted: %s", value)
		}
	}
}

func TestPermissionManifestConsumesSharedRetryAndTerminalStatuses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Retry struct {
			Statuses, TerminalStatuses []int
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, status := range fixture.Retry.Statuses {
		assertManifestStatusRequestCount(t, status, 3)
	}
	for _, status := range fixture.Retry.TerminalStatuses {
		assertManifestStatusRequestCount(t, status, 2)
	}
}

func assertManifestStatusRequestCount(t *testing.T, status, expected int) {
	t.Helper()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"safe","token_type":"Bearer","expires_in":60,"scope":"permissions:sync"}`))
			return
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"status":%d,"error":"STATUS_%d","message":"failed","timestamp":"2026-07-17T00:00:00Z"}`, status, status)
	}))
	defer server.Close()
	client, err := NewPermissionManifestClient(PermissionManifestClientConfig{IssuerEndpoint: server.URL, PortalAPIEndpoint: server.URL, ClientID: "id", ClientSecret: "secret", MaxRetries: 2, MaxRetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ValidatePermissionManifest(context.Background(), testManifest()); err == nil {
		t.Fatalf("status %d was accepted", status)
	}
	if calls != expected {
		t.Fatalf("status %d calls=%d expected=%d", status, calls, expected)
	}
}

func TestPermissionManifestMalformedErrorUsesStableCode(t *testing.T) {
	err := parsePermissionManifestError(&http.Response{StatusCode: 400, Header: http.Header{}}, []byte(`{}`))
	var protocol *PermissionManifestError
	if !errors.As(err, &protocol) || protocol.Code != "INVALID_ERROR_RESPONSE" {
		t.Fatalf("error=%v", err)
	}
}

func TestPermissionManifestTokenErrorNeverUsesIssuerDescription(t *testing.T) {
	err := parsePermissionManifestTokenError(&http.Response{StatusCode: 400}, []byte(`{"error":"invalid_client","error_description":"secret diagnostic"}`))
	var protocol *PermissionManifestError
	if !errors.As(err, &protocol) || protocol.Code != "invalid_client" || protocol.Message != "permission manifest machine token request failed" || strings.Contains(fmt.Sprint(protocol), "secret diagnostic") {
		t.Fatalf("error=%v", err)
	}
}

func TestPermissionManifestSharedBudgetRedactsTokenAndRequiresFields(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"sensitive-bearer","token_type":"Bearer","expires_in":60,"scope":"wrong"}`))
	}))
	defer server.Close()
	var observations []PermissionManifestObservation
	client, _ := NewPermissionManifestClient(PermissionManifestClientConfig{IssuerEndpoint: server.URL, PortalAPIEndpoint: server.URL, ClientID: "id", ClientSecret: "secret", MaxRetries: 2, MaxRetryDelay: time.Millisecond, Observer: func(event PermissionManifestObservation) { observations = append(observations, event) }})
	_, err := client.ValidatePermissionManifest(context.Background(), testManifest())
	var protocol *PermissionManifestError
	if !errors.As(err, &protocol) || protocol.Code != "INVALID_TOKEN_RESPONSE" || strings.Contains(protocol.Body, "sensitive-bearer") || calls != 3 {
		t.Fatalf("error=%v calls=%d body=%q", err, calls, protocol.Body)
	}
	if len(observations) != 1 || observations[0].Outcome != "ERROR" || strings.Contains(fmt.Sprint(observations), "sensitive-bearer") {
		t.Fatalf("observations=%v", observations)
	}

	calls = 0
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"safe","token_type":"Bearer","expires_in":60,"scope":"permissions:sync"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	client.ClearPermissionManifestTokenCache()
	_, err = client.ValidatePermissionManifest(context.Background(), testManifest())
	if !errors.As(err, &protocol) || protocol.Code != "INVALID_MANIFEST_RESPONSE" || calls != 2 {
		t.Fatalf("missing fields error=%v calls=%d", err, calls)
	}
}

func TestPermissionManifestBudgetIsSharedAcrossIssuerAndPortal(t *testing.T) {
	var calls int
	var manifestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"safe","token_type":"Bearer","expires_in":60,"scope":"permissions:sync"}`))
			return
		}
		manifestPath = r.URL.Path
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"status":503,"error":"UNAVAILABLE","message":"down","timestamp":"2026-07-17T00:00:00Z"}`))
	}))
	defer server.Close()
	client, _ := NewPermissionManifestClient(PermissionManifestClientConfig{IssuerEndpoint: server.URL, PortalAPIEndpoint: server.URL, ClientID: "id", ClientSecret: "secret", MaxRetries: 2, MaxRetryDelay: time.Millisecond})
	_, err := client.ValidatePermissionManifest(context.Background(), testManifest())
	var protocol *PermissionManifestError
	if !errors.As(err, &protocol) || protocol.Status != 503 || calls != 3 || manifestPath != "/open/v1/permission-manifests:sync" {
		t.Fatalf("error=%v calls=%d manifestPath=%q", err, calls, manifestPath)
	}
}

func TestPermissionManifestRejectsSharedResponseVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ ResponseReject []string }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := fixture.ResponseReject
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth2/token" {
					_, _ = w.Write([]byte(`{"access_token":"safe","token_type":"Bearer","expires_in":60,"scope":"permissions:sync"}`))
					return
				}
				var request PreparedPermissionManifest
				_ = json.NewDecoder(r.Body).Decode(&request)
				base := map[string]any{"mode": request.Mode, "manifestId": request.ManifestID, "revision": request.Revision, "fingerprint": request.Fingerprint, "applied": false, "results": []any{}, "drift": []any{}, "counts": map[string]int{"created": 0, "updated": 0, "unchanged": 0, "resurrected": 0, "conflict": 0, "drift": 0}}
				switch name {
				case "missing-required-field":
					_, _ = w.Write([]byte(`{}`))
				case "unknown-result-enum":
					base["results"] = []any{map[string]string{"key": "posts:read", "operation": "UNKNOWN", "reason": "DECLARATION_ACCEPTED"}}
					_ = json.NewEncoder(w).Encode(base)
				case "wrong-counts":
					base["counts"].(map[string]int)["created"] = 1
					_ = json.NewEncoder(w).Encode(base)
				case "malformed-json":
					_, _ = w.Write([]byte(`{`))
				case "duplicate-json-member-where-supported":
					_, _ = fmt.Fprintf(w, `{"mode":"validate","mode":"validate","manifestId":%q,"revision":%q,"fingerprint":%q,"applied":false,"results":[],"drift":[],"counts":{"created":0,"updated":0,"unchanged":0,"resurrected":0,"conflict":0,"drift":0}}`, request.ManifestID, request.Revision, request.Fingerprint)
				default:
					t.Fatalf("unknown shared responseReject vector %s", name)
				}
			}))
			defer server.Close()
			client, _ := NewPermissionManifestClient(PermissionManifestClientConfig{IssuerEndpoint: server.URL, PortalAPIEndpoint: server.URL, ClientID: "id", ClientSecret: "secret"})
			_, err := client.ValidatePermissionManifest(context.Background(), testManifest())
			var protocol *PermissionManifestError
			if !errors.As(err, &protocol) || (protocol.Code != "INVALID_MANIFEST_RESPONSE" && protocol.Code != "INVALID_JSON_RESPONSE") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func assertSharedLocalReject(t *testing.T, name string) {
	t.Helper()
	candidate := testManifest()
	switch name {
	case "duplicate-resource-action-key":
		candidate.Permissions = append(candidate.Permissions, candidate.Permissions[0])
	case "non-nfc-string":
		candidate.Permissions[0].Name = "Cafe\u0301"
	case "malformed-or-wildcard-key":
		candidate.Permissions[0].Resource = "*"
	case "name-over-128-utf16-units":
		candidate.Permissions[0].Name = strings.Repeat("x", 129)
	case "description-over-512-utf16-units":
		candidate.Permissions[0].Description = ptr(strings.Repeat("x", 513))
	default:
		t.Fatalf("unknown shared localReject vector %s", name)
	}
	if _, err := PreparePermissionManifest(candidate, PermissionManifestValidate); err == nil {
		t.Fatalf("shared localReject vector %s was accepted", name)
	}
}

func TestPreparePermissionManifestSortsAndRejectsInvalidInput(t *testing.T) {
	prepared, err := PreparePermissionManifest(PermissionManifest{ManifestID: "orders-api", Revision: "1", Permissions: []PermissionManifestDeclaration{
		{Resource: "users", Action: "read", Name: "Read users"},
		{Resource: "orders", Action: "write", Name: "Café", Description: ptr("café/日")},
	}}, PermissionManifestUpsert)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Permissions[0].Key() != "orders:write" {
		t.Fatalf("not sorted: %#v", prepared.Permissions)
	}
	duplicate := testManifest()
	duplicate.Permissions = append(duplicate.Permissions, duplicate.Permissions[0])
	if _, err := PreparePermissionManifest(duplicate, PermissionManifestValidate); err == nil {
		t.Fatal("duplicate accepted")
	}
	nonNFC := testManifest()
	nonNFC.Permissions[0].Name = "Cafe\u0301"
	if _, err := PreparePermissionManifest(nonNFC, PermissionManifestValidate); err == nil {
		t.Fatal("non-NFC accepted")
	}
	for _, invalid := range []PermissionManifestDeclaration{{Resource: "*", Action: "read", Name: "Read"}, {Resource: "posts", Action: "read", Name: strings.Repeat("x", 129)}, {Resource: "posts", Action: "read", Name: "Read", Description: ptr(strings.Repeat("x", 513))}} {
		candidate := testManifest()
		candidate.Permissions = []PermissionManifestDeclaration{invalid}
		if _, err := PreparePermissionManifest(candidate, PermissionManifestValidate); err == nil {
			t.Fatalf("invalid declaration accepted: %#v", invalid)
		}
	}
}

func TestPermissionManifestStartupDisabledDoesZeroWork(t *testing.T) {
	result, err := RunPermissionManifestStartup(context.Background(), nil, testManifest(), PermissionManifestStartupOptions{})
	if err != nil || result.NetworkAttempted || result.Continued || result.Result != nil {
		t.Fatalf("result=%v err=%v", result, err)
	}
}

func TestPermissionManifestDevelopmentStartupRequiresFailurePolicy(t *testing.T) {
	_, err := RunPermissionManifestStartup(context.Background(), nil, testManifest(), PermissionManifestStartupOptions{Mode: PermissionManifestDevelopmentStartup})
	if err == nil {
		t.Fatal("missing failure policy accepted")
	}
}

func TestPermissionManifestDevelopmentContinueRequiresAndEmitsRedactedEvent(t *testing.T) {
	_, err := RunPermissionManifestStartup(context.Background(), nil, testManifest(), PermissionManifestStartupOptions{Mode: PermissionManifestDevelopmentStartup, FailurePolicy: PermissionManifestContinue})
	if err == nil || !strings.Contains(err.Error(), "OnContinueError") {
		t.Fatalf("missing callback error=%v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"safe","token_type":"Bearer","expires_in":60,"scope":"permissions:sync"}`))
			return
		}
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"status":503,"error":"UNAVAILABLE","message":"secret detail","timestamp":"2026-07-17T00:00:00Z"}`))
	}))
	defer server.Close()
	client, _ := NewPermissionManifestClient(PermissionManifestClientConfig{IssuerEndpoint: server.URL, PortalAPIEndpoint: server.URL, ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	var events []PermissionManifestContinueEvent
	result, err := RunPermissionManifestStartup(context.Background(), client, testManifest(), PermissionManifestStartupOptions{Mode: PermissionManifestDevelopmentStartup, FailurePolicy: PermissionManifestContinue, IdempotencyKey: "continue-key", OnContinueError: func(event PermissionManifestContinueEvent) { events = append(events, event) }})
	if err != nil || !result.NetworkAttempted || !result.Continued || result.Result != nil {
		t.Fatalf("result=%v err=%v", result, err)
	}
	want := []PermissionManifestContinueEvent{{Mode: "DEVELOPMENT_STARTUP", Outcome: "CONTINUED", Status: 503, Code: "UNAVAILABLE"}}
	if !reflect.DeepEqual(events, want) || strings.Contains(fmt.Sprint(events), "secret detail") {
		t.Fatalf("events=%v", events)
	}
}

func TestPermissionManifestUsesBackendUTF16TextLimits(t *testing.T) {
	manifest := testManifest()
	manifest.Permissions[0].Name = strings.Repeat("😀", 65)
	if _, err := PreparePermissionManifest(manifest, PermissionManifestValidate); err == nil {
		t.Fatal("65 supplementary characters exceeded the 128 UTF-16 unit limit")
	}
}

func ptr(value string) *string { return &value }

func TestPermissionManifestRealBackendE2E(t *testing.T) {
	if os.Getenv("IAM_PERMISSION_MANIFEST_E2E") != "1" {
		t.Skip("live fixture disabled")
	}
	manifest := PermissionManifest{ManifestID: env(t, "IAM_MANIFEST_ID"), Revision: "e2e-1", Permissions: []PermissionManifestDeclaration{
		{Resource: "orders", Action: "write", Name: "Café", Description: ptr("café/日")},
		{Resource: "users", Action: "read", Name: "Read users"},
	}}
	config := func(clientID, secret string) PermissionManifestClientConfig {
		return PermissionManifestClientConfig{IssuerEndpoint: env(t, "IAM_MANIFEST_ISSUER"), PortalAPIEndpoint: env(t, "IAM_MANIFEST_PORTAL"), ClientID: clientID, ClientSecret: secret}
	}
	client, err := NewPermissionManifestClient(config(env(t, "IAM_MANIFEST_CLIENT_ID"), env(t, "IAM_MANIFEST_CLIENT_SECRET")))
	if err != nil {
		t.Fatal(err)
	}
	validate, err := client.ValidatePermissionManifest(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.UpsertPermissionManifest(context.Background(), manifest, "sdk-go-replay-key")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := client.UpsertPermissionManifest(context.Background(), manifest, "sdk-go-replay-key")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := client.ValidatePermissionManifest(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if validate.Fingerprint != first.Fingerprint || first.Fingerprint != replay.Fingerprint {
		t.Fatal("fingerprints differ")
	}
	for _, item := range stored.Results {
		if item.Operation != "UNCHANGED" {
			t.Fatalf("stored operation = %s", item.Operation)
		}
	}
	changed := manifest
	changed.Revision = "e2e-2"
	_, err = client.UpsertPermissionManifest(context.Background(), changed, "sdk-go-replay-key")
	var protocol *PermissionManifestError
	if !errors.As(err, &protocol) || protocol.Status != 409 {
		t.Fatalf("idempotency mismatch error = %v", err)
	}
	wrong, _ := NewPermissionManifestClient(config(env(t, "IAM_MANIFEST_WRONG_CLIENT_ID"), env(t, "IAM_MANIFEST_WRONG_CLIENT_SECRET")))
	_, err = wrong.ValidatePermissionManifest(context.Background(), manifest)
	if !errors.As(err, &protocol) || protocol.Status != 401 {
		t.Fatalf("wrong scope error = %v", err)
	}
	cross, _ := NewPermissionManifestClient(config(env(t, "IAM_MANIFEST_CROSS_CLIENT_ID"), env(t, "IAM_MANIFEST_CROSS_CLIENT_SECRET")))
	_, err = cross.ValidatePermissionManifest(context.Background(), manifest)
	if !errors.As(err, &protocol) || protocol.Status != 404 {
		t.Fatalf("cross owner error = %v", err)
	}
	crossApplication, _ := NewPermissionManifestClient(config(env(t, "IAM_MANIFEST_APP_B_CLIENT_ID"), env(t, "IAM_MANIFEST_APP_B_CLIENT_SECRET")))
	isolated, err := crossApplication.ValidatePermissionManifest(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range isolated.Results {
		if item.Operation != "CREATE" {
			t.Fatalf("cross application operation = %s", item.Operation)
		}
	}
}

func TestPermissionManifestRealBackendNegativeRetryPolicy(t *testing.T) {
	mode := os.Getenv("IAM_PERMISSION_MANIFEST_NEGATIVE_E2E")
	if mode == "" {
		t.Skip("negative live fixture disabled")
	}
	clientID, secret := env(t, "IAM_NEG_CLIENT_ID"), env(t, "IAM_NEG_CLIENT_SECRET")
	if mode == "rate" {
		clientID, secret = env(t, "IAM_NEG_RATE_CLIENT_ID"), env(t, "IAM_NEG_RATE_CLIENT_SECRET")
	}
	config := func(portal string) PermissionManifestClientConfig {
		return PermissionManifestClientConfig{IssuerEndpoint: env(t, "IAM_NEG_ISSUER"), PortalAPIEndpoint: portal, ClientID: clientID, ClientSecret: secret, MaxRetries: map[bool]int{true: 1, false: 2}[mode == "rate"], MaxRetryDelay: time.Millisecond}
	}
	manifest := PermissionManifest{
		ManifestID: "m3-negative-go-" + mode,
		Revision:   "1",
		Permissions: []PermissionManifestDeclaration{
			{Resource: "orders", Action: "read", Name: "Read orders"},
		},
	}
	if mode == "terminal" {
		direct, _ := NewPermissionManifestClient(config(env(t, "IAM_NEG_PORTAL")))
		if _, err := direct.UpsertPermissionManifest(context.Background(), manifest, "sdk-go-terminal-key"); err != nil {
			t.Fatal(err)
		}
		manifest.Revision = "2"
	}
	proxied, _ := NewPermissionManifestClient(config(env(t, "IAM_NEG_PROXY")))
	var err error
	if mode == "terminal" {
		_, err = proxied.UpsertPermissionManifest(context.Background(), manifest, "sdk-go-terminal-key")
	} else {
		_, err = proxied.ValidatePermissionManifest(context.Background(), manifest)
	}
	var protocol *PermissionManifestError
	expected := 409
	if mode == "rate" {
		expected = 429
	}
	if !errors.As(err, &protocol) || protocol.Status != expected {
		t.Fatalf("negative error = %v", err)
	}
}

func env(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
