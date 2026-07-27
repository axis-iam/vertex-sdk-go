package iamtest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/axis-iam/vertex-sdk-go/iamtest"
)

func TestMockServer_Endpoints(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.Given("admin", "posts:read", "posts:write")

	// discovery
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"jwks_uri"`)) {
		t.Fatalf("discovery missing jwks_uri: %s", body)
	}

	// jwks
	resp, err = http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"keys"`)) {
		t.Fatalf("jwks missing keys field: %s", body)
	}

	// resolve
	reqBody, _ := json.Marshal(map[string]any{"clientId": "app", "roles": []string{"admin"}})
	resp, err = http.Post(srv.URL+"/open/v1/permissions:resolve", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var decoded map[string][]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("resolve body: %v / %s", err, body)
	}
	if len(decoded["permissions"]) != 2 {
		t.Fatalf("wrong permissions: %v", decoded)
	}

	// list
	resp, err = http.Get(srv.URL + "/open/v1/apps/my-app/permissions")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"permissions"`)) {
		t.Fatalf("list body: %s", body)
	}

	// unknown
	resp, err = http.Get(srv.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}
