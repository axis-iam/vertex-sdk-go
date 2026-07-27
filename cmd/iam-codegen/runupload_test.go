package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRunUploadStructuredManifest(t *testing.T) {
	var portalCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "safe", "token_type": "Bearer", "expires_in": 300, "scope": "permissions:sync"})
		case "/open/v1/permission-manifests:sync":
			portalCalls.Add(1)
			var request map[string]any
			_ = json.NewDecoder(r.Body).Decode(&request)
			_ = json.NewEncoder(w).Encode(map[string]any{"mode": request["mode"], "manifestId": request["manifestId"], "revision": request["revision"], "fingerprint": request["fingerprint"], "applied": false, "results": []any{}, "drift": []any{}, "counts": map[string]int{"created": 0, "updated": 0, "unchanged": 0, "resurrected": 0, "conflict": 0, "drift": 0}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"manifestId":"cli-test","revision":"1","permissions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runUpload([]string{"--issuer-endpoint", srv.URL, "--portal-api-endpoint", srv.URL, "--client-id", "cid", "--client-secret", "secret", "--manifest", path}); err != nil {
		t.Fatal(err)
	}
	if portalCalls.Load() != 1 {
		t.Fatalf("portal calls = %d", portalCalls.Load())
	}
}

func TestRunUploadMissingFlags(t *testing.T) {
	if runUpload([]string{}) == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadPermissionManifestConsumesSharedFileVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ManifestFiles struct {
			Accept []struct{ Name, JSON string }
			Reject []struct{ Name, JSON string }
		} `json:"manifestFiles"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.ManifestFiles.Accept {
		t.Run("accept/"+vector.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(vector.JSON), 0o600); err != nil {
				t.Fatal(err)
			}
			manifest, err := loadPermissionManifest(path)
			if err != nil || manifest.ManifestID != "orders-api" {
				t.Fatalf("manifest=%v err=%v", manifest, err)
			}
		})
	}
	for _, vector := range fixture.ManifestFiles.Reject {
		t.Run("reject/"+vector.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(vector.JSON), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPermissionManifest(path); err == nil {
				t.Fatal("invalid shared file vector accepted")
			}
		})
	}
}
