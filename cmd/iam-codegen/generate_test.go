package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGenerateUsesOnlyLocalManifest(t *testing.T) {
	directory := t.TempDir()
	manifest := filepath.Join(directory, "manifest.json")
	output := filepath.Join(directory, "permissions.gen.go")
	if err := os.WriteFile(manifest, []byte(`{"manifestId":"orders-api","revision":"1","permissions":[{"resource":"orders","action":"read","name":"Read orders","description":null}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runGenerate([]string{"--manifest", manifest, "--package", "perms", "--output", output}); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `OrdersRead = authz.PermissionKey{Resource: "orders", Action: "read"}`) {
		t.Fatalf("unexpected generated source:\n%s", source)
	}
}
