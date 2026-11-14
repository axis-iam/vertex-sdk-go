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
	output := filepath.Join(directory, "generated", "permissions.gen.go")
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
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("generated file must be owner-only: info=%v err=%v", info, err)
	}
	info, err = os.Stat(filepath.Dir(output))
	if err != nil || info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("generated directory must not grant other-user access: info=%v err=%v", info, err)
	}
}

func TestRunGenerateReportsOutputFailure(t *testing.T) {
	directory := t.TempDir()
	manifest := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"manifestId":"orders-api","revision":"1","permissions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	if err := runGenerate([]string{"--manifest", manifest, "--output", filepath.Join(directory, "permissions.gen.go")}); err == nil {
		t.Fatal("broken stdout reported success")
	}
}
