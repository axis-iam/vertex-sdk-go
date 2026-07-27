package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchesConsumesSharedWildcardVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CodeGeneration struct {
			WildcardMatch []struct {
				Target  string `json:"target"`
				Granted string `json:"granted"`
				Matches bool   `json:"matches"`
			} `json:"wildcardMatch"`
		} `json:"codeGeneration"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.CodeGeneration.WildcardMatch {
		parts := strings.Split(vector.Target, ":")
		if len(parts) != 2 {
			t.Fatalf("invalid shared target %q", vector.Target)
		}
		if got := Matches(PermissionKey{Resource: parts[0], Action: parts[1]}, vector.Granted); got != vector.Matches {
			t.Fatalf("Matches(%q, %q) = %v", vector.Target, vector.Granted, got)
		}
	}
}

func TestMatches(t *testing.T) {
	target := PermissionKey{Resource: "orders", Action: "read"}

	cases := []struct {
		granted string
		want    bool
	}{
		{"orders:read", true},
		{"orders:*", true},
		{"*:read", false},
		{"*:*", true},
		{"users:read", false},
		{"orders:write", false},
		{"", false},
		{"orders", false},
		{":read", false},
		{"orders:", false},
		{"Orders:read", false}, // case-sensitive
	}
	for _, c := range cases {
		t.Run(c.granted, func(t *testing.T) {
			if got := Matches(target, c.granted); got != c.want {
				t.Fatalf("Matches(%q) = %v, want %v", c.granted, got, c.want)
			}
		})
	}
}

func TestHasPermission(t *testing.T) {
	tests := []struct {
		required PermissionKey
		granted  []string
		want     bool
	}{
		{PermissionKey{"orders", "read"}, []string{"orders:read"}, true},
		{PermissionKey{"orders", "read"}, []string{"orders:*"}, true},
		{PermissionKey{"orders", "read"}, []string{"*:*"}, true},
		{PermissionKey{"orders", "read"}, []string{"*:read"}, false},
		{PermissionKey{"orders", "read"}, []string{"users:read"}, false},
		{PermissionKey{"orders", "read"}, []string{"orders"}, false},
		{PermissionKey{"orders", "read"}, []string{}, false},
		{PermissionKey{"orders", "read"}, nil, false},
		{PermissionKey{}, []string{"orders:read"}, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s in %v", tt.required, tt.granted), func(t *testing.T) {
			if got := HasPermission(tt.required, tt.granted); got != tt.want {
				t.Errorf("HasPermission(%q, %v) = %v, want %v", tt.required, tt.granted, got, tt.want)
			}
		})
	}
}

func TestHasAllPermissions(t *testing.T) {
	targets := []PermissionKey{
		{"orders", "read"},
		{"posts", "write"},
	}
	if !HasAllPermissions(targets, []string{"orders:read", "posts:write"}) {
		t.Fatal("expected all granted")
	}
	if HasAllPermissions(targets, []string{"orders:read"}) {
		t.Fatal("missing posts:write should fail")
	}
	if HasAllPermissions(nil, []string{"*:*"}) {
		t.Fatal("empty target list should be false (defensive)")
	}
}

func TestHasAnyPermission(t *testing.T) {
	targets := []PermissionKey{
		{"orders", "read"},
		{"posts", "write"},
	}
	if !HasAnyPermission(targets, []string{"orders:read"}) {
		t.Fatal("expected any match")
	}
	if HasAnyPermission(targets, []string{"users:list"}) {
		t.Fatal("no match but accepted")
	}
}

func TestParsePermission(t *testing.T) {
	good, err := ParsePermission("orders:read")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if good.Resource != "orders" || good.Action != "read" {
		t.Fatalf("parsed wrong: %+v", good)
	}
	for _, bad := range []string{"", ":", "orders", ":read", "orders:"} {
		if _, err := ParsePermission(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestPermissionKeyString(t *testing.T) {
	k := PermissionKey{Resource: "posts", Action: "read"}
	if k.String() != "posts:read" {
		t.Fatalf("got %s", k.String())
	}
	if k.Authority() != "posts:read" {
		t.Fatalf("authority mismatch")
	}
}
