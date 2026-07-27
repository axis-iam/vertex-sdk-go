package authz

import (
	"context"
	"errors"
	"testing"
)

func TestContextRoundTrip(t *testing.T) {
	u := &User{Subject: "u1", Permissions: []string{"posts:read"}}
	ctx := WithUser(context.Background(), u)

	got := FromContext(ctx)
	if got == nil || got.Subject != "u1" {
		t.Fatalf("roundtrip failed: %+v", got)
	}
}

func TestFromContext_Missing(t *testing.T) {
	if FromContext(context.Background()) != nil {
		t.Fatal("expected nil for empty ctx")
	}
	if FromContext(nil) != nil { //nolint:staticcheck
		t.Fatal("expected nil for nil ctx")
	}
}

func TestUserHelpers(t *testing.T) {
	u := &User{
		Permissions: []string{"posts:*"},
		AMR:         []string{"pwd", "mfa"},
		Actor:       &Actor{Subject: "admin"},
	}
	if !u.HasPermission("posts", "read") {
		t.Fatal("wildcard failed")
	}
	if !u.IsImpersonating() {
		t.Fatal("should be impersonating")
	}
	if !u.HasMFA() {
		t.Fatal("should have mfa")
	}
	var nilUser *User
	if nilUser.HasPermission("a", "b") || nilUser.IsImpersonating() || nilUser.HasMFA() {
		t.Fatal("nil receiver should be safe + false")
	}
}

func TestMustPermission(t *testing.T) {
	ctx := context.Background()
	if err := MustPermission(ctx, PermissionKey{"a", "b"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
	ctx = WithUser(ctx, &User{Permissions: []string{"posts:read"}})
	if err := MustPermission(ctx, PermissionKey{"posts", "write"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if err := MustPermission(ctx, PermissionKey{"posts", "read"}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}
