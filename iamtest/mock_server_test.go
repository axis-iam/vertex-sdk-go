package iamtest_test

import (
	"context"
	"testing"

	"github.com/axis-iam/vertex-sdk-go/iamtest"
)

func TestMockResolver(t *testing.T) {
	r := iamtest.NewMockResolver().Given("admin", "posts:*").Given("viewer", "posts:read")
	perms, err := r.Resolve(context.Background(), "app", []string{"admin", "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) != 2 {
		t.Fatalf("expected dedup of 2, got %v", perms)
	}
}

func TestMockServer_TokenFor(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.WithAudience("aud")
	tok, err := srv.TokenFor("u", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
}

func TestNewContext(t *testing.T) {
	ctx := iamtest.NewContext(context.Background(),
		iamtest.WithSubject("u"),
		iamtest.WithEmail("u@x.com"),
		iamtest.WithAppID("app"),
		iamtest.WithRoles("r"),
		iamtest.WithPermissions("posts:read"),
		iamtest.WithOrg("org", "ADMIN"),
		iamtest.WithACR("mfa"),
		iamtest.WithImpersonator("admin"),
	)
	// Just exercise the constructors — behavioural checks live in authz.
	if ctx == nil {
		t.Fatal("nil ctx")
	}
}
