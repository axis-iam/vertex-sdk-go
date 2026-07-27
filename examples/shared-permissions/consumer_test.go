package sharedpermissions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
)

func TestGeneratedPermissionBindsToServerGuardAllowAndDeny(t *testing.T) {
	var sdk iam.SDK
	guard := sdk.RequirePerm(OrdersRead)
	handler := guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	allow := httptest.NewRequest(http.MethodGet, "/orders", nil)
	allow = allow.WithContext(iamtest.NewContext(allow.Context(), iamtest.WithPermissions("orders:*")))
	allowResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowResponse, allow)
	if allowResponse.Code != http.StatusNoContent {
		t.Fatalf("generated OrdersRead guard should allow orders:*, got %d", allowResponse.Code)
	}

	deny := httptest.NewRequest(http.MethodGet, "/orders", nil)
	deny = deny.WithContext(iamtest.NewContext(deny.Context(), iamtest.WithPermissions("users:*")))
	denyResponse := httptest.NewRecorder()
	handler.ServeHTTP(denyResponse, deny)
	if denyResponse.Code != http.StatusForbidden {
		t.Fatalf("generated OrdersRead guard should deny users:*, got %d", denyResponse.Code)
	}

	if OrdersRead.Authority() != "orders:read" {
		t.Fatal("generated permission wire key changed")
	}
}
