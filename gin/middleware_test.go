package iamgin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	iamgin "github.com/axis-iam/vertex-sdk-go/gin"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
	"github.com/gin-gonic/gin"
)

func TestResourceAudienceContract(t *testing.T) {
	srv, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.Given("reader", "orders:read")
	sdk, err := iam.New(&iam.SDKConfig{Endpoint: srv.URL, ClientID: "orders-m2m-client", ClientSecret: "fixture", Audience: "api://orders"})
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(iamgin.Authenticate(sdk))
	router.GET("/orders", iamgin.RequirePerm(authz.PermissionKey{Resource: "orders", Action: "read"}), func(c *gin.Context) {
		if u := iam.FromContext(c.Request.Context()); u == nil || u.Subject != "u1" {
			t.Error("missing verified request context")
		}
		c.Status(204)
	})
	for _, tc := range []struct {
		name     string
		audience string
		roles    []string
		status   int
	}{
		{"resource", "api://orders", []string{"reader"}, 204},
		{"client-id", "orders-m2m-client", []string{"reader"}, 401},
		{"missing-auth", "", nil, 401},
		{"insufficient-permission", "api://orders", []string{"none"}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/orders", nil)
			if tc.audience != "" {
				token, err := srv.TokenForWith("u1", tc.roles, map[string]any{"aud": tc.audience})
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("want %d, got %d", tc.status, rec.Code)
			}
			if iam.FromContext(req.Context()) != nil {
				t.Fatal("authentication escaped request context")
			}
		})
	}
}
