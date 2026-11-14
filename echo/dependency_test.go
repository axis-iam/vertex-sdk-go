package iamecho_test

import (
	"encoding/json"
	iam "github.com/axis-iam/vertex-sdk-go"
	iamecho "github.com/axis-iam/vertex-sdk-go/echo"
	"github.com/axis-iam/vertex-sdk-go/iamtest"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAuthDependencyFailures(t *testing.T) {
	mock, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()
	token, err := mock.TokenFor("u1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body       string
		upstream, status int
	}{
		{"fetch", "sensitive upstream details", 502, 503},
		{"parse", "{", 200, 503},
		{"unknown", `{"keys":[]}`, 200, 401},
		{"malformed", "{", 200, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/openid-configuration" {
					_ = json.NewEncoder(w).Encode(map[string]string{"issuer": mock.Issuer(), "jwks_uri": "http://" + r.Host + "/jwks"})
					return
				}
				calls.Add(1)
				w.WriteHeader(tc.upstream)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()
			sdk, err := iam.New(&iam.SDKConfig{Endpoint: s.URL, Issuer: mock.Issuer(), ClientID: "client", ClientSecret: "fixture", Audience: "api://orders"})
			if err != nil {
				t.Fatal(err)
			}
			router := echo.New()
			router.Use(iamecho.Authenticate(sdk))
			router.GET("/", func(echo.Context) error { t.Error("must fail closed"); return nil })
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				bearer := token
				if tc.name == "malformed" {
					bearer = "not.a.jwt"
				}
				req.Header.Set("Authorization", "Bearer "+bearer)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				code, message := "UNAUTHORIZED", "invalid bearer token"
				if tc.status == 503 {
					code, message = "AUTH_DEPENDENCY_UNAVAILABLE", "authentication service unavailable"
				}
				want := "{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}\n"
				if rec.Code != tc.status || rec.Body.String() != want {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
				}
				if iam.FromContext(req.Context()) != nil {
					t.Error("unverified context escaped adapter")
				}
			}
			wantCalls := int32(1)
			if tc.name == "malformed" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls {
				t.Fatalf("unexpected JWKS requests %d", calls.Load())
			}
		})
	}
}
