// chi-demo is a minimal IAM SDK example using go-chi/chi.
//
// Run:
//
//	IAM_ENDPOINT=https://iam.example.com \
//	IAM_CLIENT_ID=iam_web_or_m2m_client_id \
//	IAM_CLIENT_SECRET=... \
//	go run .
//
// IAM_CLIENT_ID and IAM_CLIENT_SECRET must come from a WEB/M2M confidential
// ApplicationClient under the demo business Application.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	iamchi "github.com/axis-iam/vertex-sdk-go/chi"
)

// In real apps this is generated from iam-permission-manifest.json by
// `iam-codegen generate` into an internal/perms package.
var (
	PostsRead  = authz.PermissionKey{Resource: "posts", Action: "read"}
	PostsWrite = authz.PermissionKey{Resource: "posts", Action: "write"}
)

func main() {
	cfg := &iam.SDKConfig{
		Endpoint:     mustEnv("IAM_ENDPOINT"),
		ClientID:     mustEnv("IAM_CLIENT_ID"),
		ClientSecret: mustEnv("IAM_CLIENT_SECRET"),
	}
	sdk, err := iam.New(cfg)
	if err != nil {
		log.Fatalf("iam: %v", err)
	}
	r := chi.NewRouter()
	r.Use(iamchi.Authenticate(sdk))

	r.With(iamchi.RequirePerm(PostsRead)).Get("/posts", list)
	r.With(iamchi.RequirePerm(PostsWrite)).Post("/posts", create)
	r.With(iamchi.RequireStepUp("urn:iam:acr:mfa")).Post("/posts/danger", danger)

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

func list(w http.ResponseWriter, r *http.Request) {
	u := authz.FromContext(r.Context())
	_ = json.NewEncoder(w).Encode(map[string]any{"user": u.Subject, "permissions": u.Permissions})
}

func create(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) }
func danger(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("env %s is required", k)
	}
	return v
}
