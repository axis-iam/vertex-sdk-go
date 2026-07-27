// echo-demo is a minimal IAM SDK example using labstack/echo.
// IAM_CLIENT_ID and IAM_CLIENT_SECRET must come from a WEB/M2M confidential
// ApplicationClient under the demo business Application.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	iamecho "github.com/axis-iam/vertex-sdk-go/echo"
)

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
	e := echo.New()
	e.Use(iamecho.Authenticate(sdk))

	e.GET("/posts", func(c echo.Context) error {
		u := authz.FromContext(c.Request().Context())
		return c.JSON(http.StatusOK, echo.Map{"user": u.Subject, "permissions": u.Permissions})
	}, iamecho.RequirePerm(PostsRead))

	e.POST("/posts", func(c echo.Context) error {
		return c.NoContent(http.StatusCreated)
	}, iamecho.RequirePerm(PostsWrite))

	log.Fatal(e.Start(":8080"))
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("env %s is required", k)
	}
	return v
}
