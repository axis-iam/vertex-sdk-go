// gin-demo is a minimal IAM SDK example using gin-gonic/gin.
// IAM_CLIENT_ID and IAM_CLIENT_SECRET must come from a WEB/M2M confidential
// ApplicationClient under the demo business Application.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	iamgin "github.com/axis-iam/vertex-sdk-go/gin"
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
	r := gin.Default()
	r.Use(iamgin.Authenticate(sdk))

	r.GET("/posts", iamgin.RequirePerm(PostsRead), func(c *gin.Context) {
		u := authz.FromContext(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"user": u.Subject, "permissions": u.Permissions})
	})
	r.POST("/posts", iamgin.RequirePerm(PostsWrite), func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"ok": true})
	})

	log.Println("listening on :8080")
	_ = r.Run(":8080")
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("env %s is required", k)
	}
	return v
}
