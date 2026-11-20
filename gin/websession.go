package iamgin

import (
	"net/http"

	"github.com/axis-iam/vertex-sdk-go/websession"
	"github.com/gin-gonic/gin"
)

// WebSessionHandler serves the same C0 routes as net/http. Mount on /auth/*path
// (or the configured BasePath) without stripping the prefix.
func WebSessionHandler(service *websession.Service) gin.HandlerFunc {
	return gin.WrapH(service.Handler())
}

// WebSession puts the verified identity in the native request context and
// aborts the chain on failure. FromContext never performs implicit network I/O.
func WebSession(service *websession.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		called := false
		service.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
		if !called {
			c.Abort()
		}
	}
}
