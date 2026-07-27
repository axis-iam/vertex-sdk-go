// Package iamgin exposes the IAM SDK as gin.HandlerFunc middleware.
package iamgin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
)

// Authenticate validates the bearer token, resolves permissions, and stashes
// the *authz.User in the gin context chain.
func Authenticate(sdk *iam.SDK, opts ...iam.AuthOption) gin.HandlerFunc {
	inner := sdk.Authenticate(opts...)
	return func(c *gin.Context) {
		done := false
		h := inner(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			done = true
			c.Request = r // propagate context carrying *authz.User
			c.Next()
		}))
		h.ServeHTTP(c.Writer, c.Request)
		if !done {
			c.Abort()
		}
	}
}

// RequirePerm rejects the request with 403 if the caller lacks perm.
func RequirePerm(perm authz.PermissionKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := authz.FromContext(c.Request.Context())
		if u == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errPayload("UNAUTHORIZED", "not authenticated"))
			return
		}
		if !authz.HasPermission(perm, u.Permissions) {
			c.AbortWithStatusJSON(http.StatusForbidden, errPayload("FORBIDDEN", "missing permission: "+perm.Authority()))
			return
		}
	}
}

// RequireAnyPerm accepts the request if the caller holds any of perms.
func RequireAnyPerm(perms []authz.PermissionKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := authz.FromContext(c.Request.Context())
		if u == nil || !authz.HasAnyPermission(perms, u.Permissions) {
			c.AbortWithStatusJSON(http.StatusForbidden, errPayload("FORBIDDEN", "missing any of required permissions"))
			return
		}
	}
}

// RequireAllPerms accepts the request only if the caller holds every perm.
func RequireAllPerms(perms []authz.PermissionKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := authz.FromContext(c.Request.Context())
		if u == nil || !authz.HasAllPermissions(perms, u.Permissions) {
			c.AbortWithStatusJSON(http.StatusForbidden, errPayload("FORBIDDEN", "missing required permissions"))
			return
		}
	}
}

// RequireStepUp requires the JWT's acr claim to match acr.
func RequireStepUp(acr string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := authz.FromContext(c.Request.Context())
		if u == nil || u.ACR != acr {
			c.AbortWithStatusJSON(http.StatusForbidden, errPayload("STEP_UP_REQUIRED", "acr "+acr+" required"))
			return
		}
	}
}

// RequireNoImpersonation blocks requests performed under an admin
// impersonation token.
func RequireNoImpersonation() gin.HandlerFunc {
	return func(c *gin.Context) {
		u := authz.FromContext(c.Request.Context())
		if u == nil || u.IsImpersonating() {
			c.AbortWithStatusJSON(http.StatusForbidden, errPayload("FORBIDDEN", "impersonated sessions may not perform this action"))
			return
		}
	}
}

func errPayload(code, message string) gin.H { return gin.H{"code": code, "message": message} }
