// Package iamecho exposes the IAM SDK as echo.MiddlewareFunc middleware.
package iamecho

import (
	"net/http"

	"github.com/labstack/echo/v4"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
)

// Authenticate validates the bearer token and stashes the *authz.User in the
// echo request context.
func Authenticate(sdk *iam.SDK, opts ...iam.AuthOption) echo.MiddlewareFunc {
	inner := sdk.Authenticate(opts...)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var callErr error
			handler := inner(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				callErr = next(c)
			}))
			handler.ServeHTTP(c.Response().Writer, c.Request())
			return callErr
		}
	}
}

// RequirePerm rejects the request with 403 if the caller lacks perm.
func RequirePerm(perm authz.PermissionKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u := authz.FromContext(c.Request().Context())
			if u == nil {
				return c.JSON(http.StatusUnauthorized, errPayload("UNAUTHORIZED", "not authenticated"))
			}
			if !authz.HasPermission(perm, u.Permissions) {
				return c.JSON(http.StatusForbidden, errPayload("FORBIDDEN", "missing permission: "+perm.Authority()))
			}
			return next(c)
		}
	}
}

// RequireAnyPerm accepts the request if the caller holds any of perms.
func RequireAnyPerm(perms []authz.PermissionKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u := authz.FromContext(c.Request().Context())
			if u == nil || !authz.HasAnyPermission(perms, u.Permissions) {
				return c.JSON(http.StatusForbidden, errPayload("FORBIDDEN", "missing any of required permissions"))
			}
			return next(c)
		}
	}
}

// RequireAllPerms accepts the request only if the caller holds every perm.
func RequireAllPerms(perms []authz.PermissionKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u := authz.FromContext(c.Request().Context())
			if u == nil || !authz.HasAllPermissions(perms, u.Permissions) {
				return c.JSON(http.StatusForbidden, errPayload("FORBIDDEN", "missing required permissions"))
			}
			return next(c)
		}
	}
}

// RequireStepUp enforces an ACR level.
func RequireStepUp(acr string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u := authz.FromContext(c.Request().Context())
			if u == nil || u.ACR != acr {
				return c.JSON(http.StatusForbidden, errPayload("STEP_UP_REQUIRED", "acr "+acr+" required"))
			}
			return next(c)
		}
	}
}

// RequireNoImpersonation blocks impersonated sessions.
func RequireNoImpersonation() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u := authz.FromContext(c.Request().Context())
			if u == nil || u.IsImpersonating() {
				return c.JSON(http.StatusForbidden, errPayload("FORBIDDEN", "impersonated sessions may not perform this action"))
			}
			return next(c)
		}
	}
}

func errPayload(code, message string) map[string]string { return map[string]string{"code": code, "message": message} }
