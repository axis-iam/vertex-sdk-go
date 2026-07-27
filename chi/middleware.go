// Package iamchi provides thin wrappers around the core net/http middleware
// for chi-based applications. Because chi middleware already uses the
// http.Handler signature, this package is intentionally minimal.
package iamchi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	"github.com/axis-iam/vertex-sdk-go/middleware"
)

// Authenticate forwards to (*iam.SDK).Authenticate.
func Authenticate(sdk *iam.SDK, opts ...iam.AuthOption) func(http.Handler) http.Handler {
	return sdk.Authenticate(opts...)
}

// RequirePerm is an alias for middleware.RequirePerm exposed under the
// iamchi package name so user code reads iamchi.RequirePerm(...).
func RequirePerm(perm authz.PermissionKey, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequirePerm(perm, opts...)
}

// RequireAnyPerm is an alias for middleware.RequireAnyPerm.
func RequireAnyPerm(perms []authz.PermissionKey, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireAnyPerm(perms, opts...)
}

// RequireAllPerms is an alias for middleware.RequireAllPerms.
func RequireAllPerms(perms []authz.PermissionKey, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireAllPerms(perms, opts...)
}

// RequireStepUp is an alias for middleware.RequireStepUp.
func RequireStepUp(acr string, opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireStepUp(acr, opts...)
}

// RequireNoImpersonation is an alias for middleware.RequireNoImpersonation.
func RequireNoImpersonation(opts ...middleware.Option) func(http.Handler) http.Handler {
	return middleware.RequireNoImpersonation(opts...)
}

// Install registers the Authenticate middleware on r. Separate route groups
// still compose the RequirePerm middleware themselves.
func Install(r chi.Router, sdk *iam.SDK, opts ...iam.AuthOption) {
	r.Use(sdk.Authenticate(opts...))
}
