package middleware

import (
	"net/http"

	"github.com/axis-iam/vertex-sdk-go/authz"
)

// RequirePerm returns a middleware that rejects the request with 403 if the
// context User does not satisfy perm.
func RequirePerm(perm authz.PermissionKey, opts ...Option) func(http.Handler) http.Handler {
	o := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := authz.FromContext(r.Context())
			if u == nil {
				o.responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
				return
			}
			if !authz.HasPermission(perm, u.Permissions) {
				o.responder(w, r, http.StatusForbidden, "FORBIDDEN", "missing permission: "+perm.Authority())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPerm passes if the caller holds any one of perms.
func RequireAnyPerm(perms []authz.PermissionKey, opts ...Option) func(http.Handler) http.Handler {
	o := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := authz.FromContext(r.Context())
			if u == nil {
				o.responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
				return
			}
			if !authz.HasAnyPermission(perms, u.Permissions) {
				o.responder(w, r, http.StatusForbidden, "FORBIDDEN", "missing any of required permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllPerms passes only if the caller holds every perm.
func RequireAllPerms(perms []authz.PermissionKey, opts ...Option) func(http.Handler) http.Handler {
	o := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := authz.FromContext(r.Context())
			if u == nil {
				o.responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
				return
			}
			if !authz.HasAllPermissions(perms, u.Permissions) {
				o.responder(w, r, http.StatusForbidden, "FORBIDDEN", "missing required permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireStepUp enforces that the JWT's acr claim matches acr.
func RequireStepUp(acr string, opts ...Option) func(http.Handler) http.Handler {
	o := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := authz.FromContext(r.Context())
			if u == nil {
				o.responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
				return
			}
			if u.ACR != acr {
				o.responder(w, r, http.StatusForbidden, "STEP_UP_REQUIRED", "acr "+acr+" required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireNoImpersonation rejects requests executed under an admin
// impersonation token.
func RequireNoImpersonation(opts ...Option) func(http.Handler) http.Handler {
	o := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := authz.FromContext(r.Context())
			if u == nil {
				o.responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
				return
			}
			if u.IsImpersonating() {
				o.responder(w, r, http.StatusForbidden, "FORBIDDEN", "impersonated sessions may not perform this action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Option tunes a middleware helper.
type Option func(*options)

type options struct {
	responder ErrorResponder
}

// WithResponder lets callers substitute their own ErrorResponder.
func WithResponder(r ErrorResponder) Option {
	return func(o *options) { o.responder = r }
}

func applyOptions(opts []Option) options {
	o := options{responder: DefaultErrorResponder}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
