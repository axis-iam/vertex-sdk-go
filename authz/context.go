package authz

import (
	"context"
	"errors"
)

// User is the authenticated caller as seen by the request-scoped context.
type User struct {
	Subject     string
	AppID       string
	Email       string
	OrgID       string
	OrgRole     string
	WorkspaceID string
	SessionID   string
	Roles       []string
	Permissions []string
	AMR         []string
	ACR         string
	Actor       *Actor
	Claims      map[string]any
}

// Actor is the delegating subject for impersonation (JWT act claim).
type Actor struct {
	Subject string
}

// IsImpersonating reports whether the current request is an admin acting as
// another user.
func (u *User) IsImpersonating() bool { return u != nil && u.Actor != nil && u.Actor.Subject != "" }

// HasMFA reports whether the JWT's amr claim includes an MFA factor.
func (u *User) HasMFA() bool {
	if u == nil {
		return false
	}
	for _, a := range u.AMR {
		if a == "mfa" || a == "totp" || a == "webauthn" || a == "pwd+mfa" {
			return true
		}
	}
	return false
}

// HasPermission mirrors the package-level HasPermission against this user's
// permission list.
func (u *User) HasPermission(resource, action string) bool {
	if u == nil {
		return false
	}
	return HasPermission(PermissionKey{Resource: resource, Action: action}, u.Permissions)
}

type ctxKey struct{}

var userCtxKey ctxKey

// WithUser returns a new context carrying u.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userCtxKey, u)
}

// FromContext returns the User previously stored with WithUser, or nil.
func FromContext(ctx context.Context) *User {
	if ctx == nil {
		return nil
	}
	u, _ := ctx.Value(userCtxKey).(*User)
	return u
}

// MustPermission returns an error if the current context does not satisfy perm.
func MustPermission(ctx context.Context, perm PermissionKey) error {
	u := FromContext(ctx)
	if u == nil {
		return ErrUnauthenticated
	}
	if !HasPermission(perm, u.Permissions) {
		return ErrForbidden
	}
	return nil
}

// Errors returned from the context helpers.
var (
	ErrUnauthenticated = errors.New("authz: unauthenticated")
	ErrForbidden       = errors.New("authz: forbidden")
)
