package iamtest

import (
	"context"

	"github.com/axis-iam/vertex-sdk-go/authz"
)

// Option mutates a test *authz.User.
type Option func(*authz.User)

// WithSubject sets the user subject.
func WithSubject(sub string) Option { return func(u *authz.User) { u.Subject = sub } }

// WithEmail sets the email.
func WithEmail(email string) Option { return func(u *authz.User) { u.Email = email } }

// WithAppID sets the app_id claim.
func WithAppID(id string) Option { return func(u *authz.User) { u.AppID = id } }

// WithRoles sets the roles.
func WithRoles(roles ...string) Option { return func(u *authz.User) { u.Roles = roles } }

// WithPermissions sets the permissions.
func WithPermissions(perms ...string) Option { return func(u *authz.User) { u.Permissions = perms } }

// WithOrg sets the org context.
func WithOrg(orgID, orgRole string) Option {
	return func(u *authz.User) { u.OrgID = orgID; u.OrgRole = orgRole }
}

// WithACR sets the ACR.
func WithACR(acr string) Option { return func(u *authz.User) { u.ACR = acr } }

// WithImpersonator marks the user as impersonated by actor.
func WithImpersonator(actor string) Option {
	return func(u *authz.User) { u.Actor = &authz.Actor{Subject: actor} }
}

// NewContext returns a context carrying an authz.User built from opts.
func NewContext(ctx context.Context, opts ...Option) context.Context {
	u := &authz.User{}
	for _, o := range opts {
		o(u)
	}
	return authz.WithUser(ctx, u)
}
