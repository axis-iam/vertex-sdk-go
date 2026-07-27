package authz

import "context"

// Resolver maps a (clientID, roles) tuple to the flat list of permissions
// the user holds. Implementations may cache, fall back or fail open.
type Resolver interface {
	Resolve(ctx context.Context, clientID string, roles []string) ([]string, error)
}

// ResolverFunc adapts a plain function into a Resolver.
type ResolverFunc func(ctx context.Context, clientID string, roles []string) ([]string, error)

// Resolve implements Resolver.
func (f ResolverFunc) Resolve(ctx context.Context, clientID string, roles []string) ([]string, error) {
	return f(ctx, clientID, roles)
}
