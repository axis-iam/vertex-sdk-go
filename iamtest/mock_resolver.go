package iamtest

import (
	"context"
	"sort"
)

// MockResolver is a deterministic authz.Resolver for unit tests.
type MockResolver struct {
	rolesToPerms map[string][]string
}

// NewMockResolver returns a fresh MockResolver with no mappings.
func NewMockResolver() *MockResolver {
	return &MockResolver{rolesToPerms: map[string][]string{}}
}

// Given maps role → perms. Chainable.
func (m *MockResolver) Given(role string, perms ...string) *MockResolver {
	m.rolesToPerms[role] = append([]string(nil), perms...)
	return m
}

// Resolve implements authz.Resolver. Returns the union of permissions for
// the requested roles, deduplicated + sorted for reproducibility.
func (m *MockResolver) Resolve(_ context.Context, _ string, roles []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range roles {
		for _, p := range m.rolesToPerms[r] {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}
