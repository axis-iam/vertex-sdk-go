package authz

import (
	"regexp"
	"strings"
)

var concretePermissionSegment = regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)

// PermissionKey is the canonical identifier for a permission — a pair of
// resource and action strings.
type PermissionKey struct {
	Resource string
	Action   string
}

// Authority returns the "resource:action" string form used on the wire.
func (k PermissionKey) Authority() string { return k.Resource + ":" + k.Action }

// String implements fmt.Stringer and returns the same as Authority.
func (k PermissionKey) String() string { return k.Authority() }

// IsZero reports whether the key is empty.
func (k PermissionKey) IsZero() bool { return k.Resource == "" && k.Action == "" }

// IsConcrete reports whether the key is a canonical non-wildcard declaration key.
func (k PermissionKey) IsConcrete() bool {
	return concretePermissionSegment.MatchString(k.Resource) && concretePermissionSegment.MatchString(k.Action)
}

// ParsePermission parses a "resource:action" string. Empty components and
// missing colons yield an error.
func ParsePermission(s string) (PermissionKey, error) {
	if strings.Count(s, ":") != 1 {
		return PermissionKey{}, &InvalidPermissionError{Raw: s}
	}
	idx := strings.Index(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return PermissionKey{}, &InvalidPermissionError{Raw: s}
	}
	return PermissionKey{Resource: s[:idx], Action: s[idx+1:]}, nil
}

// InvalidPermissionError is returned when a permission string is malformed.
type InvalidPermissionError struct{ Raw string }

func (e *InvalidPermissionError) Error() string {
	return "authz: invalid permission string: " + e.Raw
}

// PermissionDefinition is a permission declaration — the registered form
// uploaded to the IAM server and referenced by codegen.
type PermissionDefinition struct {
	Resource    string
	Action      string
	Description string
}

// Key returns the PermissionKey corresponding to this definition.
func (d PermissionDefinition) Key() PermissionKey {
	return PermissionKey{Resource: d.Resource, Action: d.Action}
}

// Matches reports whether a granted permission string satisfies the target.
// Matching rules (aligned with sdk-js / sdk-java):
//
//   - exact match: "orders:read" matches "orders:read"
//   - action wildcard: "orders:*" matches "orders:read" and "orders:create"
//   - full wildcard: "*:*" matches everything
//   - resource-agnostic action wildcard "*:read" is rejected
//   - malformed or non-canonical entries never match
//   - matching is case sensitive
func Matches(target PermissionKey, granted string) bool {
	if !target.IsConcrete() {
		return false
	}
	gk, err := ParsePermission(granted)
	if err != nil {
		return false
	}
	if gk.Resource == "*" {
		return gk.Action == "*"
	}
	if !concretePermissionSegment.MatchString(gk.Resource) {
		return false
	}
	if gk.Action == "*" {
		return gk.Resource == target.Resource
	}
	return concretePermissionSegment.MatchString(gk.Action) && gk == target
}

// HasPermission reports whether any of the granted permission strings
// satisfies target.
func HasPermission(target PermissionKey, granted []string) bool {
	for _, g := range granted {
		if Matches(target, g) {
			return true
		}
	}
	return false
}

// HasAllPermissions reports whether every target is satisfied by granted.
func HasAllPermissions(targets []PermissionKey, granted []string) bool {
	for _, t := range targets {
		if !HasPermission(t, granted) {
			return false
		}
	}
	return len(targets) > 0
}

// HasAnyPermission reports whether at least one target is satisfied by granted.
func HasAnyPermission(targets []PermissionKey, granted []string) bool {
	for _, t := range targets {
		if HasPermission(t, granted) {
			return true
		}
	}
	return false
}
