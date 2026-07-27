package iamjwt

import (
	jwt "github.com/go-jose/go-jose/v4/jwt"
)

// Claims is the union of IAM-specific JWT fields overlaid on the standard
// registered claims (iss, aud, sub, exp, ...).
type Claims struct {
	jwt.Claims
	AppID       string   `json:"app_id,omitempty"`
	Email       string   `json:"email,omitempty"`
	WorkspaceID string   `json:"workspace_id,omitempty"`
	OrgID       string   `json:"org_id,omitempty"`
	OrgSlug     string   `json:"org_slug,omitempty"`
	OrgRole     string   `json:"org_role,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	AMR         []string `json:"amr,omitempty"`
	ACR         string   `json:"acr,omitempty"`
	SessionID   string   `json:"sid,omitempty"`
	Actor       *Actor   `json:"act,omitempty"`
	Extra       map[string]any `json:"-"`
}

// Actor is the JWT act claim for delegated/impersonated sessions.
type Actor struct {
	Subject string `json:"sub"`
}
