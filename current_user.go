package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CurrentUser is the safe authenticated /me view. Metadata is never authorization.
type CurrentUser struct {
	ID                    string                     `json:"id"`
	Email                 *string                    `json:"email"`
	Username              *string                    `json:"username"`
	Status                string                     `json:"status"`
	EmailVerified         bool                       `json:"emailVerified"`
	AuthenticationContext AuthenticationContext      `json:"authenticationContext"`
	Metadata              map[string]json.RawMessage `json:"metadata"`
}

type ImpersonationContext struct {
	ActorID         string `json:"actorId"`
	ImpersonationID string `json:"impersonationId"`
}

type AuthenticationContext struct {
	SubjectType                string                `json:"subjectType"`
	ApplicationID              string                `json:"applicationId"`
	ClientID                   string                `json:"clientId"`
	SessionID                  string                `json:"sessionId"`
	WorkspaceID                *string               `json:"workspaceId"`
	WorkspaceSelectionRequired bool                  `json:"workspaceSelectionRequired"`
	OrganizationID             *string               `json:"organizationId"`
	OrganizationSlug           *string               `json:"organizationSlug"`
	OrganizationRole           *string               `json:"organizationRole"`
	AuthTime                   *time.Time            `json:"authTime"`
	AuthenticationMethods      []string              `json:"authenticationMethods"`
	AssuranceLevel             *string               `json:"assuranceLevel"`
	Impersonation              *ImpersonationContext `json:"impersonation"`
}

// CurrentUserError exposes HTTP status without reflecting upstream diagnostics.
type CurrentUserError struct{ Status int }

func (e *CurrentUserError) Error() string {
	return fmt.Sprintf("iam: current-user request failed: HTTP %d", e.Status)
}

// GetCurrentUser reads context explicitly with a user bearer. It does not resolve or verify token bytes locally.
func (c *Client) GetCurrentUser(ctx context.Context, accessToken string) (*CurrentUser, error) {
	token := normalizeBearer(accessToken)
	if token == "" {
		return nil, errors.New("iam: access token is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint()+"/api/v1/auth/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("iam: current-user transport failed")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &CurrentUserError{Status: res.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 1048577))
	if err != nil || len(data) > 1048576 {
		return nil, errors.New("iam: invalid current-user response")
	}
	return ParseCurrentUser(data)
}

// ParseCurrentUser rejects absent and malformed bindings; nullable fields must be explicitly present.
func ParseCurrentUser(data []byte) (*CurrentUser, error) {
	invalid := errors.New("iam: invalid current-user view")
	var root map[string]json.RawMessage
	var out CurrentUser
	if json.Unmarshal(data, &root) != nil || json.Unmarshal(data, &out) != nil {
		return nil, invalid
	}
	required := func(m map[string]json.RawMessage, keys ...string) bool {
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				return false
			}
		}
		return true
	}
	if !required(root, "id", "email", "username", "status", "emailVerified", "authenticationContext", "metadata") || string(root["emailVerified"]) == "null" || out.Metadata == nil {
		return nil, invalid
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(root["authenticationContext"], &raw) != nil || !required(raw, "subjectType", "applicationId", "clientId", "sessionId", "workspaceId", "workspaceSelectionRequired", "organizationId", "organizationSlug", "organizationRole", "authTime", "authenticationMethods", "assuranceLevel", "impersonation") || string(raw["workspaceSelectionRequired"]) == "null" {
		return nil, invalid
	}
	c := out.AuthenticationContext
	if c.SubjectType != "USER" || strings.TrimSpace(out.ID) == "" || strings.TrimSpace(out.Status) == "" || strings.TrimSpace(c.ApplicationID) == "" || strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.SessionID) == "" || c.AuthenticationMethods == nil {
		return nil, invalid
	}
	for _, s := range c.AuthenticationMethods {
		if strings.TrimSpace(s) == "" {
			return nil, invalid
		}
	}
	for _, s := range []*string{out.Email, out.Username, c.WorkspaceID, c.OrganizationID, c.OrganizationSlug, c.OrganizationRole, c.AssuranceLevel} {
		if s != nil && strings.TrimSpace(*s) == "" {
			return nil, invalid
		}
	}
	if (c.WorkspaceSelectionRequired && c.WorkspaceID != nil) || (c.OrganizationID == nil && (c.OrganizationSlug != nil || c.OrganizationRole != nil)) {
		return nil, invalid
	}
	if c.Impersonation != nil && (strings.TrimSpace(c.Impersonation.ActorID) == "" || strings.TrimSpace(c.Impersonation.ImpersonationID) == "") {
		return nil, invalid
	}
	return &out, nil
}
