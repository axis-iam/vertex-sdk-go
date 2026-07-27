package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/axis-iam/vertex-sdk-go/authz"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
)

// ErrorResponder renders an error to the client. Applications can replace
// the default JSON responder to match their API conventions.
type ErrorResponder func(w http.ResponseWriter, r *http.Request, status int, code, message string)

// DefaultErrorResponder emits a small JSON payload.
func DefaultErrorResponder(w http.ResponseWriter, _ *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

// AuthConfig is the configuration for Auth.
type AuthConfig struct {
	Verifier  *iamjwt.Verifier
	Resolver  authz.Resolver
	ClientID  string
	Responder ErrorResponder
}

// Auth builds a middleware that validates the bearer JWT, resolves
// permissions, and injects an *authz.User into the request context.
func Auth(cfg AuthConfig) func(http.Handler) http.Handler {
	if cfg.Responder == nil {
		cfg.Responder = DefaultErrorResponder
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := BearerToken(r)
			if token == "" {
				cfg.Responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing bearer token")
				return
			}
			claims, err := cfg.Verifier.Verify(r.Context(), token)
			if err != nil {
				cfg.Responder(w, r, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
				return
			}
			clientID := cfg.ClientID
			if clientID == "" && claims.AppID != "" {
				clientID = claims.AppID
			}
			perms, err := cfg.Resolver.Resolve(r.Context(), clientID, claims.Roles)
			if err != nil {
				cfg.Responder(w, r, http.StatusForbidden, "FORBIDDEN", err.Error())
				return
			}
			u := &authz.User{
				Subject:     claims.Subject,
				AppID:       claims.AppID,
				Email:       claims.Email,
				OrgID:       claims.OrgID,
				OrgRole:     claims.OrgRole,
				WorkspaceID: claims.WorkspaceID,
				SessionID:   claims.SessionID,
				Roles:       claims.Roles,
				Permissions: perms,
				AMR:         claims.AMR,
				ACR:         claims.ACR,
				Claims:      claims.Extra,
			}
			if claims.Actor != nil {
				u.Actor = &authz.Actor{Subject: claims.Actor.Subject}
			}
			next.ServeHTTP(w, r.WithContext(authz.WithUser(r.Context(), u)))
		})
	}
}
