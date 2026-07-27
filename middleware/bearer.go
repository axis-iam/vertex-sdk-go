package middleware

import (
	"net/http"
	"strings"
)

// BearerToken extracts the bearer token from the Authorization header, or
// returns the empty string.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
