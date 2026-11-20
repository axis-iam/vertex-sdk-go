package websession

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/axis-iam/vertex-sdk-go/authz"
)

// Binding is the single owner of the browser's host-session identity. Native
// session bridges store the SDK handle in a dedicated server-side namespace and
// must rotate/fence it atomically; they must never auto-save token snapshots.
// Read must distinguish absent ("",nil) from an unavailable host store.
// Write and Clear preserve unrelated host session fields. A bridge must not be
// combined with a second session Cookie owner.
// Clear must clear browser authentication Cookie state even when returning a
// server-side storage error; failure to change that namespace is reported as
// local UNCONFIRMED. It must not rely on a successful storage write to clear it.
type Binding interface {
	Read(ctx context.Context, r *http.Request) (string, error)
	Write(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, expires time.Time) error
	Clear(ctx context.Context, w http.ResponseWriter, r *http.Request) error
}

type CookieOptions struct {
	Origin            string
	Name              string
	AllowLoopbackHTTP bool
}
type CookieBinding struct {
	name   string
	secure bool
}

func urlQuery(r *http.Request) (url.Values, error) { return url.ParseQuery(r.URL.RawQuery) }

func NewCookieBinding(opts CookieOptions) (*CookieBinding, error) {
	u, ok := validURL(opts.Origin, opts.AllowLoopbackHTTP)
	if !ok || u.Path != "" {
		return nil, invalid()
	}
	secure := u.Scheme == "https"
	if opts.Name == "" {
		opts.Name = "__Host-axis-session"
		if !secure {
			opts.Name = "axis-session-dev"
		}
	}
	if strings.ContainsAny(opts.Name, ";= \t\r\n") || opts.Name == "" ||
		(!secure && (strings.HasPrefix(opts.Name, "__Host-") || strings.HasPrefix(opts.Name, "__Secure-"))) {
		return nil, invalid()
	}
	if (&http.Cookie{Name: opts.Name, Value: "valid"}).Valid() != nil {
		return nil, invalid()
	}
	return &CookieBinding{name: opts.Name, secure: secure}, nil
}

func (b *CookieBinding) Read(ctx context.Context, r *http.Request) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	id := ""
	found := false
	for _, c := range r.Cookies() {
		if c.Name != b.name {
			continue
		}
		if found || !randomValue(c.Value) {
			return "", invalid()
		}
		id, found = c.Value, true
	}
	return id, nil
}
func (b *CookieBinding) Write(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, expires time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !randomValue(id) {
		return invalid()
	}
	http.SetCookie(w, &http.Cookie{Name: b.name, Value: id, Path: "/", HttpOnly: true, Secure: b.secure, SameSite: http.SameSiteLaxMode, Expires: expires})
	return nil
}
func (b *CookieBinding) Clear(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, &http.Cookie{Name: b.name, Value: "", Path: "/", HttpOnly: true, Secure: b.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	return nil
}

type contextKey struct{}
type requestIdentity struct {
	id      string
	session View
}

// FromContext reads an isolated, already verified session without network I/O.
func FromContext(ctx context.Context) *View {
	x, ok := ctx.Value(contextKey{}).(requestIdentity)
	if !ok {
		return nil
	}
	data, err := json.Marshal(x.session)
	if err != nil {
		return nil
	}
	var v View
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	return &v
}

func withIdentity(r *http.Request, id string, v View) *http.Request {
	c := v.Profile.AuthenticationContext
	u := &authz.User{Subject: v.Profile.ID, AppID: c.ApplicationID, SessionID: c.SessionID,
		Roles: append([]string(nil), v.Permissions.Roles...), Permissions: append([]string(nil), v.Permissions.Permissions...),
		AMR: append([]string(nil), c.AuthenticationMethods...)}
	if c.OrganizationID != nil {
		u.OrgID = *c.OrganizationID
	}
	if c.OrganizationRole != nil {
		u.OrgRole = *c.OrganizationRole
	}
	if c.WorkspaceID != nil {
		u.WorkspaceID = *c.WorkspaceID
	}
	if c.AssuranceLevel != nil {
		u.ACR = *c.AssuranceLevel
	}
	if v.Profile.Email != nil {
		u.Email = *v.Profile.Email
	}
	if c.Impersonation != nil {
		u.Actor = &authz.Actor{Subject: c.Impersonation.ActorID}
	}
	ctx := context.WithValue(r.Context(), contextKey{}, requestIdentity{id: id, session: v})
	return r.WithContext(authz.WithUser(ctx, u))
}

func explicitCredential(r *http.Request) bool {
	return len(r.Header.Values("Authorization")) > 0 || len(r.Header.Values("X-API-Key")) > 0
}

// Middleware protects only explicitly mounted business endpoints. Mixing a
// submitted Bearer/API key with Cookie auth is rejected; hosts choose their
// credential routing before this middleware rather than falling back on error.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if explicitCredential(r) {
			s.writeError(w, failure(400, "SESSION_CREDENTIAL_CONFLICT", ErrValidation), nil)
			return
		}
		id, err := s.cfg.Binding.Read(r.Context(), r)
		if err != nil {
			s.writeError(w, storeError(err), nil)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if err := s.csrf(r.Context(), r, id); err != nil {
				s.writeError(w, err, nil)
				return
			}
		}
		if previous, ok := r.Context().Value(contextKey{}).(requestIdentity); ok && previous.id == id {
			next.ServeHTTP(w, r)
			return
		}
		v, err := s.Authenticate(r.Context(), id)
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		next.ServeHTTP(w, withIdentity(r, id, v))
	})
}

func (s *Service) csrf(ctx context.Context, r *http.Request, id string) error {
	origins, tokens := r.Header.Values("Origin"), r.Header.Values("X-CSRF-Token")
	if len(origins) != 1 || origins[0] != s.cfg.Origin || len(tokens) != 1 {
		return failure(403, "SESSION_CSRF_INVALID", ErrForbidden)
	}
	record, err := s.load(ctx, id)
	if err != nil {
		return err
	}
	if !randomValue(tokens[0]) || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(record.CSRF)) != 1 {
		return failure(403, "SESSION_CSRF_INVALID", ErrForbidden)
	}
	return nil
}

func readBody(r *http.Request, out any) error {
	if ct := strings.Split(r.Header.Get("Content-Type"), ";")[0]; ct != "application/json" {
		return invalid()
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(data) > 65536 || strings.TrimSpace(string(data)) == "null" || decode(data, out, true) != nil {
		return invalid()
	}
	return nil
}

func (s *Service) writeJSON(w http.ResponseWriter, status int, out any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(out) // A disconnected browser cannot undo a committed operation.
}

func (s *Service) writeError(w http.ResponseWriter, err error, details any) {
	e := &Error{Code: "IAM_UNAVAILABLE", Status: 503, Cause: ErrUnavailable}
	_ = errors.As(err, &e)
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	body := map[string]any{"status": e.Status, "error": e.Code, "message": e.Code, "timestamp": s.cfg.Clock().UTC()}
	if details != nil {
		body["details"] = details
	}
	s.writeJSON(w, e.Status, body)
}

// Handler serves the finite C0 host routes beneath BasePath. Mount the same
// instance on any supported framework. It never proxies business URLs.
func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.AuthBudget)
	defer cancel()
	r = r.WithContext(ctx)
	if explicitCredential(r) {
		s.writeError(w, failure(400, "SESSION_CREDENTIAL_CONFLICT", ErrValidation), nil)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, s.cfg.BasePath)
	if path == r.URL.Path || strings.Contains(r.URL.EscapedPath(), "%") {
		http.NotFound(w, r)
		return
	}
	id, err := s.cfg.Binding.Read(ctx, r)
	if err != nil {
		s.writeError(w, storeError(err), nil)
		return
	}
	if r.Method == "POST" {
		if err := s.csrf(ctx, r, id); err != nil {
			s.writeError(w, err, nil)
			return
		}
	} else if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	if r.Method == "GET" && path != "/callback" && path != "/login" && r.URL.RawQuery != "" {
		s.writeError(w, invalid(), nil)
		return
	}
	if r.Method == "POST" && r.URL.RawQuery != "" {
		s.writeError(w, invalid(), nil)
		return
	}
	writeView := func(next string, v View, err error) {
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		if next != "" && next != id {
			if err := s.cfg.Binding.Write(ctx, w, r, next, v.ExpiresAt); err != nil {
				_ = s.terminate(next)
				s.writeError(w, storeError(err), nil)
				return
			}
		}
		s.writeJSON(w, 200, v)
	}
	switch {
	case r.Method == "GET" && path == "/session/bootstrap":
		next, v, err := s.Bootstrap(ctx, id)
		writeView(next, v, err)
	case r.Method == "GET" && path == "/session":
		record, err := s.load(ctx, id)
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		if record.Kind == "session" {
			v, err := s.Authenticate(ctx, id)
			writeView("", v, err)
		} else {
			writeView("", view(record), nil)
		}
	case r.Method == "GET" && path == "/login":
		q, err := urlQuery(r)
		if err != nil || len(q) > 1 || (len(q) == 1 && len(q["returnTo"]) != 1) {
			s.writeError(w, invalid(), nil)
			return
		}
		target, err := s.Hosted(ctx, id, q.Get("returnTo"))
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		http.Redirect(w, r, target, 302)
	case r.Method == "GET" && path == "/callback":
		q, err := urlQuery(r)
		if err != nil {
			s.writeError(w, invalid(), nil)
			return
		}
		next, v, target, err := s.Callback(ctx, id, q)
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		if next != "" && next != id {
			if err := s.cfg.Binding.Write(ctx, w, r, next, v.ExpiresAt); err != nil {
				_ = s.terminate(next)
				s.writeError(w, storeError(err), nil)
				return
			}
		}
		http.Redirect(w, r, target, 302)
	case r.Method == "POST" && path == "/session/login":
		var empty struct{}
		if err := readBody(r, &empty); err != nil {
			s.writeError(w, err, nil)
			return
		}
		v, err := s.Login(ctx, id)
		writeView("", v, err)
	case r.Method == "POST" && strings.HasPrefix(path, "/session/login/"):
		action := strings.TrimPrefix(path, "/session/login/")
		var input any
		switch action {
		case "authenticate":
			input = &AuthenticateInput{}
		case "challenges":
			input = &ChallengeInput{}
		case "authorize":
			input = &ProviderInput{}
		case "mfa":
			input = &MFAInput{}
		case "magic":
			input = &MagicInput{}
		case "complete", "cancel":
			input = &struct{}{}
		default:
			http.NotFound(w, r)
			return
		}
		if err := readBody(r, input); err != nil {
			s.writeError(w, err, nil)
			return
		}
		switch v := input.(type) {
		case *AuthenticateInput:
			input = *v
		case *ChallengeInput:
			input = *v
		case *ProviderInput:
			input = *v
		case *MFAInput:
			input = *v
		case *MagicInput:
			input = *v
		default:
			input = nil
		}
		next, v, err := s.Action(ctx, id, action, input)
		writeView(next, v, err)
	case r.Method == "POST" && path == "/session/logout":
		var empty struct{}
		if err := readBody(r, &empty); err != nil {
			s.writeError(w, err, nil)
			return
		}
		clearErr := s.cfg.Binding.Clear(ctx, w, r)
		result, err := s.Logout(ctx, id)
		if clearErr != nil {
			err = storeError(clearErr)
			result.Local = "UNCONFIRMED"
		}
		if err != nil {
			s.writeError(w, err, result)
			return
		}
		s.writeJSON(w, 200, result)
	case r.Method == "GET" && (path == "/auth-methods" || path == "/auth-policy"):
		out, err := s.PublicConfig(ctx, path[1:])
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		s.writeJSON(w, 200, out)
	case r.Method == "POST" && path == "/registration":
		var input SignupInput
		if err := readBody(r, &input); err != nil {
			s.writeError(w, err, nil)
			return
		}
		out, status, err := s.Register(ctx, id, input)
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		s.writeJSON(w, status, out)
	case strings.HasPrefix(path, "/registration/"):
		parts := strings.Split(strings.TrimPrefix(path, "/registration/"), "/")
		if !randomValue(parts[0]) || len(parts) > 2 {
			http.NotFound(w, r)
			return
		}
		action, code := "get", ""
		if len(parts) == 2 {
			action = parts[1]
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			if action == "complete" {
				var input struct {
					Code string `json:"code"`
				}
				if err := readBody(r, &input); err != nil {
					s.writeError(w, err, nil)
					return
				}
				code = input.Code
			} else {
				var empty struct{}
				if err := readBody(r, &empty); err != nil {
					s.writeError(w, err, nil)
					return
				}
			}
		} else if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		out, err := s.RegistrationAction(ctx, id, parts[0], action, code)
		if err != nil {
			s.writeError(w, err, nil)
			return
		}
		s.writeJSON(w, 200, out)
	case r.Method == "POST" && path == "/password-reset/request":
		var input struct {
			Email string `json:"email"`
		}
		if err := readBody(r, &input); err != nil {
			s.writeError(w, err, nil)
			return
		}
		if err := s.RequestPasswordReset(ctx, input.Email); err != nil {
			s.writeError(w, err, nil)
			return
		}
		w.WriteHeader(204)
	case r.Method == "POST" && path == "/password-reset/complete":
		var input struct {
			Token       string `json:"token"`
			NewPassword string `json:"newPassword"`
		}
		if err := readBody(r, &input); err != nil {
			s.writeError(w, err, nil)
			return
		}
		if err := s.ResetPassword(ctx, input.Token, input.NewPassword); err != nil {
			s.writeError(w, err, nil)
			return
		}
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}
