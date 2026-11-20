package websession

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SignupInput struct {
	Identifier                  Identifier `json:"identifier"`
	Password                    string     `json:"password"`
	UILocales                   *string    `json:"uiLocales,omitempty"`
	RegistrationGrantToken      string     `json:"registrationGrantToken,omitempty"`
	RegistrationAccessCode      string     `json:"registrationAccessCode,omitempty"`
	OrganizationInvitationToken string     `json:"organizationInvitationToken,omitempty"`
}

type RegistrationView struct {
	RegistrationID  string     `json:"registrationId"`
	Status          string     `json:"status"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	NextAction      string     `json:"nextAction"`
	NextChallengeAt *time.Time `json:"nextChallengeAt"`
}
type registrationResponse struct {
	RegistrationView
	ControlSecret string `json:"controlSecret"`
}

// Register binds registration control to an opaque local reference. It never
// promotes a registration response into an authenticated application session.
func (s *Service) Register(ctx context.Context, id string, input SignupInput) (RegistrationView, int, error) {
	if !input.Identifier.valid() || strings.TrimSpace(input.Password) == "" || len(input.Password) > 128 ||
		(input.RegistrationGrantToken != "" && input.RegistrationAccessCode != "") ||
		len(input.RegistrationGrantToken) > 2048 || len(input.RegistrationAccessCode) > 128 {
		return RegistrationView{}, 0, invalid()
	}
	r, err := s.load(ctx, id)
	if err != nil {
		return RegistrationView{}, 0, err
	}
	r, err = s.own(ctx, id, "registration", r)
	if err != nil {
		return RegistrationView{}, 0, err
	}
	var response registrationResponse
	body := struct {
		SignupInput
		ClientID string `json:"client_id"`
	}{input, s.cfg.ClientID}
	if err := s.request(ctx, "POST", "/api/v1/auth/signup", body, "", http.Header{"Idempotency-Key": {r.Fence}}, &response, false); err != nil {
		return RegistrationView{}, 0, s.releaseAction(ctx, id, r, err)
	}
	if !uuidPattern.MatchString(response.RegistrationID) || response.Status == "" || response.NextAction == "" ||
		response.ExpiresAt.IsZero() {
		_ = s.terminate(id)
		return RegistrationView{}, 0, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	ref := random()
	if r.Registrations == nil {
		r.Registrations = map[string]Registration{}
	}
	for key, x := range r.Registrations {
		if !s.cfg.Clock().Before(x.ExpiresAt) {
			delete(r.Registrations, key)
		}
	}
	r.Registrations[ref] = Registration{ID: response.RegistrationID, ControlSecret: response.ControlSecret, ExpiresAt: response.ExpiresAt}
	r.State = Prelogin
	if r.Kind == "session" {
		r.State = SignedIn
	}
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		_ = s.terminate(id)
		return RegistrationView{}, 0, storeError(err)
	}
	response.RegistrationID = ref
	status := 201
	if response.Status == "PENDING_VERIFICATION" {
		if response.ControlSecret == "" {
			_ = s.terminate(id)
			return RegistrationView{}, 0, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
		status = 202
	}
	return response.RegistrationView, status, nil
}

func (s *Service) RegistrationAction(ctx context.Context, id, ref, action, code string) (RegistrationView, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return RegistrationView{}, err
	}
	reg, ok := r.Registrations[ref]
	if !ok || !s.cfg.Clock().Before(reg.ExpiresAt) || reg.ControlSecret == "" {
		return RegistrationView{}, invalid()
	}
	if !contains([]string{"get", "challenges", "complete", "cancel"}, action) || (action == "complete" && len(code) != 6) {
		return RegistrationView{}, invalid()
	}
	r, err = s.own(ctx, id, "registration:"+action, r)
	if err != nil {
		return RegistrationView{}, err
	}
	path := "/api/v1/auth/signup/operations/" + url.PathEscape(reg.ID)
	headers := http.Header{"Registration-Client": {s.cfg.ClientID}}
	method := "POST"
	var body any = map[string]string{"controlSecret": reg.ControlSecret}
	if action == "get" {
		method = "GET"
		body = nil
		headers.Set("Registration-Control", reg.ControlSecret)
	} else {
		path += "/" + action
	}
	if action == "complete" {
		body = map[string]string{"controlSecret": reg.ControlSecret, "code": code}
	}
	var response registrationResponse
	if err := s.request(ctx, method, path, body, "", headers, &response, false); err != nil {
		return RegistrationView{}, s.releaseAction(ctx, id, r, err)
	}
	if response.RegistrationID != reg.ID || response.Status == "" || response.ExpiresAt.IsZero() || response.NextAction == "" {
		_ = s.terminate(id)
		return RegistrationView{}, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	if response.Status != "PENDING_VERIFICATION" {
		delete(r.Registrations, ref)
	}
	r.State = Prelogin
	if r.Kind == "session" {
		r.State = SignedIn
	}
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		return RegistrationView{}, storeError(err)
	}
	response.RegistrationID = ref
	return response.RegistrationView, nil
}

// PublicConfig forwards only the two configured-client public DTOs.
func (s *Service) PublicConfig(ctx context.Context, kind string) (any, error) {
	if kind != "auth-methods" && kind != "auth-policy" {
		return nil, invalid()
	}
	var out map[string]any
	if err := s.request(ctx, "GET", "/api/v1/apps/"+url.PathEscape(s.cfg.ClientID)+"/"+kind, nil, "", nil, &out, false); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	return publicCapability(kind, out)
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	if strings.TrimSpace(email) == "" || len(email) > 320 {
		return invalid()
	}
	body := map[string]string{"email": email, "client_id": s.cfg.ClientID}
	if s.cfg.PasswordResetURL != "" {
		body["redirect_uri"] = s.cfg.PasswordResetURL
	}
	return s.request(ctx, "POST", "/api/v1/auth/password/forgot", body, "", nil, nil, false)
}

func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(password) == "" || len(password) > 128 {
		return invalid()
	}
	return s.request(ctx, "POST", "/api/v1/auth/password/reset", map[string]string{"token": token, "newPassword": password}, "",
		http.Header{"Password-Reset-Client": {s.cfg.ClientID}}, nil, false)
}
