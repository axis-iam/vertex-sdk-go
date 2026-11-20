package websession

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AuthenticateInput struct {
	Method     string     `json:"method"`
	Identifier Identifier `json:"identifier"`
	Password   string     `json:"password,omitempty"`
	Proof      string     `json:"proof,omitempty"`
}
type ChallengeInput struct {
	Method     string     `json:"method"`
	Identifier Identifier `json:"identifier"`
}
type ProviderInput struct {
	ProviderID             string `json:"providerId"`
	RegistrationGrantToken string `json:"registrationGrantToken,omitempty"`
	RegistrationAccessCode string `json:"registrationAccessCode,omitempty"`
}
type MFAInput struct {
	Method string `json:"method"`
	Code   string `json:"code"`
}
type MagicInput struct {
	TransactionID string `json:"transactionId"`
	State         string `json:"state"`
	Proof         string `json:"proof"`
}

func (i Identifier) valid() bool {
	return contains([]string{"EMAIL", "USERNAME", "PHONE"}, i.Kind) && strings.TrimSpace(i.Value) != "" &&
		len(i.Value) <= 1024 && (i.Region == nil || (i.Kind == "PHONE" && len(*i.Region) == 2))
}

type transactionResponse struct {
	TransactionID      string     `json:"transactionId"`
	ControlSecret      string     `json:"controlSecret"`
	State              string     `json:"state"`
	ExpiresAt          time.Time  `json:"expiresAt"`
	NextAction         string     `json:"nextAction"`
	ChallengeExpiresAt *time.Time `json:"challengeExpiresAt"`
	CooldownSeconds    *int       `json:"cooldownSeconds"`
	AuthorizationURL   string     `json:"authorizationUrl"`
	Kind               string     `json:"kind"`
	Code               string     `json:"code"`
	OAuthState         string     `json:"stateBinding"` // complete decodes its exact state separately
}

var stateActions = map[string]string{
	"AUTHENTICATING": "authenticate", "AWAITING_PROVIDER": "authorize", "MFA_REQUIRED": "mfa",
	"AUTHENTICATED": "complete", "COMPLETED": "none", "CANCELLED": "none", "EXPIRED": "none", "REJECTED": "none",
}

// Login creates a custom transaction; proof collection alone cannot set a user.
func (s *Service) Login(ctx context.Context, id string) (View, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return View{}, err
	}
	if r.Kind != "prelogin" || r.TransactionID != "" || r.OAuthState != "" {
		return View{}, failure(409, "SESSION_ACTION_PENDING", ErrConflict)
	}
	r, err = s.own(ctx, id, "create", r)
	if err != nil {
		return View{}, err
	}
	r.OAuthState, r.Verifier, r.Nonce, r.ReturnTo = random(), random(), random(), s.cfg.ReturnTo
	// Persist the new binding before sending the create request.
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		return View{}, storeError(err)
	}
	r, err = s.intent(ctx, id, r)
	if err != nil {
		return View{}, err
	}
	body := map[string]string{"client_id": s.cfg.ClientID, "entryMode": "CUSTOM", "redirect_uri": s.cfg.CallbackURL,
		"scope": strings.Join(s.cfg.Scopes, " "), "state": r.OAuthState, "code_challenge": challenge(r.Verifier),
		"code_challenge_method": "S256", "nonce": r.Nonce}
	var response transactionResponse
	err = s.request(ctx, "POST", "/api/v1/auth/transactions", body, "", nil, &response, false)
	if err != nil {
		_ = s.terminate(id)
		return View{}, err
	}
	if !uuidPattern.MatchString(response.TransactionID) || response.ControlSecret == "" {
		_ = s.terminate(id)
		return View{}, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	r.TransactionID, r.ControlSecret = response.TransactionID, response.ControlSecret
	return s.commitTransaction(ctx, id, r, response, true)
}

func (s *Service) commitTransaction(ctx context.Context, id string, r Record, response transactionResponse, created bool) (View, error) {
	if response.TransactionID != r.TransactionID || response.ExpiresAt.IsZero() ||
		!s.cfg.Clock().Before(response.ExpiresAt) || (response.CooldownSeconds != nil && *response.CooldownSeconds < 0) {
		_ = s.terminate(id)
		return View{}, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	state := response.State
	if created && state == "" {
		for st, action := range stateActions {
			if response.NextAction == action && action != "none" {
				state = st
				break
			}
		}
	}
	if state == "" {
		state = r.LoginState
	} // challenge response has no state
	expected, ok := stateActions[state]
	if !ok || response.NextAction != expected {
		_ = s.terminate(id)
		return View{}, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	r.State, r.LoginState, r.NextAction = Prelogin, state, response.NextAction
	r.AbsoluteExpiresAt = minTime(r.AbsoluteExpiresAt, response.ExpiresAt)
	r.IdleExpiresAt = r.AbsoluteExpiresAt
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		_ = s.terminate(id)
		return View{}, storeError(err)
	}
	v := view(r)
	v.ChallengeExpiresAt, v.CooldownSeconds = response.ChallengeExpiresAt, response.CooldownSeconds
	if state == "CANCELLED" || state == "EXPIRED" || state == "REJECTED" || state == "COMPLETED" {
		if err := s.terminate(id); err != nil {
			return View{}, storeError(err)
		}
	}
	return v, nil
}

// Action advances only the finite C0 login surface. It returns a replacement
// binding only after a completed code exchange.
func (s *Service) Action(ctx context.Context, id, action string, input any) (string, View, error) {
	return s.action(ctx, id, action, input)
}

func (s *Service) action(ctx context.Context, id, action string, input any) (string, View, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.AuthBudget)
	defer cancel()
	r, err := s.load(ctx, id)
	if err != nil {
		return "", View{}, err
	}
	if r.Kind != "prelogin" || r.TransactionID == "" {
		return "", View{}, invalid()
	}
	body := input
	switch action {
	case "authenticate":
		x, ok := input.(AuthenticateInput)
		if !ok || !x.Identifier.valid() {
			return "", View{}, invalid()
		}
		if x.Method == "PASSWORD" {
			if strings.TrimSpace(x.Password) == "" || len(x.Password) > 1024 || x.Proof != "" {
				return "", View{}, invalid()
			}
		} else if !contains([]string{"EMAIL_OTP", "SMS_OTP", "EMAIL_MAGIC_LINK"}, x.Method) ||
			strings.TrimSpace(x.Proof) == "" || len(x.Proof) > 128 || x.Password != "" {
			return "", View{}, invalid()
		}
		if (x.Method == "EMAIL_OTP" || x.Method == "EMAIL_MAGIC_LINK") && x.Identifier.Kind != "EMAIL" ||
			x.Method == "SMS_OTP" && x.Identifier.Kind != "PHONE" {
			return "", View{}, invalid()
		}
		r.Identifier = &x.Identifier
	case "challenges":
		x, ok := input.(ChallengeInput)
		if !ok || !x.Identifier.valid() || !contains([]string{"EMAIL_OTP", "SMS_OTP", "EMAIL_MAGIC_LINK"}, x.Method) ||
			((x.Method == "EMAIL_OTP" || x.Method == "EMAIL_MAGIC_LINK") && x.Identifier.Kind != "EMAIL") ||
			(x.Method == "SMS_OTP" && x.Identifier.Kind != "PHONE") {
			return "", View{}, invalid()
		}
		r.Identifier = &x.Identifier
	case "authorize":
		x, ok := input.(ProviderInput)
		if !ok || !uuidPattern.MatchString(x.ProviderID) || (x.RegistrationGrantToken != "" && x.RegistrationAccessCode != "") ||
			len(x.RegistrationGrantToken) > 2048 || len(x.RegistrationAccessCode) > 128 {
			return "", View{}, invalid()
		}
	case "mfa":
		x, ok := input.(MFAInput)
		if !ok || !contains([]string{"TOTP", "RECOVERY_CODE"}, x.Method) || strings.TrimSpace(x.Code) == "" || len(x.Code) > 128 {
			return "", View{}, invalid()
		}
	case "magic":
		x, ok := input.(MagicInput)
		if !ok || x.TransactionID != r.TransactionID || x.State != r.OAuthState || r.Identifier == nil ||
			r.Identifier.Kind != "EMAIL" || r.MagicConsumed || strings.TrimSpace(x.Proof) == "" || len(x.Proof) > 128 {
			return "", View{}, invalid()
		}
		r.MagicConsumed = true
		body = AuthenticateInput{Method: "EMAIL_MAGIC_LINK", Identifier: *r.Identifier, Proof: x.Proof}
	case "complete", "cancel", "get":
		if input != nil {
			return "", View{}, invalid()
		}
		body = struct{}{}
	default:
		return "", View{}, invalid()
	}
	r, err = s.own(ctx, id, "transaction:"+action, r)
	if err != nil {
		return "", View{}, err
	}
	// Completion performs a code request then exchange under the same fence;
	// persisting intent also prevents expired owners from duplicating proofs.
	if action != "get" {
		r, err = s.intent(ctx, id, r)
		if err != nil {
			return "", View{}, err
		}
	}
	headers := http.Header{"Authentication-Transaction": {r.ControlSecret}, "Idempotency-Key": {r.Fence}}
	path := "/api/v1/auth/transactions/" + url.PathEscape(r.TransactionID)
	method := "POST"
	suffix := action
	if action == "magic" {
		suffix = "authenticate"
	}
	if action == "get" {
		method = "GET"
		body = nil
	} else {
		path += "/" + suffix
	}
	if action == "complete" {
		var completed struct {
			Kind      string `json:"kind"`
			Code      string `json:"code"`
			State     string `json:"state"`
			ExpiresIn *int   `json:"expiresIn"`
		}
		if err := s.request(ctx, method, path, body, "", headers, &completed, false); err != nil {
			_ = s.terminate(id)
			return "", View{}, err
		}
		if completed.Kind != "authorization_code" || completed.Code == "" || completed.State != r.OAuthState ||
			completed.ExpiresIn == nil || *completed.ExpiresIn < 0 {
			_ = s.terminate(id)
			return "", View{}, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
		return s.exchange(ctx, id, completed.Code, r)
	}
	if action == "authorize" {
		var response struct {
			URL       string    `json:"authorizationUrl"`
			ExpiresAt time.Time `json:"expiresAt"`
		}
		if err := s.request(ctx, method, path, body, "", headers, &response, false); err != nil {
			return "", View{}, s.releaseAction(ctx, id, r, err)
		}
		u, err := url.Parse(response.URL)
		// Provider navigation may be external HTTPS; credentials/fragments reject.
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && !(s.cfg.AllowLoopbackHTTP && sameOrigin(response.URL, s.cfg.Issuer))) ||
			!s.cfg.Clock().Before(response.ExpiresAt) {
			_ = s.terminate(id)
			return "", View{}, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
		r.State, r.LoginState, r.NextAction = Prelogin, "AWAITING_PROVIDER", "authorize"
		r.Version++
		if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
			return "", View{}, storeError(err)
		}
		v := view(r)
		v.AuthorizationURL = response.URL
		return "", v, nil
	}
	var response transactionResponse
	if err := s.request(ctx, method, path, body, "", headers, &response, false); err != nil {
		return "", View{}, s.releaseAction(ctx, id, r, err)
	}
	v, err := s.commitTransaction(ctx, id, r, response, false)
	return "", v, err
}

func (s *Service) transaction(ctx context.Context, id, action string, input any) (View, error) {
	_, v, err := s.action(ctx, id, action, input)
	return v, err
}

func (s *Service) releaseAction(ctx context.Context, id string, r Record, upstream error) error {
	if errors.Is(upstream, ErrUnavailable) || ctx.Err() != nil {
		_ = s.terminate(id)
		return upstream
	}
	r.State = Prelogin
	if r.Kind == "session" {
		r.State = SignedIn
	}
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		return storeError(err)
	}
	return upstream
}

func sameOrigin(a, b string) bool {
	x, err := url.Parse(a)
	if err != nil {
		return false
	}
	y, err := url.Parse(b)
	return err == nil && x.Scheme == y.Scheme && x.Host == y.Host
}
