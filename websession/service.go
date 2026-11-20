package websession

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	iam "github.com/axis-iam/vertex-sdk-go"
)

// View is the only browser session projection. It never contains OAuth or
// transaction credentials. A proof-complete login has NextAction "complete"
// and no Profile; it is not yet a signed-in application session.
type View struct {
	State              string           `json:"state"`
	ExpiresAt          time.Time        `json:"expiresAt"`
	CSRFToken          string           `json:"csrfToken"`
	Owner              string           `json:"owner,omitempty"`
	Version            *uint64          `json:"version,omitempty"`
	Profile            *iam.CurrentUser `json:"profile,omitempty"`
	Permissions        *Permissions     `json:"permissions,omitempty"`
	NextAction         string           `json:"nextAction,omitempty"`
	ChallengeExpiresAt *time.Time       `json:"challengeExpiresAt,omitempty"`
	CooldownSeconds    *int             `json:"cooldownSeconds,omitempty"`
	AuthorizationURL   string           `json:"authorizationUrl,omitempty"`
}

func view(r Record) View {
	r = clone(r)
	v := View{State: Prelogin, ExpiresAt: minTime(r.AbsoluteExpiresAt, r.IdleExpiresAt), CSRFToken: r.CSRF}
	if r.Kind == "session" {
		v.State, v.Owner, v.Version, v.Profile, v.Permissions = "AUTHENTICATED", r.Owner, &r.Version, r.Profile, r.Permissions
	} else if r.LoginState != "" {
		v.State, v.NextAction = r.LoginState, r.NextAction
	}
	return v
}

// ParseView validates C0 browser views, including explicit nullable profile
// fields and optional matching-context permission envelopes.
func ParseView(data []byte) (*View, error) {
	var raw map[string]json.RawMessage
	if decode(data, &raw, false) != nil {
		return nil, invalid()
	}
	allowed := map[string]bool{}
	for _, k := range []string{"state", "expiresAt", "csrfToken", "owner", "version", "profile", "permissions", "nextAction", "challengeExpiresAt", "cooldownSeconds", "authorizationUrl"} {
		allowed[k] = true
	}
	for k := range raw {
		if !allowed[k] {
			return nil, invalid()
		}
	}
	var v View
	// permissions can contain the IAM Application/Organization envelope.
	if decode(data, &v, false) != nil || !randomValue(v.CSRFToken) || v.ExpiresAt.IsZero() {
		return nil, invalid()
	}
	states := map[string]bool{Prelogin: true, "AUTHENTICATING": true, "AWAITING_PROVIDER": true, "MFA_REQUIRED": true, "AUTHENTICATED": true, "COMPLETED": true, "CANCELLED": true, "EXPIRED": true, "REJECTED": true}
	if !states[v.State] || (v.CooldownSeconds != nil && *v.CooldownSeconds < 0) {
		return nil, invalid()
	}
	if v.Profile == nil {
		if v.Owner != "" || v.Version != nil || v.Permissions != nil || (v.State == "AUTHENTICATED" && v.NextAction != "complete") {
			return nil, invalid()
		}
	} else {
		p, err := iam.ParseCurrentUser(raw["profile"])
		if err != nil || v.State != "AUTHENTICATED" || !randomValue(v.Owner) || v.Version == nil ||
			*v.Version > 9007199254740991 || v.Permissions == nil || v.Permissions.Roles == nil || v.Permissions.Permissions == nil {
			return nil, invalid()
		}
		var envelope map[string]json.RawMessage
		if decode(raw["permissions"], &envelope, false) != nil {
			return nil, invalid()
		}
		if app, ok := envelope["applicationId"]; ok {
			var a string
			var org *string
			if json.Unmarshal(app, &a) != nil || a != p.AuthenticationContext.ApplicationID ||
				envelope["organizationId"] == nil || json.Unmarshal(envelope["organizationId"], &org) != nil ||
				!equalOptional(org, p.AuthenticationContext.OrganizationID) {
				return nil, invalid()
			}
		}
		for _, k := range v.Permissions.Permissions {
			if !permissionPattern.MatchString(k) {
				return nil, invalid()
			}
		}
		v.Profile = p
	}
	return &v, nil
}

func (s *Service) load(ctx context.Context, id string) (Record, error) {
	if !randomValue(id) {
		return Record{}, failure(401, "SESSION_REQUIRED", ErrInvalidSession)
	}
	r, err := s.cfg.Provider.Load(ctx, id)
	if err != nil {
		return Record{}, storeError(err)
	}
	if r.SchemaVersion != SchemaVersion || r.ClientID != s.cfg.ClientID || expired(r, s.cfg.Clock()) || r.State == Invalidated {
		return Record{}, failure(401, "SESSION_INVALIDATED", ErrInvalidSession)
	}
	return r, nil
}

// Bootstrap returns a new binding only for known absent/expired state. Provider
// failures propagate; an outage is never converted into an anonymous success.
func (s *Service) Bootstrap(ctx context.Context, id string) (string, View, error) {
	if id != "" {
		r, err := s.load(ctx, id)
		if err == nil {
			if r.Kind == "session" {
				v, err := s.Authenticate(ctx, id)
				return id, v, err
			}
			return id, view(r), nil
		}
		if !errors.Is(err, ErrInvalidSession) {
			return "", View{}, err
		}
	}
	now := s.cfg.Clock()
	r := Record{SchemaVersion: SchemaVersion, Kind: "prelogin", State: Prelogin, ClientID: s.cfg.ClientID,
		CreatedAt: now, AbsoluteExpiresAt: now.Add(s.cfg.PreloginTTL), IdleExpiresAt: now.Add(s.cfg.PreloginTTL),
		Owner: random(), CSRF: random()}
	next := random()
	if err := s.cfg.Provider.Create(ctx, next, r); err != nil {
		return "", View{}, storeError(err)
	}
	return next, view(r), nil
}

func (s *Service) terminate(id string) error {
	// Cleanup must still fence a cancelled request. It is bounded independently.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.UpstreamTimeout)
	defer cancel()
	_, err := s.cfg.Provider.Invalidate(ctx, id)
	if errors.Is(err, ErrAbsent) {
		return nil
	}
	return err
}

func (s *Service) own(ctx context.Context, id, operation string, r Record) (Record, error) {
	now := s.cfg.Clock()
	if r.State == SendIntent {
		if now.Before(r.LeaseExpiresAt) {
			return Record{}, failure(409, "SESSION_ACTION_PENDING", ErrConflict)
		}
		_ = s.terminate(id) // SEND_INTENT itself fences retries even if cleanup fails.
		sentinel, code := ErrRefreshUncertain, "REFRESH_UNCERTAIN"
		if r.Kind == "prelogin" {
			sentinel, code = ErrExchangeUncertain, "AUTH_EXCHANGE_UNCERTAIN"
		}
		return Record{}, failure(401, code, sentinel)
	}
	if r.State == Owned && now.Before(r.LeaseExpiresAt) {
		return Record{}, failure(409, "SESSION_ACTION_PENDING", ErrConflict)
	}
	r.State, r.Operation, r.Fence, r.LeaseExpiresAt = Owned, operation, random(), now.Add(s.cfg.RefreshLease)
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		return Record{}, storeError(err)
	}
	return r, nil
}

func (s *Service) intent(ctx context.Context, id string, r Record) (Record, error) {
	if err := ctx.Err(); err != nil {
		r.State = SignedIn
		if r.Kind == "prelogin" {
			r.State = Prelogin
		}
		r.Version++
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.UpstreamTimeout)
		defer cancel()
		if e := s.cfg.Provider.CompareAndSwap(release, id, r.Version-1, r); e != nil {
			return Record{}, storeError(e)
		}
		return Record{}, failure(503, "IAM_UNAVAILABLE", errors.Join(ErrUnavailable, err))
	}
	r.State = SendIntent
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		return Record{}, storeError(err)
	}
	return r, nil
}

// Authenticate explicitly refreshes if needed and performs one online validity
// check. Context getters and permission checks never repeat this network work.
func (s *Service) Authenticate(ctx context.Context, id string) (View, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.AuthBudget)
	defer cancel()
	r, err := s.load(ctx, id)
	if err != nil {
		return View{}, err
	}
	if r.Kind != "session" || r.Profile == nil || r.Permissions == nil {
		return View{}, failure(401, "SESSION_REQUIRED", ErrInvalidSession)
	}
	if r.State == Owned || r.State == SendIntent {
		if r.State == SendIntent || s.cfg.Clock().Before(r.LeaseExpiresAt) {
			_, err = s.own(ctx, id, "refresh", r)
			return View{}, err
		}
		// An expired owner with no SEND_INTENT has provably not sent.
		r.State = SignedIn
		r.Version++
		if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
			return View{}, storeError(err)
		}
	}
	now := s.cfg.Clock()
	if !now.Add(s.cfg.RefreshSkew).Before(r.AccessExpiresAt) && r.RefreshToken != "" {
		r, err = s.refresh(ctx, id, r)
		if err != nil {
			return View{}, err
		}
	} else if !now.Before(r.AccessExpiresAt) {
		_ = s.terminate(id)
		return View{}, failure(401, "SESSION_INVALIDATED", ErrInvalidSession)
	}
	oldVersion := r.Version
	if err := s.validity(ctx, &r); err != nil {
		if errors.Is(err, ErrInvalidSession) {
			_ = s.terminate(id)
		}
		return View{}, err
	}
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, oldVersion, r); err != nil {
		return View{}, storeError(err)
	}
	return view(r), nil
}

func (s *Service) refresh(ctx context.Context, id string, r Record) (Record, error) {
	var err error
	r, err = s.own(ctx, id, "refresh", r)
	if err != nil {
		return Record{}, err
	}
	r, err = s.intent(ctx, id, r)
	if err != nil {
		return Record{}, err
	}
	t, err := s.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.RefreshToken}}, r.Nonce, true)
	if err != nil {
		if errors.Is(err, errNotSent) {
			release, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.UpstreamTimeout)
			defer cancel()
			r.State = SignedIn
			r.Version++
			if releaseErr := s.cfg.Provider.CompareAndSwap(release, id, r.Version-1, r); releaseErr != nil {
				return Record{}, storeError(releaseErr)
			}
			return Record{}, err
		}
		_ = s.terminate(id)
		if errors.Is(err, ErrUnavailable) {
			return Record{}, failure(401, "REFRESH_UNCERTAIN", errors.Join(ErrRefreshUncertain, err))
		}
		return Record{}, err
	}
	// A rotating refresh response must supply its new generation.
	if t.Refresh == "" || t.Refresh == r.RefreshToken || (t.subject != "" && t.subject != r.Profile.ID) {
		_ = s.terminate(id)
		return Record{}, failure(401, "REFRESH_UNCERTAIN", ErrRefreshUncertain)
	}
	r.AccessToken, r.RefreshToken, r.AccessExpiresAt = t.Access, t.Refresh, s.cfg.Clock().Add(time.Duration(t.Expires)*time.Second)
	r.State = SignedIn
	r.Version++
	if err := s.cfg.Provider.CompareAndSwap(ctx, id, r.Version-1, r); err != nil {
		_ = s.terminate(id)
		return Record{}, failure(401, "REFRESH_UNCERTAIN", errors.Join(ErrRefreshUncertain, err))
	}
	return r, nil
}

func (s *Service) exchange(ctx context.Context, id, code string, r Record) (string, View, error) {
	r, err := s.intent(ctx, id, r)
	if err != nil {
		return "", View{}, err
	}
	t, err := s.token(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.cfg.CallbackURL}, "code_verifier": {r.Verifier}}, r.Nonce, false)
	if err != nil {
		_ = s.terminate(id)
		if errors.Is(err, ErrUnavailable) && !errors.Is(err, errNotSent) {
			err = failure(401, "AUTH_EXCHANGE_UNCERTAIN", errors.Join(ErrExchangeUncertain, err))
		}
		return "", View{}, err
	}
	now := s.cfg.Clock()
	next := Record{SchemaVersion: SchemaVersion, Kind: "session", State: SignedIn, ClientID: s.cfg.ClientID,
		CreatedAt: now, AbsoluteExpiresAt: now.Add(s.cfg.AbsoluteTTL), IdleExpiresAt: minTime(now.Add(s.cfg.IdleTTL), now.Add(s.cfg.AbsoluteTTL)),
		Owner: random(), CSRF: random(), Nonce: r.Nonce, AccessToken: t.Access, RefreshToken: t.Refresh,
		AccessExpiresAt: now.Add(time.Duration(t.Expires) * time.Second)}
	if err := s.identity(ctx, &next); err != nil {
		_ = s.terminate(id)
		return "", View{}, err
	}
	if t.subject != "" && t.subject != next.Profile.ID {
		_ = s.terminate(id)
		return "", View{}, failure(401, "OIDC_INVALID", ErrInvalidSession)
	}
	nextID := random()
	if err := s.cfg.Provider.Rotate(ctx, id, r.Version, nextID, next); err != nil {
		_ = s.terminate(id)
		return "", View{}, failure(401, "AUTH_EXCHANGE_UNCERTAIN", errors.Join(ErrExchangeUncertain, err))
	}
	return nextID, view(next), nil
}

// Callback validates the complete unique branch before atomically consuming it.
// AUTH_CONTINUATION keeps the existing controlled custom transaction for MFA.
func (s *Service) Callback(ctx context.Context, id string, q url.Values) (string, View, string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.AuthBudget)
	defer cancel()
	r, err := s.load(ctx, id)
	if err != nil {
		return "", View{}, "", err
	}
	if r.Kind != "prelogin" || r.OAuthState == "" || q.Get("state") != r.OAuthState {
		return "", View{}, "", invalid()
	}
	for k, values := range q {
		if len(values) != 1 || values[0] == "" || !contains([]string{"state", "code", "kind", "auth_transaction_id", "error"}, k) {
			return "", View{}, "", invalid()
		}
	}
	code, kind, denied := q.Get("code"), q.Get("kind"), q.Get("error")
	switch {
	case code != "" && len(q) == 2:
		r, err = s.own(ctx, id, "callback", r)
		if err != nil {
			return "", View{}, "", err
		}
		next, v, err := s.exchange(ctx, id, code, r)
		return next, v, r.ReturnTo, err
	case kind == "AUTH_CONTINUATION" && code == "" && denied == "" && len(q) == 3 &&
		r.TransactionID != "" && r.LoginState == "AWAITING_PROVIDER" && q.Get("auth_transaction_id") == r.TransactionID:
		v, err := s.transaction(ctx, id, "get", nil)
		if err == nil && v.State != "MFA_REQUIRED" {
			return "", View{}, "", invalid()
		}
		return id, v, s.cfg.ReturnTo, err
	case denied == "access_denied" && len(q) == 2:
		if err := s.terminate(id); err != nil {
			return "", View{}, "", storeError(err)
		}
		return "", View{}, "", failure(401, "AUTH_CANCELLED", ErrInvalidSession)
	default:
		return "", View{}, "", invalid()
	}
}

type LogoutResult struct {
	Local  string `json:"local"`
	Cookie string `json:"cookie"`
	Remote string `json:"remote"`
	SSO    string `json:"sso"`
}

// Logout invalidates before remote I/O. It never refreshes to obtain logout
// credentials, and RT revocation is never reported as session revocation.
func (s *Service) Logout(ctx context.Context, id string) (LogoutResult, error) {
	result := LogoutResult{Local: "INVALIDATED", Cookie: "CLEARED", Remote: "NOT_ATTEMPTED", SSO: "NOT_REQUESTED"}
	r, err := s.cfg.Provider.Invalidate(ctx, id)
	if errors.Is(err, ErrAbsent) {
		result.Local = "NOT_FOUND"
		return result, nil
	}
	var localErr error
	if err != nil {
		result.Local = "UNCONFIRMED"
		localErr = storeError(err)
		// An unavailable atomic invalidate may still permit a read. A read
		// failure does not fabricate remote success or erase the local failure.
		r, err = s.cfg.Provider.Load(ctx, id)
		if err != nil {
			return result, localErr
		}
	}
	if r.AccessToken != "" && s.cfg.Clock().Before(r.AccessExpiresAt) {
		body := map[string]string{}
		if r.RefreshToken != "" {
			body["refresh_token"] = r.RefreshToken
		}
		err = s.request(ctx, "POST", "/api/v1/auth/logout", body, r.AccessToken, nil, nil, false)
		if err == nil {
			result.Remote = "SESSION_REVOKED"
		}
	} else if r.RefreshToken != "" {
		err = s.request(ctx, "POST", "/oauth2/revoke", url.Values{"token": {r.RefreshToken}, "token_type_hint": {"refresh_token"}}, "", nil, nil, false)
		if err == nil {
			result.Remote = "REFRESH_FAMILY_REVOKED"
		}
	}
	if err != nil {
		result.Remote = "UNCONFIRMED"
		return result, failure(503, "IAM_UNAVAILABLE", errors.Join(ErrUnavailable, err, localErr))
	}
	return result, localErr
}
