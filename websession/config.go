package websession

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
	"github.com/go-jose/go-jose/v4"
)

// Config enables server_session explicitly. None of these settings change the
// existing JWT/Bearer SDK. Origin and redirects are never inferred from Host or
// forwarded headers. TLS termination must enforce this configured public origin.
type Config struct {
	Issuer, Audience, ClientID, ClientSecret string
	Origin, CallbackURL, BasePath            string
	Scopes                                   []string
	ReturnTo                                 string
	AllowedReturnTo                          []string
	PasswordResetURL                         string
	Provider                                 Provider
	Binding                                  Binding
	// AllowLoopbackHTTP is development-only and requires loopback endpoints.
	AllowLoopbackHTTP                 bool
	Replicas, Workers                 int
	HTTPClient                        *http.Client
	PreloginTTL, AbsoluteTTL, IdleTTL time.Duration
	RefreshLease, RefreshSkew         time.Duration
	UpstreamTimeout, AuthBudget       time.Duration
	Clock                             func() time.Time
}

type Service struct {
	cfg  Config
	http *http.Client
	keys *iamjwt.JWKSProvider
	algs []jose.SignatureAlgorithm
}

var opaquePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var permissionPattern = regexp.MustCompile(`^([a-z0-9_-]{1,128}:(\*|[a-z0-9_-]{1,128})|\*:\*)$`)

func randomValue(s string) bool { return opaquePattern.MatchString(s) }
func random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("websession: secure random unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func validURL(raw string, allowHTTP bool) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, false
	}
	if u.Scheme == "https" {
		return u, true
	}
	ip := net.ParseIP(u.Hostname())
	if allowHTTP && u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return u, true
	}
	return nil, false
}

func localReturn(s string) bool {
	u, err := url.Parse(s)
	return err == nil && strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") &&
		!strings.ContainsAny(s, "\\\r\n") && u.IsAbs() == false && u.Host == "" && u.Fragment == "" &&
		!strings.Contains(strings.ToLower(s), "%2f") && !strings.Contains(strings.ToLower(s), "%5c")
}

// New validates explicit configuration and resolves pinned OIDC discovery using
// ctx. No background network process or token retry is installed.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Provider == nil || !cfg.Provider.Capabilities().Atomic ||
		strings.TrimSpace(cfg.Audience) == "" || strings.TrimSpace(cfg.ClientID) == "" || len(cfg.ClientID) > 128 ||
		cfg.ClientSecret == "" || cfg.Replicas < 0 || cfg.Workers < 0 ||
		((cfg.Replicas > 1 || cfg.Workers > 1) && !cfg.Provider.Capabilities().Shared) {
		return nil, invalid()
	}
	issuer, ok := validURL(cfg.Issuer, cfg.AllowLoopbackHTTP)
	if !ok || (issuer.Path != "" && issuer.Path != "/") {
		return nil, invalid()
	}
	origin, ok := validURL(cfg.Origin, cfg.AllowLoopbackHTTP)
	if !ok || origin.Path != "" {
		return nil, invalid()
	}
	callback, ok := validURL(cfg.CallbackURL, cfg.AllowLoopbackHTTP)
	if !ok || callback.Scheme != origin.Scheme || callback.Host != origin.Host {
		return nil, invalid()
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/auth"
	}
	if !localReturn(cfg.BasePath) || strings.Contains(cfg.BasePath, "?") || strings.HasSuffix(cfg.BasePath, "/") ||
		callback.Path != cfg.BasePath+"/callback" || callback.RawPath != "" {
		return nil, invalid()
	}
	if cfg.ReturnTo == "" || !localReturn(cfg.ReturnTo) {
		return nil, invalid()
	}
	found := false
	cfg.AllowedReturnTo = append([]string(nil), cfg.AllowedReturnTo...)
	for _, s := range cfg.AllowedReturnTo {
		if !localReturn(s) {
			return nil, invalid()
		}
		if s == cfg.ReturnTo {
			found = true
		}
	}
	if !found || len(cfg.Scopes) == 0 {
		return nil, invalid()
	}
	cfg.Scopes = append([]string(nil), cfg.Scopes...)
	seen := map[string]bool{}
	for _, scope := range cfg.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") || seen[scope] {
			return nil, invalid()
		}
		seen[scope] = true
	}
	if len(strings.Join(cfg.Scopes, " ")) > 2048 {
		return nil, invalid()
	}
	if cfg.PasswordResetURL != "" {
		u, ok := validURL(cfg.PasswordResetURL, cfg.AllowLoopbackHTTP)
		if !ok || u.Scheme != origin.Scheme || u.Host != origin.Host {
			return nil, invalid()
		}
	}
	for _, item := range []struct {
		value *time.Duration
		def   time.Duration
	}{
		{&cfg.PreloginTTL, 600 * time.Second}, {&cfg.AbsoluteTTL, time.Hour}, {&cfg.IdleTTL, time.Hour},
		{&cfg.RefreshLease, 15 * time.Second}, {&cfg.RefreshSkew, 30 * time.Second},
		{&cfg.UpstreamTimeout, 5 * time.Second}, {&cfg.AuthBudget, 10 * time.Second},
	} {
		if *item.value < 0 {
			return nil, invalid()
		}
		if *item.value == 0 {
			*item.value = item.def
		}
	}
	if cfg.PreloginTTL > 600*time.Second || cfg.AbsoluteTTL > time.Hour || cfg.IdleTTL > time.Hour {
		return nil, invalid()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Binding == nil {
		b, err := NewCookieBinding(CookieOptions{Origin: cfg.Origin, AllowLoopbackHTTP: cfg.AllowLoopbackHTTP})
		if err != nil {
			return nil, err
		}
		cfg.Binding = b
	}
	h := http.Client{}
	if cfg.HTTPClient != nil {
		h = *cfg.HTTPClient
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &Service{cfg: cfg, http: &h}
	var discovery struct {
		Issuer     string   `json:"issuer"`
		JWKS       string   `json:"jwks_uri"`
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := s.request(ctx, "GET", "/.well-known/openid-configuration", nil, "", nil, &discovery, false); err != nil {
		return nil, err
	}
	if discovery.Issuer != cfg.Issuer {
		return nil, invalid()
	}
	jwks, ok := validURL(discovery.JWKS, cfg.AllowLoopbackHTTP)
	if !ok || jwks.Scheme != issuer.Scheme || jwks.Host != issuer.Host {
		return nil, invalid()
	}
	for _, alg := range discovery.Algorithms {
		switch alg {
		case "RS256", "ES256":
			s.algs = append(s.algs, jose.SignatureAlgorithm(alg))
		}
	}
	if len(s.algs) == 0 {
		return nil, invalid()
	}
	// JWKSProvider uses the same redirect-rejecting, bounded transport.
	jh := h
	jh.Timeout = cfg.UpstreamTimeout
	var err error
	s.keys, err = iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: discovery.JWKS, Client: &jh})
	if err != nil {
		return nil, errors.Join(ErrValidation, err)
	}
	return s, nil
}

func (s *Service) BasePath() string { return s.cfg.BasePath }

func minTime(values ...time.Time) time.Time {
	t := values[0]
	for _, v := range values[1:] {
		if v.Before(t) {
			t = v
		}
	}
	return t
}
