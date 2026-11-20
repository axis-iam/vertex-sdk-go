package websession

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func hostRequest(s *Service, method, path, body, id, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, s.cfg.Origin+s.BasePath()+path, strings.NewReader(body))
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", s.cfg.Origin)
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if id != "" {
		req.AddCookie(&http.Cookie{Name: "axis-session-dev", Value: id})
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestWebSessionHTTP(t *testing.T) {
	t.Run("Configuration", TestWebSessionConfiguration)
	f, _, s := newTestService(t)
	if got := hostRequest(s, "GET", "/login", "", "", ""); got.Code != 401 || got.Header().Get("Location") != "" {
		t.Fatal("unbound navigation", got.Code)
	}
	bootstrap := hostRequest(s, "GET", "/session/bootstrap", "", "", "")
	var initial View
	if json.Unmarshal(bootstrap.Body.Bytes(), &initial) != nil || bootstrap.Code != 200 || len(bootstrap.Result().Cookies()) != 1 {
		t.Fatal("bootstrap")
	}
	cookie := bootstrap.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("cookie policy")
	}
	id := cookie.Value
	for _, path := range []string{"/session/login", "/registration", "/password-reset/request", "/session/logout"} {
		got := hostRequest(s, "POST", path, "{}", id, "wrong")
		if got.Code != 403 {
			t.Fatalf("CSRF %s = %d", path, got.Code)
		}
	}
	if got := hostRequest(s, "POST", "/session/login", `{"unknown":true}`, id, initial.CSRFToken); got.Code != 400 {
		t.Fatal("unknown JSON")
	}
	if got := hostRequest(s, "POST", "/session/login", `{"x":1,"x":2}`, id, initial.CSRFToken); got.Code != 400 {
		t.Fatal("duplicate JSON")
	}
	nav := hostRequest(s, "GET", "/login?returnTo=%2Faccount", "", ""+id, "")
	if nav.Code != 302 {
		t.Fatalf("Hosted %d %s", nav.Code, nav.Body.String())
	}
	u, _ := url.Parse(nav.Header().Get("Location"))
	f.mu.Lock()
	f.codes["browser-code"] = u.Query().Get("nonce")
	f.mu.Unlock()
	got := hostRequest(s, "GET", "/callback?"+url.Values{"code": {"browser-code"}, "state": {u.Query().Get("state")}}.Encode(), "", id, "")
	if got.Code != 302 || got.Header().Get("Location") != "/account" || strings.Contains(got.Body.String(), "browser-code") {
		t.Fatal("callback", got.Code, got.Body.String())
	}
	id = got.Result().Cookies()[0].Value
	session := hostRequest(s, "GET", "/session", "", id, "")
	var v View
	if session.Code != 200 || json.Unmarshal(session.Body.Bytes(), &v) != nil || v.Profile == nil {
		t.Fatal("session", session.Body.String())
	}
	for _, secret := range []string{"fixture-access", "fixture-refresh", "fixture-control", "id_token", "access_token", "code_verifier"} {
		if bytes.Contains(session.Body.Bytes(), []byte(secret)) {
			t.Fatal("leak", secret)
		}
	}
	req := httptest.NewRequest("GET", s.cfg.Origin+"/business", nil)
	req.AddCookie(&http.Cookie{Name: "axis-session-dev", Value: id})
	req.Header.Set("Authorization", "Bearer invalid")
	rec := httptest.NewRecorder()
	s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("mixed credentials inherited cookie") })).ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatal("mixed credentials")
	}
	logout := hostRequest(s, "POST", "/session/logout", "{}", id, v.CSRFToken)
	if logout.Code != 200 || logout.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout", logout.Body.String())
	}
	if got := hostRequest(s, "GET", "/session", "", id, ""); got.Code != 401 {
		t.Fatal("logout retained")
	}
	// Same browser's new generation cannot be overwritten by an old request.
	fresh := hostRequest(s, "GET", "/session/bootstrap", "", "", "")
	if fresh.Result().Cookies()[0].Value == id {
		t.Fatal("identity reused")
	}
}

func TestWebSessionConfiguration(t *testing.T) {
	f, m, _ := newTestService(t)
	for _, change := range []func(*Config){
		func(c *Config) { c.Provider = nil }, func(c *Config) { c.Replicas = 2 }, func(c *Config) { c.Workers = 2 },
		func(c *Config) { c.Origin = "http://example.com" }, func(c *Config) { c.CallbackURL = "https://other.test/auth/callback" },
		func(c *Config) { c.ReturnTo = "//other.test" }, func(c *Config) { c.Audience = "" }, func(c *Config) { c.AbsoluteTTL = -1 },
	} {
		cfg := f.config(m)
		change(&cfg)
		if _, err := New(context.Background(), cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
