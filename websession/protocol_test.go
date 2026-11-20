package websession

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
)

func TestWebSessionProtocol(t *testing.T) {
	t.Run("MissingPermissionContext", func(t *testing.T) {
		f, m, s := newTestService(t)
		f.omitPermissionContext = true
		ctx := context.Background()
		id, _, _ := s.Bootstrap(ctx, "")
		nav, _ := s.Hosted(ctx, id, "")
		u, _ := url.Parse(nav)
		f.codes["bad-permission"] = u.Query().Get("nonce")
		if _, _, _, err := s.Callback(ctx, id, url.Values{"code": {"bad-permission"}, "state": {u.Query().Get("state")}}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("missing permission context accepted", err)
		}
		if _, err := m.Load(ctx, id); !errors.Is(err, ErrAbsent) {
			t.Fatal("failed exchange retained auth")
		}
	})
	t.Run("C0Views", func(t *testing.T) {
		data, err := os.ReadFile("testdata/c0-v1.json")
		if err != nil {
			t.Fatal(err)
		}
		var vectors struct {
			ViewVectors []struct {
				ID     string          `json:"id"`
				Accept bool            `json:"accept"`
				Value  json.RawMessage `json:"value"`
			} `json:"viewVectors"`
		}
		if err := json.Unmarshal(data, &vectors); err != nil {
			t.Fatal(err)
		}
		for _, v := range vectors.ViewVectors {
			t.Run(v.ID, func(t *testing.T) {
				_, err := ParseView(v.Value)
				if (err == nil) != v.Accept {
					t.Fatalf("accept=%v err=%v", v.Accept, err)
				}
			})
		}
	})
	t.Run("HostedBindingAndReplay", func(t *testing.T) {
		f, _, s := newTestService(t)
		ctx := context.Background()
		if _, err := s.Hosted(ctx, "", ""); err == nil {
			t.Fatal("unbound GET allowed")
		}
		id, _, err := s.Bootstrap(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		nav, err := s.Hosted(ctx, id, "/account")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(nav)
		q := u.Query()
		if q.Get("audience") != "" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
			t.Fatal("invalid authorize")
		}
		for _, bad := range []url.Values{
			{"state": {"wrong"}, "code": {"one"}}, {"state": {q.Get("state"), q.Get("state")}, "code": {"one"}},
			{"state": {q.Get("state")}, "code": {"one"}, "kind": {"AUTH_CONTINUATION"}},
		} {
			if _, _, _, err := s.Callback(ctx, id, bad); err == nil {
				t.Fatal("bad callback accepted")
			}
		}
		if f.tokenCount.Load() != 0 {
			t.Fatal("invalid callback exchanged")
		}
		f.mu.Lock()
		f.codes["one"] = q.Get("nonce")
		f.mu.Unlock()
		callback := url.Values{"state": {q.Get("state")}, "code": {"one"}}
		next, v, target, err := s.Callback(ctx, id, callback)
		if err != nil || next == id || v.Profile == nil || target != "/account" {
			t.Fatalf("exchange %v %v", v, err)
		}
		if _, _, _, err := s.Callback(ctx, id, callback); err == nil || f.tokenCount.Load() != 1 {
			t.Fatal("callback replay")
		}
	})
	t.Run("OIDCBindings", func(t *testing.T) {
		for name, override := range map[string]map[string]any{
			"issuer": {"iss": "https://other.test"}, "audience": {"aud": "resource"}, "azp": {"aud": []string{"connected-web", "other"}, "azp": "other"},
			"nonce": {"nonce": "wrong"}, "expired": {"exp": 1}, "missingExpiry": {"exp": nil},
			"subject": {"sub": "another-user"},
		} {
			t.Run(name, func(t *testing.T) {
				f, _, s := newTestService(t)
				f.idOverride = override
				ctx := context.Background()
				id, _, _ := s.Bootstrap(ctx, "")
				nav, _ := s.Hosted(ctx, id, "")
				u, _ := url.Parse(nav)
				f.codes["one"] = u.Query().Get("nonce")
				_, _, _, err := s.Callback(ctx, id, url.Values{"state": {u.Query().Get("state")}, "code": {"one"}})
				if !errors.Is(err, ErrInvalidSession) {
					t.Fatalf("OIDC accepted: %v", err)
				}
			})
		}
	})
	t.Run("CustomPasswordMFAProviderMagicCancel", func(t *testing.T) {
		f, _, s := newTestService(t)
		ctx := context.Background()
		id, _, _ := s.Bootstrap(ctx, "")
		v, err := s.Login(ctx, id)
		if err != nil || v.State != "AUTHENTICATING" || v.Profile != nil {
			t.Fatalf("create %v %v", v, err)
		}
		input := AuthenticateInput{Method: "PASSWORD", Identifier: Identifier{Kind: "EMAIL", Value: "reader@example.test"}, Password: "wrong"}
		if _, _, err := s.Action(ctx, id, "authenticate", input); err == nil {
			t.Fatal("bad password accepted")
		}
		input.Password = "correct"
		_, v, err = s.Action(ctx, id, "authenticate", input)
		if err != nil || v.NextAction != "complete" || v.Profile != nil {
			t.Fatalf("proof %v %v", v, err)
		}
		next, v, err := s.Action(ctx, id, "complete", nil)
		if err != nil || next == "" || v.Profile == nil {
			t.Fatalf("complete %v %v", v, err)
		}
		id, _, _ = s.Bootstrap(ctx, "")
		_, _ = s.Login(ctx, id)
		_, _, err = s.Action(ctx, id, "authorize", ProviderInput{ProviderID: fixtureApp})
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.txState = "MFA_REQUIRED"
		f.mu.Unlock()
		r, _ := s.load(ctx, id)
		q := url.Values{"kind": {"AUTH_CONTINUATION"}, "auth_transaction_id": {fixtureTx}, "state": {r.OAuthState}}
		_, v, _, err = s.Callback(ctx, id, q)
		if err != nil || v.State != "MFA_REQUIRED" || v.Profile != nil {
			t.Fatalf("continuation %v %v", v, err)
		}
		if _, _, _, err := s.Callback(ctx, id, q); err == nil {
			t.Fatal("continuation replay")
		}
		_, v, err = s.Action(ctx, id, "mfa", MFAInput{Method: "TOTP", Code: "123456"})
		if err != nil || v.NextAction != "complete" {
			t.Fatal(err)
		}
		_, v, err = s.Action(ctx, id, "complete", nil)
		if err != nil || v.Profile == nil {
			t.Fatal(err)
		}
		id, _, _ = s.Bootstrap(ctx, "")
		_, _ = s.Login(ctx, id)
		_, _, err = s.Action(ctx, id, "challenges", ChallengeInput{Method: "EMAIL_MAGIC_LINK", Identifier: Identifier{Kind: "EMAIL", Value: "reader@example.test"}})
		if err != nil {
			t.Fatal(err)
		}
		r, _ = s.load(ctx, id)
		magic := MagicInput{TransactionID: fixtureTx, State: r.OAuthState, Proof: "one-time-proof"}
		_, v, err = s.Action(ctx, id, "magic", magic)
		if err != nil || v.NextAction != "complete" {
			t.Fatal(err)
		}
		if _, _, err := s.Action(ctx, id, "magic", magic); err == nil {
			t.Fatal("magic replay")
		}
		id, _, _ = s.Bootstrap(ctx, "")
		_, _ = s.Login(ctx, id)
		_, v, err = s.Action(ctx, id, "cancel", nil)
		if err != nil || v.State != "CANCELLED" {
			t.Fatal(err)
		}
		if _, _, err := s.Action(ctx, id, "complete", nil); err == nil {
			t.Fatal("cancel replay")
		}
		id, _, _ = s.Bootstrap(ctx, "")
		_, _ = s.Login(ctx, id)
		_, _, err = s.Action(ctx, id, "authorize", ProviderInput{ProviderID: fixtureApp})
		if err != nil {
			t.Fatal(err)
		}
		r, _ = s.load(ctx, id)
		f.mu.Lock()
		f.codes["provider-code"] = r.Nonce
		f.mu.Unlock()
		_, v, _, err = s.Callback(ctx, id, url.Values{"code": {"provider-code"}, "state": {r.OAuthState}})
		if err != nil || v.Profile == nil {
			t.Fatal("provider code", err)
		}
		id, _, _ = s.Bootstrap(ctx, "")
		_, _ = s.Hosted(ctx, id, "")
		r, _ = s.load(ctx, id)
		if _, _, _, err := s.Callback(ctx, id, url.Values{"error": {"access_denied"}, "state": {r.OAuthState}}); !errors.Is(err, ErrInvalidSession) {
			t.Fatal("denial", err)
		}
		if _, _, _, err := s.Callback(ctx, id, url.Values{"code": {"unused"}, "state": {r.OAuthState}}); err == nil {
			t.Fatal("denied callback revived")
		}
	})
	t.Run("RegistrationAndRecoveryPurpose", func(t *testing.T) {
		f, _, s := newTestService(t)
		ctx := context.Background()
		id, _, _ := s.Bootstrap(ctx, "")
		reg, status, err := s.Register(ctx, id, SignupInput{Identifier: Identifier{Kind: "EMAIL", Value: "reader@example.test"}, Password: "password"})
		if err != nil || status != 202 || !randomValue(reg.RegistrationID) {
			t.Fatalf("signup %v %v", reg, err)
		}
		if _, err := s.RegistrationAction(ctx, id, fixtureReg, "complete", "123456"); err == nil {
			t.Fatal("upstream ref accepted")
		}
		reg, err = s.RegistrationAction(ctx, id, reg.RegistrationID, "complete", "123456")
		if err != nil || reg.Status != "VERIFIED" {
			t.Fatal(err)
		}
		if _, err := s.Authenticate(ctx, id); err == nil {
			t.Fatal("registration logged in")
		}
		if err := s.RequestPasswordReset(ctx, "reader@example.test"); err != nil {
			t.Fatal(err)
		}
		if err := s.ResetPassword(ctx, "reset-proof", "new-password"); err != nil {
			t.Fatal(err)
		}
		if f.tokenCount.Load() != 0 {
			t.Fatal("recovery returned credentials")
		}
	})
}
