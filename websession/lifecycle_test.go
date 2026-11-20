package websession

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axis-iam/vertex-sdk-go/authz"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type faultyProvider struct {
	Provider
	loadErr, casErr, invalidateErr error
}

func (p *faultyProvider) Load(ctx context.Context, id string) (Record, error) {
	if p.loadErr != nil {
		return Record{}, p.loadErr
	}
	return p.Provider.Load(ctx, id)
}
func (p *faultyProvider) CompareAndSwap(ctx context.Context, id string, v uint64, r Record) error {
	if p.casErr != nil && r.State == SignedIn {
		return p.casErr
	}
	return p.Provider.CompareAndSwap(ctx, id, v, r)
}
func (p *faultyProvider) Invalidate(ctx context.Context, id string) (Record, error) {
	if p.invalidateErr != nil {
		return Record{}, p.invalidateErr
	}
	return p.Provider.Invalidate(ctx, id)
}

func TestWebSessionLifecycle(t *testing.T) {
	t.Run("RefreshAndImmutableAbsolute", func(t *testing.T) {
		f, m, s := newTestService(t)
		ctx := context.Background()
		id, _ := hostedSession(t, f, s)
		before, _ := m.Load(ctx, id)
		f.clock.Add(100 * time.Second)
		v, err := s.Authenticate(ctx, id)
		if err != nil || v.Profile == nil || f.refreshCount.Load() != 1 {
			t.Fatalf("refresh %v", err)
		}
		after, _ := m.Load(ctx, id)
		if after.RefreshToken == before.RefreshToken || !after.AbsoluteExpiresAt.Equal(before.AbsoluteExpiresAt) || !after.CreatedAt.Equal(before.CreatedAt) {
			t.Fatal("deadline or rotation")
		}
	})
	t.Run("NoRTExpiry", func(t *testing.T) {
		f, _, s := newTestService(t)
		f.noRefresh = true
		id, _ := hostedSession(t, f, s)
		f.clock.Add(121 * time.Second)
		if _, err := s.Authenticate(context.Background(), id); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("no RT %v", err)
		}
		if f.refreshCount.Load() != 0 {
			t.Fatal("fabricated refresh")
		}
	})
	t.Run("DependencyAndRevocationDistinct", func(t *testing.T) {
		f, m, s := newTestService(t)
		ctx := context.Background()
		id, _ := hostedSession(t, f, s)
		f.validityStatus.Store(503)
		if _, err := s.Authenticate(ctx, id); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if _, err := m.Load(ctx, id); err != nil {
			t.Fatal("503 destroyed identity")
		}
		f.validityStatus.Store(401)
		if _, err := s.Authenticate(ctx, id); !errors.Is(err, ErrInvalidSession) {
			t.Fatal(err)
		}
		if _, err := m.Load(ctx, id); !errors.Is(err, ErrAbsent) {
			t.Fatal("revoked session retained")
		}
	})
	t.Run("ProviderFailureNotAnonymous", func(t *testing.T) {
		f, m, s := newTestService(t)
		p := &faultyProvider{Provider: m, loadErr: ErrUnavailable}
		s.cfg.Provider = p
		if _, _, err := s.Bootstrap(context.Background(), random()); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if f.tokenCount.Load() != 0 {
			t.Fatal("provider failure reached IAM")
		}
	})
	for _, tc := range []struct {
		name                                       string
		expired, noRT, remoteFailure, localFailure bool
		remote, local                              string
	}{
		{"ValidATWithRT", false, false, false, false, "SESSION_REVOKED", "INVALIDATED"},
		{"ValidATWithoutRT", false, true, false, false, "SESSION_REVOKED", "INVALIDATED"},
		{"ExpiredATWithRT", true, false, false, false, "REFRESH_FAMILY_REVOKED", "INVALIDATED"},
		{"ExpiredATWithoutRT", true, true, false, false, "NOT_ATTEMPTED", "INVALIDATED"},
		{"RemoteFailure", false, false, true, false, "UNCONFIRMED", "INVALIDATED"},
		{"LocalFailure", false, false, false, true, "SESSION_REVOKED", "UNCONFIRMED"},
	} {
		t.Run("Logout"+tc.name, func(t *testing.T) {
			f, m, s := newTestService(t)
			f.noRefresh = tc.noRT
			ctx := context.Background()
			id, _ := hostedSession(t, f, s)
			old, _ := m.Load(ctx, id)
			if tc.expired {
				f.clock.Add(121 * time.Second)
			}
			if tc.remoteFailure {
				f.logoutStatus.Store(503)
			}
			if tc.localFailure {
				s.cfg.Provider = &faultyProvider{Provider: m, invalidateErr: ErrUnavailable}
			}
			result, err := s.Logout(ctx, id)
			if (err != nil) != (tc.remoteFailure || tc.localFailure) || result.Remote != tc.remote || result.Local != tc.local || result.SSO != "NOT_REQUESTED" {
				t.Fatalf("logout %+v err=%v", result, err)
			}
			if f.refreshCount.Load() != 0 {
				t.Fatal("logout refreshed")
			}
			if !tc.localFailure {
				old.Version++
				if err := m.CompareAndSwap(ctx, id, old.Version-1, old); !errors.Is(err, ErrConflict) {
					t.Fatal("late save resurrected")
				}
			}
			if tc.expired && f.logoutCount.Load() != 0 {
				t.Fatal("expired logout AT used")
			}
		})
	}
	t.Run("RequestContextAndPermission", func(t *testing.T) {
		f, _, s := newTestService(t)
		id, _ := hostedSession(t, f, s)
		before := f.validityCount.Load()
		business := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a, b := FromContext(r.Context()), FromContext(r.Context())
			u := authz.FromContext(r.Context())
			if a == nil || b == nil || u == nil || a.Profile.ID != fixtureUser || !u.HasPermission("documents", "read") {
				t.Fatal("missing request identity")
			}
			a.Profile.ID = "changed"
			if FromContext(r.Context()).Profile.ID != fixtureUser {
				t.Fatal("mutable context")
			}
			if u.HasPermission("documents", "write") {
				t.Fatal("permission escalation")
			}
			w.WriteHeader(403)
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://127.0.0.1:33391/business", nil)
		req.AddCookie(&http.Cookie{Name: "axis-session-dev", Value: id})
		s.Middleware(s.Middleware(business)).ServeHTTP(rec, req)
		if rec.Code != 403 || f.validityCount.Load() != before+1 || FromContext(context.Background()) != nil {
			t.Fatal("implicit network or context leakage")
		}
	})
}

func TestWebSessionConcurrentRefresh(t *testing.T) {
	f, m, s := newTestService(t)
	id, _ := hostedSession(t, f, s)
	f.clock.Add(100 * time.Second)
	f.blockRefresh()
	done := make(chan error, 1)
	go func() { _, err := s.Authenticate(context.Background(), id); done <- err }()
	<-f.refreshStarted
	other, err := New(context.Background(), f.config(m))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Authenticate(context.Background(), id); !errors.Is(err, ErrConflict) {
		t.Fatalf("second owner %v", err)
	}
	close(f.refreshRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.refreshCount.Load() != 1 {
		t.Fatal("RT replay")
	}
}

func TestWebSessionConcurrentLogoutFence(t *testing.T) {
	f, m, s := newTestService(t)
	id, _ := hostedSession(t, f, s)
	f.clock.Add(100 * time.Second)
	f.blockRefresh()
	done := make(chan error, 1)
	go func() { _, err := s.Authenticate(context.Background(), id); done <- err }()
	<-f.refreshStarted
	if _, err := s.Logout(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	close(f.refreshRelease)
	if err := <-done; !errors.Is(err, ErrRefreshUncertain) {
		t.Fatalf("late refresh %v", err)
	}
	if _, err := m.Load(context.Background(), id); !errors.Is(err, ErrAbsent) {
		t.Fatal("resurrection")
	}
}

func TestWebSessionConcurrentIntentAndCommitFailure(t *testing.T) {
	t.Run("KnownDialFailureAfterIntent", func(t *testing.T) {
		f, m, s := newTestService(t)
		ctx := context.Background()
		id, _ := hostedSession(t, f, s)
		old, _ := m.Load(ctx, id)
		f.clock.Add(100 * time.Second)
		original := s.http.Transport
		s.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/oauth2/token" {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("fixture refused")}
			}
			return http.DefaultTransport.RoundTrip(r)
		})
		if _, err := s.Authenticate(ctx, id); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefreshUncertain) {
			t.Fatal("known unsent classified uncertain", err)
		}
		after, err := m.Load(ctx, id)
		if err != nil || after.State != SignedIn || after.RefreshToken != old.RefreshToken || f.refreshCount.Load() != 0 {
			t.Fatal("unsent lost identity")
		}
		s.http.Transport = original
		if _, err := s.Authenticate(ctx, id); err != nil || f.refreshCount.Load() != 1 {
			t.Fatal("not reusable after proven unsent", err)
		}
	})
	t.Run("KnownBeforeSendCancellation", func(t *testing.T) {
		f, m, s := newTestService(t)
		ctx := context.Background()
		id, _ := hostedSession(t, f, s)
		r, _ := m.Load(ctx, id)
		r, err := s.own(ctx, id, "refresh", r)
		if err != nil {
			t.Fatal(err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.intent(cancelled, id, r); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		after, err := m.Load(ctx, id)
		if err != nil || after.State != SignedIn || after.RefreshToken != r.RefreshToken || f.refreshCount.Load() != 0 {
			t.Fatal("pre-send lost identity")
		}
	})
	t.Run("ExpiredIntentNeverTakeover", func(t *testing.T) {
		f, m, s := newTestService(t)
		ctx := context.Background()
		id, _ := hostedSession(t, f, s)
		r, _ := m.Load(ctx, id)
		r, err := s.own(ctx, id, "refresh", r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.intent(ctx, id, r)
		if err != nil {
			t.Fatal(err)
		}
		f.clock.Add(16 * time.Second)
		if _, err := s.Authenticate(ctx, id); !errors.Is(err, ErrRefreshUncertain) {
			t.Fatal(err)
		}
		if f.refreshCount.Load() != 0 {
			t.Fatal("expired intent replayed RT")
		}
	})
	t.Run("CommitFailure", func(t *testing.T) {
		f, m, s := newTestService(t)
		ctx := context.Background()
		id, _ := hostedSession(t, f, s)
		s.cfg.Provider = &faultyProvider{Provider: m, casErr: ErrUnavailable}
		f.clock.Add(100 * time.Second)
		if _, err := s.Authenticate(ctx, id); !errors.Is(err, ErrRefreshUncertain) {
			t.Fatal(err)
		}
		if _, err := s.Authenticate(ctx, id); err == nil {
			t.Fatal("continued old RT")
		}
		if f.refreshCount.Load() != 1 {
			t.Fatal("commit failure replayed")
		}
	})
	t.Run("SentCancellation", func(t *testing.T) {
		f, _, s := newTestService(t)
		id, _ := hostedSession(t, f, s)
		f.clock.Add(100 * time.Second)
		f.blockRefresh()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := s.Authenticate(ctx, id); done <- err }()
		<-f.refreshStarted
		cancel()
		close(f.refreshRelease)
		err := <-done
		if !errors.Is(err, ErrRefreshUncertain) || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel chain %v", err)
		}
		if f.refreshCount.Load() != 1 {
			t.Fatal("retried cancellation")
		}
	})
}
