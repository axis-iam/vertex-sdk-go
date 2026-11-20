package websession

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebSessionBusinessCSRFGuardCachedIdentity(t *testing.T) {
	f, _, s := newTestService(t)
	id, _ := hostedSession(t, f, s)
	record, err := s.cfg.Provider.Load(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	run := func(method, csrf string, mutate bool) *httptest.ResponseRecorder {
		inner := s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count++
			w.WriteHeader(http.StatusNoContent)
		}))
		outer := s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := r.Context().Value(contextKey{}).(requestIdentity); !ok {
				t.Error("outer guard did not pass cached request identity")
			}
			if mutate {
				r.Header.Set("X-CSRF-Token", strings.Repeat("x", 43))
			}
			inner.ServeHTTP(w, r)
		}))
		req := httptest.NewRequest(method, s.cfg.Origin+"/business-write", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "axis-session-dev", Value: id})
		req.Header.Set("Origin", s.cfg.Origin)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		outer.ServeHTTP(rec, req)
		return rec
	}
	beforeValidity := f.validityCount.Load()
	if got := run(http.MethodPost, record.CSRF, false); got.Code != http.StatusNoContent {
		t.Fatalf("valid double guard write: %d", got.Code)
	}
	if f.validityCount.Load() != beforeValidity+1 {
		t.Fatalf("double guard re-authenticated: validity calls=%d", f.validityCount.Load()-beforeValidity)
	}
	if count != 1 {
		t.Fatalf("valid business side effects=%d", count)
	}
	beforeValidity = f.validityCount.Load()
	if got := run(http.MethodPost, record.CSRF, true); got.Code != http.StatusForbidden {
		t.Fatalf("mutated cached identity write: %d", got.Code)
	}
	if f.validityCount.Load() != beforeValidity+1 {
		t.Fatalf("mutated request unexpectedly re-authenticated: validity calls=%d", f.validityCount.Load()-beforeValidity)
	}
	if count != 1 {
		t.Fatalf("rejected business side effects=%d", count)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if got := run(method, "", false); got.Code != http.StatusNoContent {
			t.Fatalf("%s without CSRF: %d", method, got.Code)
		}
	}
	if count != 4 {
		t.Fatalf("safe method side effects=%d", count)
	}
}
