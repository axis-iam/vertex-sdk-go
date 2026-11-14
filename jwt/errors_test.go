package iamjwt_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axis-iam/vertex-sdk-go/iamtest"
	iamjwt "github.com/axis-iam/vertex-sdk-go/jwt"
)

func TestVerificationErrorContract(t *testing.T) {
	mock, err := iamtest.NewMockServer()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()
	v := newVerifier(t, mock, "api://orders")
	_, err = v.Verify(context.Background(), "not.a.jwt")
	var classified *iamjwt.VerificationError
	if !errors.Is(err, iamjwt.ErrInvalidToken) || !errors.As(err, &classified) || errors.Unwrap(classified) == nil {
		t.Fatalf("missing invalid-token cause: %v", err)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		kind       error
	}{
		{"status", "private upstream details", 502, iamjwt.ErrJWKSFetch},
		{"parse", "{", 200, iamjwt.ErrJWKSParse},
		{"missing-keys", "{}", 200, iamjwt.ErrJWKSParse},
		{"unknown-key", `{"keys":[]}`, 200, iamjwt.ErrUnknownKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()
			p, e := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: s.URL})
			if e != nil {
				t.Fatal(e)
			}
			_, e = p.KeyByID(context.Background(), "needed")
			if !errors.Is(e, tc.kind) || !errors.As(e, &classified) {
				t.Fatalf("wrong category: %v", e)
			}
			if tc.name == "status" {
				var status *iamjwt.JWKSStatusError
				if !errors.As(e, &status) || status.StatusCode != 502 {
					t.Fatal(e)
				}
			}
			if tc.name == "parse" {
				var syntax *json.SyntaxError
				if !errors.As(e, &syntax) {
					t.Fatal("lost JSON cause", e)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: mock.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.KeyByID(ctx, "needed")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, iamjwt.ErrJWKSFetch) {
		t.Fatal(err)
	}
}

func TestJWKSFailureCooldownClassification(t *testing.T) {
	for _, parseFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "fetch", true: "parse"}[parseFailure], func(t *testing.T) {
			var calls atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				if parseFailure {
					_, _ = w.Write([]byte("{"))
				} else {
					w.WriteHeader(503)
				}
			}))
			defer s.Close()
			p, err := iamjwt.NewJWKSProvider(iamjwt.JWKSOptions{URL: s.URL, RotationCooldown: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			kind := iamjwt.ErrJWKSFetch
			if parseFailure {
				kind = iamjwt.ErrJWKSParse
			}
			var group sync.WaitGroup
			for i := 0; i < 20; i++ {
				group.Add(1)
				go func() {
					defer group.Done()
					_, e := p.KeyByID(context.Background(), "needed")
					if !errors.Is(e, kind) {
						t.Errorf("lost dependency category: %v", e)
					}
				}()
			}
			<-started
			close(release)
			group.Wait()
			if calls.Load() != 1 {
				t.Fatalf("refresh not coalesced: %d", calls.Load())
			}
			_, err = p.KeyByID(context.Background(), "needed")
			if !errors.Is(err, kind) || calls.Load() != 1 {
				t.Fatalf("cooldown changed error: %v calls=%d", err, calls.Load())
			}
		})
	}
}
