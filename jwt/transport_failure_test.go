package iamjwt

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type failingTransport struct{ cause error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.cause }

type readFailure struct {
	cause  error
	closed bool
}

func (r *readFailure) Read([]byte) (int, error) { return 0, r.cause }
func (r *readFailure) Close() error             { r.closed = true; return nil }

type bodyTransport struct{ body io.ReadCloser }

func (b bodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: b.body, Header: make(http.Header)}, nil
}

type dependencyCause struct{}

func (*dependencyCause) Error() string { return "private dependency cause" }

func TestJWKSFailurePreservesTransportAndReadCauses(t *testing.T) {
	cause := &dependencyCause{}
	body := &readFailure{cause: cause}
	for _, transport := range []http.RoundTripper{failingTransport{cause}, bodyTransport{body}} {
		p, err := NewJWKSProvider(JWKSOptions{URL: "https://jwks.test", Client: &http.Client{Transport: transport}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.KeyByID(context.Background(), "needed")
		var actual *dependencyCause
		if !errors.Is(err, ErrJWKSFetch) || !errors.As(err, &actual) || actual != cause {
			t.Fatalf("lost cause: %v", err)
		}
	}
	if !body.closed {
		t.Fatal("response body not closed")
	}
	large := io.NopCloser(strings.NewReader(strings.Repeat(" ", (1<<20)+1)))
	p, err := NewJWKSProvider(JWKSOptions{URL: "https://jwks.test", Client: &http.Client{Transport: bodyTransport{large}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.KeyByID(context.Background(), "needed"); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("unbounded/incorrect read: %v", err)
	}
}

type blockingTransport struct {
	started, release chan struct{}
	calls            atomic.Int32
}

func (b *blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.calls.Add(1) == 1 {
		close(b.started)
	}
	select {
	case <-r.Context().Done():
		return nil, r.Context().Err()
	case <-b.release:
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"keys":[]}`)), Header: make(http.Header)}, nil
	}
}

func TestJWKSCancelledWaiterDoesNotCancelSharedRefresh(t *testing.T) {
	transport := &blockingTransport{started: make(chan struct{}), release: make(chan struct{})}
	p, err := NewJWKSProvider(JWKSOptions{URL: "https://jwks.test", Client: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.Preload(context.Background()) }()
	<-transport.started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.KeyByID(ctx, "needed"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost waiter cancellation: %v", err)
	}
	close(transport.release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = p.KeyByID(context.Background(), "needed"); !errors.Is(err, ErrUnknownKey) {
		t.Fatal(err)
	}
}
