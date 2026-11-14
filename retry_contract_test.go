package iam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type lintRoundTripper func(*http.Request) (*http.Response, error)

func (f lintRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRetryCountContract(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, value := range []int{-maxInt - 1, -1, 0, 1, maxInt} {
		config := &SDKConfig{Endpoint: "https://fixture.invalid", ClientID: "fixture", ClientSecret: "fixture", MaxRetries: value}
		client, err := NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		if value <= 0 && config.MaxRetries != 3 {
			t.Fatalf("default retry count changed for %d: %d", value, config.MaxRetries)
		}
		var calls int
		client.SetHTTPClient(&http.Client{Transport: lintRoundTripper(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"permissions":["orders:read"]}`))}, nil
		})})
		if _, err := client.ResolvePermissions(context.Background(), "fixture", []string{"reader"}); err != nil || calls != 1 {
			t.Fatalf("valid configured retry budget %d: calls=%d err=%v", value, calls, err)
		}
		// Unsupported post-construction mutation must not turn a negative int into
		// an unsigned retry budget or cause even the first transport call.
		config.MaxRetries = -maxInt - 1
		if _, err := client.ResolvePermissions(context.Background(), "fixture", []string{"reader"}); err == nil || calls != 1 {
			t.Fatalf("negative mutation reached transport: calls=%d err=%v", calls, err)
		}
	}
}

type closeErrorBody struct {
	io.Reader
	closed bool
}

func (b *closeErrorBody) Close() error {
	b.closed = true
	return errors.New("fixture close failure")
}

func TestResponseBodyClosurePreservesResult(t *testing.T) {
	for _, status := range []int{200, 400} {
		body := &closeErrorBody{Reader: strings.NewReader(`{"permissions":["orders:read"]}`)}
		client, err := NewClient(&SDKConfig{Endpoint: "https://fixture.invalid", ClientID: "fixture", ClientSecret: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		client.SetHTTPClient(&http.Client{Transport: lintRoundTripper(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: body}, nil
		})})
		result, err := client.ResolvePermissions(context.Background(), "fixture", []string{"reader"})
		if !body.closed {
			t.Fatal("response body was not closed")
		}
		if status == 200 {
			if err != nil || result == nil || len(result.Permissions) != 1 || result.Permissions[0] != "orders:read" {
				t.Fatalf("close error replaced successful response: result=%v err=%v", result, err)
			}
		} else {
			var api *APIError
			if !errors.As(err, &api) || api.Status != 400 {
				t.Fatalf("close error replaced typed HTTP error: %v", err)
			}
		}
	}
}
