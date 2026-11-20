package websession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// decode rejects duplicate object keys at every depth and trailing JSON.
func decode(data []byte, out any, strict bool) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				keys := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := k.(string)
					if !ok || keys[key] {
						return ErrValidation
					}
					keys[key] = true
					if err := walk(); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(); err != nil {
						return err
					}
				}
			default:
				return ErrValidation
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrValidation
	}
	d = json.NewDecoder(bytes.NewReader(data))
	if strict {
		d.DisallowUnknownFields()
	}
	return d.Decode(out)
}

var codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func (s *Service) request(ctx context.Context, method, path string, body any, bearer string, headers http.Header, out any, token bool) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.UpstreamTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return failure(503, "IAM_UNAVAILABLE", errors.Join(ErrUnavailable, errNotSent, err))
	}
	var reader io.Reader
	contentType := "application/json"
	if form, ok := body.(url.Values); ok {
		reader = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return invalid()
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.cfg.Issuer, "/")+path, reader)
	if err != nil {
		return invalid()
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if token || path == "/oauth2/revoke" {
		req.SetBasicAuth(s.cfg.ClientID, s.cfg.ClientSecret)
	}
	for k, values := range headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	resp, err := s.http.Do(req)
	if err != nil {
		var operation *net.OpError
		if errors.As(err, &operation) && operation.Op == "dial" {
			return failure(503, "IAM_UNAVAILABLE", errors.Join(ErrUnavailable, errNotSent, err))
		}
		// Once handed to RoundTripper, lack of a response cannot prove no send.
		return failure(503, "IAM_UNAVAILABLE", errors.Join(ErrUnavailable, err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if readErr != nil || len(data) > 1<<20 {
		return failure(503, "IAM_UNAVAILABLE", errors.Join(ErrUnavailable, readErr))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 429 {
			retry, err := strconv.Atoi(resp.Header.Get("Retry-After"))
			if err != nil || retry < 0 || retry > 86400 {
				retry = 0
			}
			return &Error{Status: 429, Code: "RATE_LIMITED", RetryAfter: retry, Cause: ErrRateLimited}
		}
		var envelope struct {
			Error string `json:"error"`
		}
		_ = decode(data, &envelope, false) // Only this stable code is ever projected.
		if token && resp.StatusCode == 400 && envelope.Error == "invalid_grant" {
			return failure(401, "SESSION_INVALIDATED", ErrInvalidSession)
		}
		if token && envelope.Error == "invalid_client" {
			return failure(503, "IAM_CLIENT_INVALID", ErrUnavailable)
		}
		if resp.StatusCode == 401 {
			return failure(401, "SESSION_INVALIDATED", ErrInvalidSession)
		}
		if resp.StatusCode == 403 {
			return failure(403, "FORBIDDEN", ErrForbidden)
		}
		if resp.StatusCode >= 500 || resp.StatusCode < 400 || resp.StatusCode > 499 {
			return failure(503, "IAM_UNAVAILABLE", ErrUnavailable)
		}
		if codePattern.MatchString(envelope.Error) {
			return failure(resp.StatusCode, envelope.Error, ErrValidation)
		}
		return failure(resp.StatusCode, "IAM_REQUEST_REJECTED", ErrValidation)
	}
	if out == nil {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") || decode(data, out, false) != nil {
		return failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
	}
	return nil
}
