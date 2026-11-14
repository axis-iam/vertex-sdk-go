package iamjwt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSProvider fetches the IAM server's JSON Web Key Set and caches it with
// lazy, coalesced refresh. It is safe for concurrent use.
type JWKSProvider struct {
	jwksURL string
	http    *http.Client
	refresh time.Duration

	mu        sync.Mutex
	set       *jose.JSONWebKeySet
	lastFetch time.Time

	// lastForcedRefresh guards the forced-refresh cooldown triggered by
	// key-rotation events (see KeyByID).
	lastForcedRefresh time.Time
	cooldown          time.Duration
	lastRefreshError  error
	refreshing        *jwksRefresh
}

type jwksRefresh struct {
	done chan struct{}
	err  error
}

// JWKSOptions configures a JWKSProvider.
type JWKSOptions struct {
	URL              string
	Client           *http.Client
	Refresh          time.Duration
	RotationCooldown time.Duration
}

// NewJWKSProvider constructs a provider. The first fetch is lazy; call
// Preload(ctx) to prime the cache eagerly.
func NewJWKSProvider(opts JWKSOptions) (*JWKSProvider, error) {
	if opts.URL == "" {
		return nil, errors.New("iamjwt: empty JWKS URL")
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if opts.Refresh <= 0 {
		opts.Refresh = time.Hour
	}
	if opts.RotationCooldown <= 0 {
		opts.RotationCooldown = 10 * time.Second
	}
	return &JWKSProvider{
		jwksURL:  opts.URL,
		http:     opts.Client,
		refresh:  opts.Refresh,
		cooldown: opts.RotationCooldown,
	}, nil
}

// Preload fetches and caches the JWKS synchronously.
func (p *JWKSProvider) Preload(ctx context.Context) error {
	return p.refreshKeys(ctx, "", true)
}

// KeyByID returns the key matching kid. If the key is absent, the provider
// force-refreshes once (subject to a cooldown) to pick up rotated keys.
func (p *JWKSProvider) KeyByID(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if err := p.refreshKeys(ctx, kid, false); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if k := p.lookup(kid); k != nil {
		return k, nil
	}
	return nil, verificationError(ErrUnknownKey, nil)
}

// lookup requires p.mu; published key sets are immutable.
func (p *JWKSProvider) lookup(kid string) *jose.JSONWebKey {
	if p.set == nil {
		return nil
	}
	if p.needsRefresh() {
		return nil // force refresh in caller
	}
	for i := range p.set.Keys {
		if p.set.Keys[i].KeyID == kid {
			key := p.set.Keys[i]
			return &key
		}
	}
	return nil
}

func (p *JWKSProvider) needsRefresh() bool {
	return time.Since(p.lastFetch) > p.refresh
}

func (p *JWKSProvider) refreshKeys(ctx context.Context, kid string, preload bool) error {
	if err := ctx.Err(); err != nil {
		return verificationError(ErrJWKSFetch, err)
	}
	p.mu.Lock()
	if !preload && p.lookup(kid) != nil {
		p.mu.Unlock()
		return nil
	}
	if pending := p.refreshing; pending != nil {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return verificationError(ErrJWKSFetch, ctx.Err())
		case <-pending.done:
			return pending.err
		}
	}
	if !preload && time.Since(p.lastForcedRefresh) < p.cooldown &&
		(p.lastRefreshError != nil || !p.needsRefresh()) {
		err := p.lastRefreshError
		p.mu.Unlock()
		return err
	}
	pending := &jwksRefresh{done: make(chan struct{})}
	p.refreshing = pending
	p.mu.Unlock()

	set, err := p.fetch(ctx)
	p.mu.Lock()
	if err == nil {
		p.set = set
		p.lastFetch = time.Now()
	}
	p.lastRefreshError = err
	pending.err = err
	if !preload || err != nil {
		p.lastForcedRefresh = time.Now()
	}
	p.refreshing = nil
	close(pending.done)
	p.mu.Unlock()
	return err
}

func (p *JWKSProvider) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return nil, verificationError(ErrJWKSFetch, err)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, verificationError(ErrJWKSFetch, err)
	}
	// Preserve the fetch/read error while always releasing the response body.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, verificationError(ErrJWKSFetch, &JWKSStatusError{StatusCode: resp.StatusCode})
	}
	const maxJWKSBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, verificationError(ErrJWKSFetch, err)
	}
	if len(body) > maxJWKSBytes {
		return nil, verificationError(ErrJWKSFetch, errors.New("JWKS response exceeds size limit"))
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, verificationError(ErrJWKSParse, err)
	}
	if set.Keys == nil {
		return nil, verificationError(ErrJWKSParse, errors.New("JWKS keys array missing"))
	}
	return &set, nil
}
