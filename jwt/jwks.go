package iamjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSProvider fetches the IAM server's JSON Web Key Set and caches it with
// background refresh. It is safe for concurrent use.
type JWKSProvider struct {
	jwksURL string
	http    *http.Client
	refresh time.Duration

	mu        sync.RWMutex
	set       *jose.JSONWebKeySet
	lastFetch time.Time

	// lastForcedRefresh guards the forced-refresh cooldown triggered by
	// key-rotation events (see KeyByID).
	lastForcedRefresh time.Time
	cooldown          time.Duration
}

// JWKSOptions configures a JWKSProvider.
type JWKSOptions struct {
	URL            string
	Client         *http.Client
	Refresh        time.Duration
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
	_, err := p.fetch(ctx)
	return err
}

// KeyByID returns the key matching kid. If the key is absent, the provider
// force-refreshes once (subject to a cooldown) to pick up rotated keys.
func (p *JWKSProvider) KeyByID(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if k := p.lookup(kid); k != nil {
		return k, nil
	}
	// force refresh once to handle rotation
	p.mu.Lock()
	if time.Since(p.lastForcedRefresh) < p.cooldown {
		p.mu.Unlock()
		return nil, fmt.Errorf("iamjwt: unknown kid %q (rotation cooldown active)", kid)
	}
	p.lastForcedRefresh = time.Now()
	p.mu.Unlock()

	if _, err := p.fetch(ctx); err != nil {
		return nil, err
	}
	if k := p.lookup(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("iamjwt: unknown kid %q", kid)
}

func (p *JWKSProvider) lookup(kid string) *jose.JSONWebKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.set == nil {
		return nil
	}
	if p.needsRefresh() {
		return nil // force refresh in caller
	}
	for i := range p.set.Keys {
		if p.set.Keys[i].KeyID == kid {
			return &p.set.Keys[i]
		}
	}
	return nil
}

func (p *JWKSProvider) needsRefresh() bool {
	return time.Since(p.lastFetch) > p.refresh
}

func (p *JWKSProvider) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("iamjwt: jwks fetch failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.set = &set
	p.lastFetch = time.Now()
	p.mu.Unlock()
	return &set, nil
}
