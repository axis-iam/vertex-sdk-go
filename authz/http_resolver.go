package authz

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/sync/singleflight"
)

// ResolveClient is the minimum surface HttpResolver needs from the IAM client.
// It is satisfied by *iam.Client.
type ResolveClient interface {
	ResolvePermissions(ctx context.Context, clientID string, roles []string) (*ResolvePermissionsResponse, error)
}

// ResolvePermissionsResponse must match the shape returned by the IAM server.
// It is redeclared here (rather than imported from the top-level iam package)
// to avoid an import cycle.
type ResolvePermissionsResponse struct {
	Permissions []string `json:"permissions"`
}

// HttpResolver resolves role → permission mappings via the IAM /open/v1 API
// with a local ristretto cache and singleflight deduplication.
type HttpResolver struct {
	client   ResolveClient
	cache    *ristretto.Cache[string, []string]
	sf       singleflight.Group
	ttl      time.Duration
	failOpen bool
	cacheMax int64
}

// HttpResolverOptions configures an HttpResolver.
type HttpResolverOptions struct {
	TTL        time.Duration
	MaxEntries int64
	FailOpen   bool
}

// NewHttpResolver wires up a resolver backed by ristretto.
func NewHttpResolver(client ResolveClient, opts HttpResolverOptions) (*HttpResolver, error) {
	if client == nil {
		return nil, errors.New("authz: nil resolve client")
	}
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 10_000
	}
	cache, err := ristretto.NewCache(&ristretto.Config[string, []string]{
		NumCounters: opts.MaxEntries * 10,
		MaxCost:     opts.MaxEntries,
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}
	return &HttpResolver{
		client:   client,
		cache:    cache,
		ttl:      opts.TTL,
		failOpen: opts.FailOpen,
		cacheMax: opts.MaxEntries,
	}, nil
}

// Resolve implements Resolver.
func (r *HttpResolver) Resolve(ctx context.Context, clientID string, roles []string) ([]string, error) {
	if len(roles) == 0 {
		return []string{}, nil
	}
	key := cacheKey(clientID, roles)
	if v, ok := r.cache.Get(key); ok {
		return v, nil
	}
	v, err, _ := r.sf.Do(key, func() (any, error) {
		resp, err := r.client.ResolvePermissions(ctx, clientID, roles)
		if err != nil {
			return nil, err
		}
		r.cache.SetWithTTL(key, resp.Permissions, 1, r.ttl)
		return resp.Permissions, nil
	})
	if err != nil {
		if r.failOpen {
			return nil, nil
		}
		return nil, err
	}
	perms, _ := v.([]string)
	return perms, nil
}

// Invalidate drops the cached mapping for a (clientID, roles) pair.
func (r *HttpResolver) Invalidate(clientID string, roles []string) {
	r.cache.Del(cacheKey(clientID, roles))
}

// Clear evicts every cached entry.
func (r *HttpResolver) Clear() { r.cache.Clear() }

func cacheKey(clientID string, roles []string) string {
	cp := append([]string(nil), roles...)
	sort.Strings(cp)
	var b strings.Builder
	b.WriteString(clientID)
	b.WriteByte('|')
	for i, r := range cp {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(r)
	}
	return b.String()
}
