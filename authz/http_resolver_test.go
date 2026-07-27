package authz

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClient struct {
	calls int32
	fn    func(ctx context.Context, clientID string, roles []string) (*ResolvePermissionsResponse, error)
}

func (f *fakeClient) ResolvePermissions(ctx context.Context, clientID string, roles []string) (*ResolvePermissionsResponse, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.fn(ctx, clientID, roles)
}

func TestHttpResolver_Cache(t *testing.T) {
	fc := &fakeClient{fn: func(_ context.Context, _ string, _ []string) (*ResolvePermissionsResponse, error) {
		return &ResolvePermissionsResponse{Permissions: []string{"posts:read"}}, nil
	}}
	r, err := NewHttpResolver(fc, HttpResolverOptions{TTL: time.Second, MaxEntries: 100})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.Resolve(ctx, "app", []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	// Wait for ristretto to admit and process the write buffer.
	r.cache.Wait()
	for range 4 {
		if _, err := r.Resolve(ctx, "app", []string{"admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&fc.calls); got > 1 {
		t.Fatalf("expected 1 call after cache warm, got %d", got)
	}
}

func TestHttpResolver_FailClose(t *testing.T) {
	fc := &fakeClient{fn: func(_ context.Context, _ string, _ []string) (*ResolvePermissionsResponse, error) {
		return nil, errors.New("boom")
	}}
	r, _ := NewHttpResolver(fc, HttpResolverOptions{FailOpen: false})
	if _, err := r.Resolve(context.Background(), "app", []string{"admin"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestHttpResolver_ZeroRolesDoesNotCallClient(t *testing.T) {
	fc := &fakeClient{fn: func(_ context.Context, _ string, _ []string) (*ResolvePermissionsResponse, error) {
		t.Fatal("zero roles must not call IAM")
		return nil, nil
	}}
	r, _ := NewHttpResolver(fc, HttpResolverOptions{})
	permissions, err := r.Resolve(context.Background(), "app", nil)
	if err != nil || len(permissions) != 0 || atomic.LoadInt32(&fc.calls) != 0 {
		t.Fatalf("permissions=%v err=%v calls=%d", permissions, err, fc.calls)
	}
}

func TestHttpResolver_FailOpen(t *testing.T) {
	fc := &fakeClient{fn: func(_ context.Context, _ string, _ []string) (*ResolvePermissionsResponse, error) {
		return nil, errors.New("boom")
	}}
	r, _ := NewHttpResolver(fc, HttpResolverOptions{FailOpen: true})
	perms, err := r.Resolve(context.Background(), "app", []string{"admin"})
	if err != nil || perms != nil {
		t.Fatalf("expected fail-open to return (nil, nil); got %v / %v", perms, err)
	}
}

func TestHttpResolver_SingleflightDedup(t *testing.T) {
	var inflight int32
	var peak int32
	block := make(chan struct{})
	fc := &fakeClient{fn: func(_ context.Context, _ string, _ []string) (*ResolvePermissionsResponse, error) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n > p {
				if atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
				continue
			}
			break
		}
		<-block
		atomic.AddInt32(&inflight, -1)
		return &ResolvePermissionsResponse{Permissions: []string{"posts:read"}}, nil
	}}
	r, _ := NewHttpResolver(fc, HttpResolverOptions{})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Resolve(context.Background(), "app", []string{"admin"})
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()
	if peak > 1 {
		t.Fatalf("singleflight broken: peak inflight %d", peak)
	}
}

func TestCacheKey_OrderInsensitive(t *testing.T) {
	if cacheKey("a", []string{"x", "y"}) != cacheKey("a", []string{"y", "x"}) {
		t.Fatal("cacheKey should sort roles")
	}
}
