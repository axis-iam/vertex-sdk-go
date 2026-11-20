package websession

import (
	"context"
	"net/http"
	"time"
)

// HostSnapshot identifies the SDK namespace in an existing native server
// session. Version is an authentication generation, independent of unrelated
// application fields. NativeID and Handle are backend-only.
type HostSnapshot struct {
	NativeID string
	Version  uint64
	Handle   string
}

// HostSession connects an existing host session's single Cookie owner.
// ReplaceAuthentication must atomically compare the captured snapshot, rotate
// the native session ID on login, and change/clear only the SDK auth namespace.
// It must reject stale auth auto-save/touch after logout or account change and
// preserve unrelated fields. An absent session returns a zero snapshot.
// Host-owned Cookie attributes must satisfy the C0 production Cookie contract.
// Ordinary Get/Set session libraries need a real atomic backend bridge; declaring
// this interface does not confer distributed safety on them.
type HostSession interface {
	AtomicAuthentication() bool
	ReadAuthentication(ctx context.Context, r *http.Request) (HostSnapshot, error)
	ReplaceAuthentication(ctx context.Context, w http.ResponseWriter, r *http.Request, expected HostSnapshot, handle string, expires time.Time) error
	// ClearAuthenticationCookie is an unconditional response-header operation
	// owned by the host, with no storage dependency. It expires the same native
	// Cookie when the authentication namespace could not be cleared atomically.
	ClearAuthenticationCookie(w http.ResponseWriter, r *http.Request)
}

type HostBinding struct{ host HostSession }
type hostSnapshotKey struct{ binding *HostBinding }

func NewHostBinding(host HostSession) (*HostBinding, error) {
	if host == nil || !host.AtomicAuthentication() {
		return nil, invalid()
	}
	return &HostBinding{host: host}, nil
}

func (b *HostBinding) Read(ctx context.Context, r *http.Request) (string, error) {
	key := hostSnapshotKey{binding: b}
	if snapshot, ok := r.Context().Value(key).(HostSnapshot); ok {
		return snapshot.Handle, nil
	}
	snapshot, err := b.host.ReadAuthentication(ctx, r)
	if err != nil {
		return "", err
	}
	if snapshot.Handle != "" && !randomValue(snapshot.Handle) {
		return "", invalid()
	}
	*r = *r.WithContext(context.WithValue(r.Context(), key, snapshot))
	return snapshot.Handle, nil
}

func (b *HostBinding) replace(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, expires time.Time) error {
	snapshot, ok := r.Context().Value(hostSnapshotKey{binding: b}).(HostSnapshot)
	if !ok {
		return invalid()
	} // A write must use the observed generation.
	return b.host.ReplaceAuthentication(ctx, w, r, snapshot, id, expires)
}
func (b *HostBinding) Write(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, expires time.Time) error {
	if !randomValue(id) {
		return invalid()
	}
	return b.replace(ctx, w, r, id, expires)
}
func (b *HostBinding) Clear(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	err := b.replace(ctx, w, r, "", time.Time{})
	if err != nil {
		b.host.ClearAuthenticationCookie(w, r)
	}
	return err
}
