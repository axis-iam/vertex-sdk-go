package websession

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// MemoryOptions are finite per-process limits. Zero selects the C0 default;
// negative values reject. Clock is optional and intended for deterministic tests.
type MemoryOptions struct {
	MaxSessions, MaxPrelogins, MaxRecordBytes int
	CleanupInterval                           time.Duration
	Clock                                     func() time.Time
}

// Memory is a bounded, volatile, single-process Provider. Share one instance
// between handlers and close it at application shutdown. It never evicts live
// identities. Restart means reauthorization, not remote IAM revocation.
type Memory struct {
	mu      sync.Mutex
	records map[string]Record
	opts    MemoryOptions
	stop    chan struct{}
	done    chan struct{}
	closed  bool
}

func NewMemory(opts MemoryOptions) (*Memory, error) {
	if opts.MaxSessions < 0 || opts.MaxPrelogins < 0 || opts.MaxRecordBytes < 0 || opts.CleanupInterval < 0 {
		return nil, invalid()
	}
	if opts.MaxSessions == 0 {
		opts.MaxSessions = 10000
	}
	if opts.MaxPrelogins == 0 {
		opts.MaxPrelogins = 1000
	}
	if opts.MaxRecordBytes == 0 {
		opts.MaxRecordBytes = 65536
	}
	if opts.CleanupInterval == 0 {
		opts.CleanupInterval = time.Minute
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	m := &Memory{records: make(map[string]Record), opts: opts, stop: make(chan struct{}), done: make(chan struct{})}
	go m.cleanup()
	return m, nil
}

func (*Memory) Capabilities() Capabilities { return Capabilities{Atomic: true} }

func (m *Memory) cleanup() {
	defer close(m.done)
	t := time.NewTicker(m.opts.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.mu.Lock()
			m.purge()
			m.mu.Unlock()
		}
	}
}

func (m *Memory) Close() error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		clear(m.records)
		close(m.stop)
	}
	m.mu.Unlock()
	<-m.done
	return nil
}

func (m *Memory) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed {
		return ErrClosed
	}
	return nil
}

func expired(r Record, now time.Time) bool {
	return !now.Before(r.AbsoluteExpiresAt) || !now.Before(r.IdleExpiresAt)
}

func (m *Memory) purge() {
	now := m.opts.Clock()
	for id, r := range m.records {
		if expired(r, now) {
			delete(m.records, id)
		}
	}
}

func (m *Memory) validate(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return invalid()
	}
	if len(b) > m.opts.MaxRecordBytes {
		return ErrCapacity
	}
	if r.SchemaVersion != SchemaVersion || r.Version != 0 || r.CreatedAt.IsZero() ||
		!r.AbsoluteExpiresAt.After(r.CreatedAt) || r.IdleExpiresAt.After(r.AbsoluteExpiresAt) ||
		expired(r, m.opts.Clock()) || (r.Kind != "prelogin" && r.Kind != "session") ||
		r.ClientID == "" || !randomValue(r.Owner) || !randomValue(r.CSRF) {
		return invalid()
	}
	if (r.Kind == "prelogin" && r.State != Prelogin) || (r.Kind == "session" && r.State != SignedIn) {
		return invalid()
	}
	cap := time.Hour
	if r.Kind == "prelogin" {
		cap = 600 * time.Second
	}
	if r.AbsoluteExpiresAt.Sub(r.CreatedAt) > cap || r.CreatedAt.After(m.opts.Clock()) {
		return invalid()
	}
	return nil
}

func (m *Memory) capacity(kind string) error {
	count := 0
	for _, r := range m.records {
		if r.Kind == kind {
			count++
		}
	}
	limit := m.opts.MaxSessions
	if kind == "prelogin" {
		limit = m.opts.MaxPrelogins
	}
	if count >= limit {
		return ErrCapacity
	}
	return nil
}

func (m *Memory) Create(ctx context.Context, id string, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return err
	}
	m.purge()
	if !randomValue(id) {
		return invalid()
	}
	if _, ok := m.records[id]; ok {
		return ErrConflict
	}
	if err := m.validate(r); err != nil {
		return err
	}
	if err := m.capacity(r.Kind); err != nil {
		return err
	}
	m.records[id] = clone(r)
	return nil
}

func (m *Memory) Load(ctx context.Context, id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return Record{}, err
	}
	r, ok := m.records[id]
	if !ok {
		return Record{}, ErrAbsent
	}
	if expired(r, m.opts.Clock()) {
		delete(m.records, id)
		return Record{}, ErrAbsent
	}
	if r.State == Invalidated {
		return Record{}, ErrAbsent
	}
	return clone(r), nil
}

func (m *Memory) current(id string, expected uint64) (Record, error) {
	r, ok := m.records[id]
	if !ok || r.State == Invalidated || expired(r, m.opts.Clock()) || r.Version != expected {
		return Record{}, ErrConflict
	}
	return r, nil
}

func (m *Memory) CompareAndSwap(ctx context.Context, id string, expected uint64, next Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return err
	}
	old, err := m.current(id, expected)
	if err != nil {
		return err
	}
	if next.Version != old.Version+1 || next.SchemaVersion != old.SchemaVersion ||
		next.CreatedAt != old.CreatedAt || next.AbsoluteExpiresAt.After(old.AbsoluteExpiresAt) ||
		next.IdleExpiresAt.After(next.AbsoluteExpiresAt) || next.Kind != old.Kind || next.ClientID != old.ClientID ||
		next.Owner != old.Owner || next.CSRF != old.CSRF ||
		!sameIdentity(old, next) {
		return ErrConflict
	}
	if old.State == SendIntent && (next.Fence != old.Fence || next.Operation != old.Operation) {
		return ErrConflict
	}
	if !contains([]string{Prelogin, SignedIn, Owned, SendIntent}, next.State) ||
		(next.State == Prelogin && next.Kind != "prelogin") || (next.State == SignedIn && next.Kind != "session") {
		return ErrConflict
	}
	b, err := json.Marshal(next)
	if err != nil {
		return invalid()
	}
	if len(b) > m.opts.MaxRecordBytes {
		return ErrCapacity
	}
	m.records[id] = clone(next)
	return nil
}

func sameIdentity(old, next Record) bool {
	if old.Profile == nil {
		return next.Profile == nil
	}
	if next.Profile == nil || old.Profile.ID != next.Profile.ID {
		return false
	}
	a, b := old.Profile.AuthenticationContext, next.Profile.AuthenticationContext
	if a.ClientID != b.ClientID || a.ApplicationID != b.ApplicationID || a.SessionID != b.SessionID {
		return false
	}
	return equalOptional(a.OrganizationID, b.OrganizationID)
}

func equalOptional(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func (m *Memory) Rotate(ctx context.Context, oldID string, expected uint64, newID string, next Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return err
	}
	if _, err := m.current(oldID, expected); err != nil {
		return err
	}
	m.purge()
	if _, exists := m.records[newID]; exists {
		return ErrConflict
	}
	if !randomValue(newID) {
		return invalid()
	}
	if err := m.validate(next); err != nil {
		return err
	}
	if err := m.capacity(next.Kind); err != nil {
		return err
	}
	m.records[newID] = clone(next)
	m.terminate(oldID)
	return nil
}

func (m *Memory) terminate(id string) {
	r := m.records[id]
	until := minTime(r.AbsoluteExpiresAt, m.opts.Clock().Add(60*time.Second))
	m.records[id] = Record{SchemaVersion: SchemaVersion, Version: r.Version + 1,
		State: Invalidated, Kind: r.Kind, CreatedAt: r.CreatedAt,
		AbsoluteExpiresAt: until, IdleExpiresAt: until}
}

func (m *Memory) Invalidate(ctx context.Context, id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return Record{}, err
	}
	r, ok := m.records[id]
	if !ok || r.State == Invalidated {
		return Record{}, ErrAbsent
	}
	m.terminate(id)
	return clone(r), nil
}
