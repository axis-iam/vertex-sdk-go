package websession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func memoryRecord(now time.Time) Record {
	return Record{SchemaVersion: 1, Kind: "prelogin", State: Prelogin, ClientID: "client", Owner: random(), CSRF: random(),
		CreatedAt: now, AbsoluteExpiresAt: now.Add(time.Minute), IdleExpiresAt: now.Add(time.Minute)}
}
func TestWebSessionMemory(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)}
	m, err := NewMemory(MemoryOptions{MaxSessions: 1, MaxPrelogins: 1, Clock: clock.Time})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	id := random()
	r := memoryRecord(clock.Time())
	r.Identifier = &Identifier{Kind: "EMAIL", Value: "reader@example.test"}
	r.Registrations = map[string]Registration{"ref": {ID: "registration", ControlSecret: "fixture-control"}}
	if err := m.Create(ctx, id, r); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, random(), r); !errors.Is(err, ErrCapacity) {
		t.Fatal("live eviction", err)
	}
	read, err := m.Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	read.CSRF = "mutated"
	read.Identifier.Value = "changed"
	read.Registrations["ref"] = Registration{}
	next, _ := m.Load(ctx, id)
	if next.CSRF != r.CSRF || next.Identifier.Value != r.Identifier.Value || next.Registrations["ref"].ControlSecret != "fixture-control" {
		t.Fatal("shared snapshot")
	}
	var winners int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, e := m.Load(ctx, id)
			if e != nil {
				return
			}
			snapshot.Version++
			snapshot.State = Owned
			// All race on expected zero; one can own this generation.
			if e = m.CompareAndSwap(ctx, id, 0, snapshot); e == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("CAS winners=%d", winners)
	}
	old, _ := m.Load(ctx, id)
	if _, err := m.Invalidate(ctx, id); err != nil {
		t.Fatal(err)
	}
	old.Version++
	if err := m.CompareAndSwap(ctx, id, old.Version-1, old); !errors.Is(err, ErrConflict) {
		t.Fatal("late save", err)
	}
	clock.Add(61 * time.Second)
	if _, err := m.Load(ctx, id); !errors.Is(err, ErrAbsent) {
		t.Fatal("TTL", err)
	}
	if err := m.Create(ctx, random(), memoryRecord(clock.Time())); err != nil {
		t.Fatal("capacity purge", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(ctx, id); !errors.Is(err, ErrClosed) {
		t.Fatal("closed read", err)
	}
	if err := m.Create(ctx, random(), memoryRecord(clock.Time())); !errors.Is(err, ErrClosed) {
		t.Fatal("closed write", err)
	}
	restarted, _ := NewMemory(MemoryOptions{Clock: clock.Time})
	defer func() { _ = restarted.Close() }()
	if _, err := restarted.Load(ctx, id); !errors.Is(err, ErrAbsent) {
		t.Fatal("restart recovered session")
	}
	if _, err := NewMemory(MemoryOptions{MaxRecordBytes: -1}); err == nil {
		t.Fatal("negative limit")
	}
	small, err := NewMemory(MemoryOptions{MaxRecordBytes: 64, Clock: clock.Time})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = small.Close() }()
	if err := small.Create(ctx, random(), memoryRecord(clock.Time())); !errors.Is(err, ErrCapacity) {
		t.Fatal("record size", err)
	}
}
