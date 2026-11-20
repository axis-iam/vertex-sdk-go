package websession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

// rpcProvider is an exclusive test fixture, not a shipped/shared production
// backend. A real OS child and parent coordinate only through its atomic API.
type rpcProvider struct{ url string }

func (*rpcProvider) Capabilities() Capabilities { return Capabilities{Atomic: true, Shared: true} }

type rpcCall struct {
	Operation, ID, NextID string
	Version               uint64
	Record                Record
}
type rpcReply struct {
	Record Record
	Error  string
}

func (p *rpcProvider) call(ctx context.Context, c rpcCall) (Record, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return Record{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(data))
	if err != nil {
		return Record{}, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = res.Body.Close() }()
	var out rpcReply
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return Record{}, err
	}
	switch out.Error {
	case "ABSENT":
		err = ErrAbsent
	case "CONFLICT":
		err = ErrConflict
	case "CAPACITY":
		err = ErrCapacity
	case "UNAVAILABLE":
		err = ErrUnavailable
	}
	return out.Record, err
}
func (p *rpcProvider) Create(ctx context.Context, id string, r Record) error {
	_, err := p.call(ctx, rpcCall{Operation: "create", ID: id, Record: r})
	return err
}
func (p *rpcProvider) Load(ctx context.Context, id string) (Record, error) {
	return p.call(ctx, rpcCall{Operation: "load", ID: id})
}
func (p *rpcProvider) CompareAndSwap(ctx context.Context, id string, v uint64, r Record) error {
	_, err := p.call(ctx, rpcCall{Operation: "cas", ID: id, Version: v, Record: r})
	return err
}
func (p *rpcProvider) Rotate(ctx context.Context, id string, v uint64, next string, r Record) error {
	_, err := p.call(ctx, rpcCall{Operation: "rotate", ID: id, NextID: next, Version: v, Record: r})
	return err
}
func (p *rpcProvider) Invalidate(ctx context.Context, id string) (Record, error) {
	return p.call(ctx, rpcCall{Operation: "invalidate", ID: id})
}

func rpcFixture(t *testing.T, m Provider) *rpcProvider {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c rpcCall
		var out rpcReply
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			w.WriteHeader(400)
			return
		}
		var err error
		switch c.Operation {
		case "create":
			err = m.Create(r.Context(), c.ID, c.Record)
		case "load":
			out.Record, err = m.Load(r.Context(), c.ID)
		case "cas":
			err = m.CompareAndSwap(r.Context(), c.ID, c.Version, c.Record)
		case "rotate":
			err = m.Rotate(r.Context(), c.ID, c.Version, c.NextID, c.Record)
		case "invalidate":
			out.Record, err = m.Invalidate(r.Context(), c.ID)
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrAbsent):
				out.Error = "ABSENT"
			case errors.Is(err, ErrConflict):
				out.Error = "CONFLICT"
			case errors.Is(err, ErrCapacity):
				out.Error = "CAPACITY"
			default:
				out.Error = "UNAVAILABLE"
			}
		}
		jsonReply(w, 200, out)
	}))
	t.Cleanup(server.Close)
	return &rpcProvider{url: server.URL}
}

func TestWebSessionConcurrentProcesses(t *testing.T) {
	if mode := os.Getenv("VERTEX_BFF_CHILD"); mode != "" {
		when, err := time.Parse(time.RFC3339Nano, os.Getenv("VERTEX_BFF_CLOCK"))
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{server: &httptest.Server{URL: os.Getenv("VERTEX_BFF_ISSUER")}, clock: &testClock{now: when}}
		s, err := New(context.Background(), f.config(&rpcProvider{url: os.Getenv("VERTEX_BFF_RPC")}))
		if err != nil {
			t.Fatal(err)
		}
		id := os.Getenv("VERTEX_BFF_ID")
		if mode == "crash-after-intent" {
			r, err := s.load(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			r, err = s.own(context.Background(), id, "refresh", r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.intent(context.Background(), id, r); err != nil {
				t.Fatal(err)
			}
			return // Process exits; no token response or commit can follow.
		}
		if _, err := s.Authenticate(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mode := range []string{"single-owner", "crash-after-intent"} {
		t.Run(mode, func(t *testing.T) {
			f, m, s := newTestService(t)
			id, _ := hostedSession(t, f, s)
			f.clock.Add(100 * time.Second)
			rpc := rpcFixture(t, m)
			parent, err := New(context.Background(), f.config(rpc))
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestWebSessionConcurrentProcesses$", "-test.count=1")
			cmd.Env = append(os.Environ(), "VERTEX_BFF_CHILD="+mode, "VERTEX_BFF_ISSUER="+f.server.URL,
				"VERTEX_BFF_RPC="+rpc.url, "VERTEX_BFF_ID="+id, "VERTEX_BFF_CLOCK="+f.clock.Time().Format(time.RFC3339Nano))
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if mode == "single-owner" {
				f.blockRefresh()
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-f.refreshStarted:
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					t.Fatal("child never refreshed")
				}
				if _, err := parent.Authenticate(context.Background(), id); !errors.Is(err, ErrConflict) {
					close(f.refreshRelease)
					_ = cmd.Wait()
					t.Fatalf("parent takeover %v", err)
				}
				close(f.refreshRelease)
				if err := cmd.Wait(); err != nil {
					t.Fatalf("child %v %s", err, output.String())
				}
				if f.refreshCount.Load() != 1 {
					t.Fatal("two process RT replay")
				}
			} else {
				if err := cmd.Run(); err != nil {
					t.Fatalf("child %v %s", err, output.String())
				}
				f.clock.Add(16 * time.Second)
				if _, err := parent.Authenticate(context.Background(), id); !errors.Is(err, ErrRefreshUncertain) {
					t.Fatal("intent takeover", err)
				}
				if f.refreshCount.Load() != 0 {
					t.Fatal("crash replay")
				}
			}
		})
	}
}
