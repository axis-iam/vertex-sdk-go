package websession

import (
	"context"
	"encoding/json"
	"time"

	iam "github.com/axis-iam/vertex-sdk-go"
)

const (
	SchemaVersion = 1
	Prelogin      = "PRELOGIN"
	SignedIn      = "SIGNED_IN"
	Owned         = "OWNED"
	SendIntent    = "SEND_INTENT"
	Invalidated   = "INVALIDATED"
)

// Record is sensitive server-side state, never a browser DTO. Providers must
// isolate snapshots and fence stale saves, including framework automatic saves.
// All times are absolute; CreatedAt and AbsoluteExpiresAt cannot be extended.
type Record struct {
	SchemaVersion     int
	Version           uint64
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
	IdleExpiresAt     time.Time
	State             string
	Kind              string // "prelogin" or "session"
	ClientID          string
	Owner             string
	CSRF              string
	OAuthState        string
	Verifier          string
	Nonce             string
	ReturnTo          string
	TransactionID     string
	ControlSecret     string
	LoginState        string
	NextAction        string
	Identifier        *Identifier
	MagicConsumed     bool
	Registrations     map[string]Registration
	AccessToken       string
	RefreshToken      string
	AccessExpiresAt   time.Time
	Profile           *iam.CurrentUser
	Permissions       *Permissions
	Operation         string
	Fence             string
	LeaseExpiresAt    time.Time
}

func (Record) String() string   { return "websession.Record(<redacted>)" }
func (Record) GoString() string { return "websession.Record(<redacted>)" }

// Capabilities describe operations whose semantics must be proved by a provider.
// Shared must only be true for an actually coordinated multi-process backend.
type Capabilities struct {
	Atomic bool
	Shared bool
}

// Provider owns only the SDK namespace. A normal session dictionary's Get/Set
// does not satisfy this contract. CAS increments Version and rejects terminal
// state, expired state, changed identity and extended absolute deadlines.
// Rotate atomically terminates oldID and creates newID, or does neither.
// Invalidate is terminal and returns the captured previous record for revocation.
// It must fence every outstanding operation before returning.
type Provider interface {
	Capabilities() Capabilities
	Create(ctx context.Context, id string, record Record) error
	Load(ctx context.Context, id string) (Record, error)
	CompareAndSwap(ctx context.Context, id string, expected uint64, record Record) error
	Rotate(ctx context.Context, oldID string, expected uint64, newID string, record Record) error
	Invalidate(ctx context.Context, id string) (Record, error)
}

func clone(r Record) Record {
	// Record contains only JSON values; providers accept validated records and
	// never retain caller-owned pointers. Failure is impossible for this schema.
	data, err := json.Marshal(r)
	if err != nil {
		panic("websession: non-JSON record")
	}
	var out Record
	if err := json.Unmarshal(data, &out); err != nil {
		panic("websession: invalid record clone")
	}
	return out
}

type Permissions struct {
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type Identifier struct {
	Kind   string  `json:"kind"`
	Value  string  `json:"value"`
	Region *string `json:"region,omitempty"`
}

type Registration struct {
	ID            string
	ControlSecret string
	ExpiresAt     time.Time
}
