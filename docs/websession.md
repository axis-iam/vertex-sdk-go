# Optional server_session

`github.com/axis-iam/vertex-sdk-go/websession` is separate from JWT/Bearer
authentication. It enables a same-origin WEB application to keep OAuth credentials
on its backend. The existing oauth_tokens flow and resource-server SDK are unchanged.
Go 1.23 is required by the module manifests. The nested adapters target chi v5,
Gin v1.10 and Echo v4.13 as pinned in their manifests.

```go
store, err := websession.NewMemory(websession.MemoryOptions{})
if err != nil { return err }
defer store.Close()
service, err := websession.New(ctx, websession.Config{
    Issuer: issuer, Audience: resourceAudience,
    ClientID: webClientID, ClientSecret: clientSecret,
    Origin: "https://app.example.test",
    CallbackURL: "https://app.example.test/auth/callback",
    Scopes: []string{"openid", "profile"}, // offline_access only when authorized
    ReturnTo: "/", AllowedReturnTo: []string{"/"},
    Provider: store, Replicas: 1, Workers: 1,
})
if err != nil { return err }
mux.Handle("/auth/", service.Handler())
mux.Handle("/api/documents", service.Middleware(documents))
```

First GET `/auth/session/bootstrap`, then navigate to `/auth/login`. Hosted GET
does not require a custom header but does require that existing binding. All POSTs,
including anonymous signup/recovery, require exact configured Origin and the
bootstrap/session view's `X-CSRF-Token`. The callback consumes code on the backend,
rotates the binding/CSRF and returns to an explicitly allowed local destination.
Proxy headers and request Host never select the origin, issuer or callback.
Development HTTP requires `AllowLoopbackHTTP:true` and loopback endpoints; its
Cookie is `axis-session-dev`. Production defaults to `__Host-axis-session`,
Secure, HttpOnly, Lax, host-only and Path=/.

The finite custom routes follow the bundled [C0 contract](connected-app-bff-c0.md).
`Login` creates a controlled transaction; `Action` accepts only authenticate,
challenges, authorize, MFA, magic, complete and cancel. PASSWORD, current email/
SMS proofs, Provider and MFA are IAM policy decisions. A proof-complete
`AUTHENTICATED/complete` view is not an application identity. Only code exchange,
OIDC validation and trusted profile/permission/validity loading sign the user in.
Registration refs are opaque local purpose-bound handles; registration/recovery
never issue an authenticated view. The browser SDK consumes and scrubs email
fragments and sends the bounded CSRF magic action; HTTP cannot read a fragment.
No generic authenticated proxy or account-management expansion is installed.

Mount the same service with the selected nested adapter:

```go
// chi
r.Mount("/auth", iamchi.WebSessionHandler(service))
r.With(iamchi.WebSession(service)).Handle("/api/documents", documents)
// Gin
r.Any("/auth/*path", iamgin.WebSessionHandler(service))
r.GET("/api/documents", iamgin.WebSession(service), gin.WrapH(documents))
// Echo
e.Any("/auth/*", iamecho.WebSessionHandler(service))
e.GET("/api/documents", echo.WrapHandler(documents), iamecho.WebSession(service))
```

All four paths use the same HTTP and session logic. After explicit Middleware
validation, `websession.FromContext(ctx)` gives an isolated safe view;
`authz.FromContext(ctx)` supplies existing permission/step-up utilities. Getters
make no network calls. Business ownership and permission decisions remain with the
application. Submitted Authorization/API-key headers reject on the Cookie entry;
hosts explicitly route other credential modes before this middleware.

The same middleware also enforces the session view's CSRF token and exact
configured Origin on every unsafe business method (POST, PUT, PATCH, DELETE and
other methods outside GET/HEAD/OPTIONS), before any cached request identity is
accepted. The application should send `X-CSRF-Token: view.CSRFToken` and the
canonical `Origin`; missing, foreign or wrong values are rejected before the
business handler. Read-only GET/HEAD/OPTIONS requests keep their normal session
behavior. The example's `POST /api/documents` demonstrates this wiring.

`Provider` requires isolated Load snapshots, Create-if-absent, monotonic CAS,
atomic Rotate and terminal Invalidate. Invalidate fences callback/refresh and
late framework save/touch before remote I/O. An unavailable provider is a typed
503, never anonymous success. Implementations must reject changed owner/client/
user/session, stale version/fence, terminal state and extended original deadlines.
Run the same lifecycle and cross-instance scenarios for a custom provider's stated
scope. An `Atomic/Shared` declaration alone is not certification.

If the application already owns a native server session, use
`NewHostBinding(hostSession)` as Config.Binding. The host supplies atomic
`ReadAuthentication` / `ReplaceAuthentication` for one SDK namespace and the
single Cookie owner; no token snapshot enters an ordinary auto-saved session bag.
It retains unrelated fields, compares the originally observed auth generation,
rotates the native ID at login and refuses stale auth saves after logout/change.
This is an explicit bridge contract, not automatic compatibility with every
framework's Get/Set store. The artifact consumers exercise a replaceable host
backend and late-save interleavings through every native router. The SDK chooses
no database, driver, schema or migration.

Explicit Memory is bounded process RAM, not persistent/multiprocess storage:
10,000 sessions, 1,000 prelogins, 65,536 bytes/record, 60-second cleanup,
600-second prelogin and one-hour local absolute/idle caps clamped to IAM.
Expired records are purged on access and periodically. Short terminal tombstones
reserve capacity for at most 60 seconds; live identities are never silently
evicted. Close stops cleanup, clears sensitive state and returns typed CLOSED on
later operations. Share one instance and close it at shutdown. Declared
workers/replicas >1 reject for Memory; no automatic topology detection is claimed.

Refresh acquisition precedes HTTP and persists SEND_INTENT. After a sent timeout,
lost lease, process crash or failed token commit, the old refresh generation is
never replayed. Session loss requires new authorization. There are zero automatic
token retries. Requests have a 10-second auth budget and 5-second upstream limit;
all I/O accepts/propagates context. Original absolute deadlines never move later.
No RT means fresh authorization when AT expires.

Logout invalidates locally and clears authentication Cookie state independently
of bounded IAM revocation. It reports local/cookie/remote/SSO separately. Valid AT
uses current-session logout; expired AT plus RT revokes only the refresh family;
expired AT without RT cannot confirm remote revocation. It never refreshes merely
to log out. SSO navigation is not automatic.
Host bridges must clear browser authentication Cookie state even when namespace
storage fails, using their storage-independent Cookie clearing operation. Such a
failure reports local UNCONFIRMED and cookie CLEARED, with a 503 response.

Errors support `errors.Is` for InvalidSession, Unavailable, Forbidden,
RateLimited, ExchangeUncertain and RefreshUncertain; `errors.As` exposes
`*websession.Error` status/code and a sanitized RetryAfter. Responses never reflect
upstream diagnostics or credentials. Do not log serialized Provider records.

`scripts/verify-bff-consumers.py` stages deterministic actual module ZIPs in an
isolated file module proxy, resolves them with GOWORK off and fresh module cache,
and runs Hosted/custom/native-store tests for all routers without consumer
replace. `build/bff-consumers/manifest.json` records source/archive digests.
Its local v0.1.1 candidate coordinate is not a public tag, registry or SumDB claim.
Combined React/browser evidence additionally requires the actual fixed JS tarballs
and a controlled registered IAM WEB client; fixture tests do not establish delivery
by external Providers, email or SMS.
