# Headless Account Security

These APIs operate on the explicitly supplied **current-user access token**. The configured
confidential client's secret is never substituted for user authorization. The server enforces
Application/user/client/session ownership, proof expiry and login-method versions. A machine
token cannot become a self-service principal. No method opens a browser, refreshes a session,
starts another operation, caches secrets or automatically retries an unknown mutation.

Save the operation ID and a caller-generated non-secret idempotency key before starting. Reuse
the same key and identical typed create request to recover a lost creation response; do not
silently generate a new key. After an uncertain begin/complete/provider exchange, query the
saved operation ID. A new authenticated session of the same owner/client can read terminal
results, but cannot take over pending mutations. A transfer counterpart may receive nullable
`result`/`completion` because the producer deliberately redacts the initiator's metadata.

`AVAILABLE` delivers TOTP material or recovery codes once. `ALREADY_DELIVERED` has no secret;
status queries never redeliver it. If enrollment material was lost, explicitly cancel or let
it expire before creating a new operation. If generated recovery codes were lost, only an
explicitly authorized new generation replaces them. Do not log request bodies, passwords,
OTPs, provider exchange verifiers, material or codes. Their diagnostic representations are
redacted, but intentional serialization/access still reveals them.

Honor typed `sessionImpact`: `CURRENT_SESSION_RETAINED` refreshes application security facts;
`REAUTHENTICATE` requires your application to clear its own user session and initiate legitimate
reauthentication; `UNCHANGED` does not imply an extra logout. The SDK performs none of these
application/session transitions implicitly. Server proof options, not anonymous login metadata,
determine executable PASSWORD/EMAIL_OTP/PROVIDER/scoped TOTP/WebAuthn actions.

Requests are closed typed payloads. Optional fields are omitted rather than serialized as null;
complete uses an omitted code for non-enrollment operations. Missing required response
fields, unsupported enum values, duplicate JSON members and malformed one-time delivery are protocol errors,
not empty success. Stable HTTP error codes and strictly parsed nonnegative integer Retry-After
seconds remain available without raw provider diagnostics. Invalid/overflow retry values produce
no delay, not a retry or a successful result. Cancellation/interruption propagates through the
language's existing context/timeout boundary. No unsafe mutation is replayed automatically.

## Public Calls

Entry: root `iam.Client` and `iam.SDK` in `github.com/axis-iam/vertex-sdk-go`. All I/O takes
`context.Context` first. Framework adapters use this same SDK/client, without a second HTTP layer.
Errors support `errors.As` for `*AccountSecurityError`, `*AccountSecurityProtocolError`,
`*AccountSecurityTransportError`; cancellation/deadline is preserved by `errors.Is`.
`CompleteMFAOperation` takes `*string`: nil omits code; a pointer to an empty code is invalid.

| Method | Producer route |
| --- | --- |
| `GetRecoveryCodesRemaining` | GET `/api/v1/auth/mfa/recovery-codes/remaining` |
| `ListAccountIdentifiers` | GET `/api/v1/auth/me/identifiers` |
| `ListAccountLoginMethods` | GET `/api/v1/auth/me/login-methods` |
| `ListLinkableIdentityProviders` | GET `/api/v1/auth/me/linkable-identity-providers` |
| `CreateIdentityOperation` | POST `/api/v1/auth/me/identity-operations` |
| `GetIdentityOperation` | GET `/api/v1/auth/me/identity-operations/{id}` |
| `ListIdentityTransfers` | GET `/api/v1/auth/me/identity-operations/transfers` |
| `ReauthenticateIdentityOperation` | POST `/api/v1/auth/me/identity-operations/{id}/reauthenticate` |
| `ChallengeIdentityOperation` | POST `/api/v1/auth/me/identity-operations/{id}/challenges` |
| `ChallengeIdentityCurrentAccount` | POST `/api/v1/auth/me/identity-operations/{id}/current-account/challenges` |
| `CompleteIdentityOperation` | POST `/api/v1/auth/me/identity-operations/{id}/complete` |
| `CancelIdentityOperation` | POST `/api/v1/auth/me/identity-operations/{id}/cancel` |
| `ConfirmIdentityTransfer` | POST `/api/v1/auth/me/identity-operations/{id}/confirm-transfer` |
| `AuthorizeIdentityOperation` | POST `/api/v1/auth/me/identity-operations/{id}/authorize` |
| `CompleteIdentityProviderAuthorization` | POST `/api/v1/auth/me/identity-operations/{id}/provider-callback` |
| `GetMFACapabilities` | GET `/api/v1/auth/mfa/capabilities` |
| `CreateMFAOperation` | POST `/api/v1/auth/mfa/operations` |
| `GetMFAOperation` | GET `/api/v1/auth/mfa/operations/{id}` |
| `ReauthenticateMFAOperation` | POST `/api/v1/auth/mfa/operations/{id}/reauthenticate` |
| `ChallengeMFAOperation` | POST `/api/v1/auth/mfa/operations/{id}/challenges` |
| `AuthorizeMFAOperation` | POST `/api/v1/auth/mfa/operations/{id}/authorize` |
| `CompleteMFAProviderAuthorization` | POST `/api/v1/auth/mfa/operations/{id}/provider-callback` |
| `BeginTOTPEnrollmentOperation` | POST `/api/v1/auth/mfa/operations/{id}/begin` |
| `CompleteMFAOperation` | POST `/api/v1/auth/mfa/operations/{id}/complete` |
| `CancelMFAOperation` | POST `/api/v1/auth/mfa/operations/{id}/cancel` |
| `StartIdentityOperationStepUp` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/start` |
| `VerifyIdentityOperationStepUp` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/verify` |
| `StartIdentityOperationWebAuthn` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/webauthn/start` |
| `VerifyIdentityOperationWebAuthn` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/webauthn/verify` |
| `StartMFAOperationStepUp` | POST `/api/v1/auth/mfa/operations/{id}/step-up/start` |
| `VerifyMFAOperationStepUp` | POST `/api/v1/auth/mfa/operations/{id}/step-up/verify` |
| `StartMFAOperationWebAuthn` | POST `/api/v1/auth/mfa/operations/{id}/step-up/webauthn/start` |
| `VerifyMFAOperationWebAuthn` | POST `/api/v1/auth/mfa/operations/{id}/step-up/webauthn/verify` |

## Recovery Example

```go
import iam "github.com/axis-iam/vertex-sdk-go"

capabilities, err := client.GetMFACapabilities(ctx, userToken)
if err != nil { return err }
operation, err := client.CreateMFAOperation(ctx, userToken, iam.MFAOperationCreate{
    Type: iam.MFAOperationTypeTOTPEnroll,
    ExpectedLoginMethodVersion: capabilities.LoginMethodVersion,
}, callerRetainedIdempotencyKey)
if err != nil { return err }
// Retain operation.ID; execute only the returned proof options, then explicitly begin/complete.
_, err = client.GetMFAOperation(ctx, userToken, operation.ID)
return err
```


## Authenticated Identifier Management and LINK Target

`listAccountIdentifiers` (language-equivalent name) returns server facts plus nullable `management`.
`management.add` is keyed by USERNAME/EMAIL/PHONE; each identifier's nullable `capabilities`
is keyed by VERIFY/SET_PRIMARY/REMOVE/REPLACE/TRANSFER. Each capability carries `allowed`,
`unavailableReasons`, `requirements`, and the exact eligible `replacementPrimaryIds`.
`management.proofOptions` lists the actual current-account proof channels. These are authenticated
advisory snapshots, not grants: do not derive management permission from anonymous login metadata,
identifier status, a catalog entry, or a configured client secret. Missing/null snapshots remain
absent; the SDK never manufactures an allowed action or substitutes a denial.

Denials are typed: ACCOUNT_INACTIVE, MANAGED_IDENTIFIER, METHOD_UNAVAILABLE,
REAUTH_METHOD_UNAVAILABLE, TARGET_PROOF_UNAVAILABLE, IDENTIFIER_ALREADY_EXISTS, NOT_APPLICABLE,
ALREADY_VERIFIED, ALREADY_PRIMARY, IDENTIFIER_UNVERIFIED, IDENTIFIER_RANGE_REJECTED,
LAST_LOGIN_METHOD and PRIMARY_REPLACEMENT_UNAVAILABLE. Requirements are typed:
CURRENT_ACCOUNT_PROOF, NEW_IDENTIFIER, TARGET_EMAIL_OTP, TARGET_PHONE_OTP, REPLACEMENT_PRIMARY,
REMOVE_OLD, COUNTERPART_CONFIRMATION and REMAINING_LOGIN_PATH. Present replacement choices to the
caller; never silently pick the first ID. Preserve the snapshot's login-method version when
creating a selected operation, and honor its actual required proofs. Mutations still revalidate
ownership, current policy/range, security version, and the last usable login path. Grandfathered
existing identifiers may remain verifiable/promotable/removable even when new ADD/REPLACE/TRANSFER
values are outside the current binding range; do not override the server's per-action decision.

An identity operation's nullable `providerTarget` comes from the **actual verified LINK adapter
result**: `providerId`, nullable/omittable `maskedDisplayName` and `maskedEmail`, and opaque
64-lowercase-hex `reference`. Display only these returned masks. Do not use Provider catalog names
or an already-linked identity as the new target, invent a fallback identity, interpret the reference
as a subject, or store raw provider claims. The target may be absent before proof; cancelled,
expired, rejected and counterpart views do not supply it. Successful LINK status/replay/committed
reads may retain the same target. The SDK does not synthesize transitions, enforce another user's
ownership locally, authorize an action from the presentation, or open a browser.

Known required fields/types/enums and malformed references remain strict protocol errors;
additive unknown response fields (including nested fields) are ignored and not retained. Duplicate
JSON members and trailing JSON remain invalid. Reserved `material`/`recoveryCodes` members on an
MFA status are not treated as future extensions: non-null redelivery is a protocol error. Optional request fields are still omitted rather
than sent as null; no new request keys or endpoint were invented for these response additions.

```go
snapshot, err := client.ListAccountIdentifiers(ctx, userToken)
if err != nil { return err }
if snapshot.Management != nil {
    addEmail, present := snapshot.Management.Add[iam.IdentifierKindEmail]
    if present && addEmail.Allowed {
        // Present addEmail.Requirements and snapshot.Management.ProofOptions.
        // A later create uses snapshot.LoginMethodVersion and a retained request key.
    }
}
operation, err := client.GetIdentityOperation(ctx, userToken, retainedOperationID)
if err != nil { return err }
if operation.ProviderTarget != nil {
    target := operation.ProviderTarget
    _ = target // Present the nullable masks, never a catalog/linked-identity substitute.
}
```

## Live Recovery-Code Remainder

Use the explicit current-user `getRecoveryCodesRemaining` equivalent (method table below) to read
`GET /api/v1/auth/mfa/recovery-codes/remaining`. The typed `RecoveryCodesRemaining` response has
only `remaining`, a nonnegative integer count of currently unused codes. This read is uncached and
never returns old plaintext recovery codes. Its bearer identifies the current owner; the configured
client secret is not substituted and there is no arbitrary userId or Application override argument.
The producer remains authoritative for authenticated user/Application ownership.

Read again after generation or consumption: `operation.result.recoveryCount` records how many
codes were generated at completion, NOT the live remainder. Do not use it, a local decrement, or
a cached generation response instead of this endpoint. Errors retain the usual sanitized typed
HTTP/code/Retry-After contract; malformed/missing/negative/overflow counts fail as protocol errors.
Additive unknown response fields stay compatible, but reserved plaintext `codes`/`recoveryCodes`/
`material` on this count response are rejected. No code-generation, verification, refresh, browser
flow or retry of an uncertain mutation is triggered by the read.

Public methods: `Client.GetRecoveryCodesRemaining(ctx, accessToken)` and the actual
high-level `SDK.GetRecoveryCodesRemaining(ctx, accessToken)` delegate.

```go
live, err := sdk.GetRecoveryCodesRemaining(ctx, userToken)
if err != nil { return err }
currentlyUnused := live.Remaining
_ = currentlyUnused // Display the current count, never old plaintext codes.
```
