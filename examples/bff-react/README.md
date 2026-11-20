# Go + React connected application

This standalone example hosts the SDK inside an ordinary Go application and serves
the React bundle at the same origin. Choose Hosted or the SDK's existing embedded
sign-in component. It does not modify an external business application.

The new connected-application JS packages must be installed from their actual
candidate tarballs until released. Install both packages together (no workspace
links), record their SHA-256, then build:

```sh
npm install --no-save /path/to/axis-iam-vertex-candidate.tgz /path/to/axis-iam-vertex-react-candidate.tgz
npm run build
```

The package.json coordinates document public identities; version 0.1.0 alone
does not establish that the registry contains this candidate's C0 transport.
Do not substitute source imports or an older dist for the combined browser proof.

The IAM registered callback remains `/auth/callback`. The Go host consumes that
callback and redirects to its configured `ReturnTo: "/"`. React's
`sessionProviderReturnUri` therefore names the exact clean app root URL, ending
in `/`. In server_session mode the Provider popup waits for that final URL;
pointing it at the intermediate callback would leave the popup waiting.
Keep this value aligned if the host's final return destination changes.

Build `../bff-server` against the Go candidate module archive/proxy using
`GOWORK=off go mod tidy` and `GOWORK=off go build .`. Configure:

```sh
export APP_ORIGIN=http://127.0.0.1:34040
export APP_LISTEN=127.0.0.1:34040
export APP_ALLOW_LOOPBACK_HTTP=true
export APP_WEB_DIR=/absolute/path/to/bff-react/dist
export IAM_ISSUER=https://iam.example.test
export IAM_AUDIENCE=api://your-application
export IAM_CLIENT_ID=your-web-client
export IAM_CALLBACK_URL=http://127.0.0.1:34040/auth/callback
export IAM_SCOPES='openid profile offline_access'
# Provide IAM_CLIENT_SECRET only to the Go process through your secret mechanism.
```

Register that exact WEB callback/origin and authorize only the scopes enabled for
the client. Offline access is optional; omit it when not authorized. Without a
refresh token the SDK requires a fresh authorization at access-token expiry.
Configure `APP_PASSWORD_RESET_URL` only for a registered proof landing URL.

Run one process. Its explicitly selected bounded Memory provider is shared by all
handlers; restarting loses local sessions and does not revoke IAM sessions.
For multiple workers/replicas, inject a qualified atomic shared Provider and, if
the host already owns its Cookie, one `HostSession` bridge.

The frontend receives only public config, safe session views and ordinary business
data. The write example sends the current safe view's CSRF token plus the exact
same-origin `Origin` to `POST /api/documents`; the shared Go middleware rejects
missing, foreign or wrong values before business code. No client secret, PKCE
material, code exchange or token endpoint runs there.
Provider and email/MFA continuation UI is owned by the actual JS package. Verify
its fixed candidate in a browser before claiming those combined flows.
