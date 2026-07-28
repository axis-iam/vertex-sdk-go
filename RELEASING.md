# Releasing 0.1.1

The first public beta uses stable module versions and prerelease release metadata. Do not add a semantic-version
prerelease suffix.

The exact planned tag set is:

- `v0.1.1` for `github.com/axis-iam/vertex-sdk-go`
- `chi/v0.1.1` for `github.com/axis-iam/vertex-sdk-go/chi`
- `gin/v0.1.1` for `github.com/axis-iam/vertex-sdk-go/gin`
- `echo/v0.1.1` for `github.com/axis-iam/vertex-sdk-go/echo`

Create and push the root tag first. Verify that the Go proxy can resolve the root module at `v0.1.1`, then create
the three nested-module tags from the same reviewed commit. Nested module files require the root module at
`v0.1.1` and contain no `replace` directive. `go.work` is only the repository development workspace and is not
part of any published module contract.

Tag creation, tag push and GitHub Release creation require separate coordinator approval. The first beta GitHub
Release is marked prerelease even though the tag is exactly `v0.1.1`.
