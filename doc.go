// Package iam is the entry point for github.com/axis-iam/vertex-sdk-go, a Go SDK
// that integrates with the IAM Authentication Center.
//
// It exposes:
//
//   - SDKConfig — runtime configuration for the SDK
//   - SDK       — orchestrator that wires JWT verification, permission
//     resolution and optional startup-time permission registration
//   - Shortcut constructors for net/http middleware via the
//     github.com/axis-iam/vertex-sdk-go/middleware sub-package
//
// Framework-specific adapters live in their own submodules to avoid pulling
// unrelated router dependencies into callers:
//
//   - github.com/axis-iam/vertex-sdk-go/chi
//   - github.com/axis-iam/vertex-sdk-go/gin
//   - github.com/axis-iam/vertex-sdk-go/echo
package iam
