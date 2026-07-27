// Package middleware provides framework-agnostic net/http middleware that
// wires the IAM SDK into any Go router. Framework-specific adapters (chi,
// gin, echo) live in their own submodules and delegate here where possible.
package middleware
