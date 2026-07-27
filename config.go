package iam

import (
	"errors"
	"time"
)

// ResolveMode controls how the SDK loads role→permission mappings.
type ResolveMode int

const (
	// ResolveOnDemand resolves permissions on the first request for a role
	// set and caches the result. This is the default.
	ResolveOnDemand ResolveMode = iota
	// ResolveFullSync pre-loads every role→permission mapping at startup.
	ResolveFullSync
)

// FailMode controls how the SDK behaves when the permission resolver errors.
type FailMode int

const (
	// FailClose denies the request when resolution fails. Default.
	FailClose FailMode = iota
	// FailOpen allows the request through with an empty permission set.
	FailOpen
)

// SDKConfig is the runtime configuration accepted by New.
type SDKConfig struct {
	// Endpoint is the base URL of the IAM server, e.g. https://iam.example.com.
	Endpoint string
	// ClientID is ApplicationClient.clientId for the WEB/M2M confidential client
	// used by this server-side SDK.
	ClientID string
	// ClientSecret authenticates the WEB/M2M confidential ApplicationClient.
	ClientSecret string
	// Audience expected in JWTs. Defaults to ClientID.
	Audience string
	// Issuer expected in JWTs. Defaults to Endpoint.
	Issuer string

	// JWKSRefresh is the interval at which the JWKS is refreshed. Default 1h.
	JWKSRefresh time.Duration
	// PermissionCacheTTL is the TTL of the role→permissions cache. Default 5m.
	PermissionCacheTTL time.Duration
	// PermissionCacheMax is the maximum number of cache entries. Default 10000.
	PermissionCacheMax int64
	// UserProfileCacheTTL is the TTL for explicit /api/v1/auth/me profile lookups. Default 1m.
	UserProfileCacheTTL time.Duration
	// UserProfileCacheMax is the maximum number of user profile cache entries. Default 10000.
	UserProfileCacheMax int64
	// DisableUserProfileCache disables caching for SDK.GetMe. Client.GetMe is always uncached.
	DisableUserProfileCache bool

	ResolveMode ResolveMode
	FailMode    FailMode

	HTTPTimeout time.Duration // default 5s
	MaxRetries  int           // default 3
}

// Validate normalises defaults and returns an error for missing required fields.
func (c *SDKConfig) Validate() error {
	if c == nil {
		return errors.New("iam: nil SDKConfig")
	}
	if c.Endpoint == "" {
		return errors.New("iam: SDKConfig.Endpoint is required")
	}
	if c.ClientID == "" {
		return errors.New("iam: SDKConfig.ClientID is required")
	}
	if c.ClientSecret == "" {
		return errors.New("iam: SDKConfig.ClientSecret is required for WEB/M2M confidential ApplicationClient")
	}
	if c.Audience == "" {
		c.Audience = c.ClientID
	}
	if c.Issuer == "" {
		c.Issuer = c.Endpoint
	}
	if c.JWKSRefresh <= 0 {
		c.JWKSRefresh = time.Hour
	}
	if c.PermissionCacheTTL <= 0 {
		c.PermissionCacheTTL = 5 * time.Minute
	}
	if c.PermissionCacheMax <= 0 {
		c.PermissionCacheMax = 10_000
	}
	if c.UserProfileCacheTTL <= 0 {
		c.UserProfileCacheTTL = time.Minute
	}
	if c.UserProfileCacheMax <= 0 {
		c.UserProfileCacheMax = 10_000
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 5 * time.Second
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = 3
	}
	return nil
}
