package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const PermissionsSyncScope = "permissions:sync"

type PermissionManifestMode string

const (
	PermissionManifestValidate PermissionManifestMode = "validate"
	PermissionManifestUpsert   PermissionManifestMode = "upsert"
)

type PermissionManifestDeclaration struct {
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

func (d PermissionManifestDeclaration) Key() string { return d.Resource + ":" + d.Action }

type PermissionManifest struct {
	ManifestID  string                          `json:"manifestId"`
	Revision    string                          `json:"revision"`
	Permissions []PermissionManifestDeclaration `json:"permissions"`
}

type PreparedPermissionManifest struct {
	Mode        PermissionManifestMode          `json:"mode"`
	ManifestID  string                          `json:"manifestId"`
	Revision    string                          `json:"revision"`
	Fingerprint string                          `json:"fingerprint"`
	Permissions []PermissionManifestDeclaration `json:"permissions"`
}

type PermissionManifestItem struct {
	Key       string `json:"key"`
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
}

type PermissionManifestDrift struct {
	Key    string `json:"key"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}

type PermissionManifestCounts struct {
	Created     int `json:"created"`
	Updated     int `json:"updated"`
	Unchanged   int `json:"unchanged"`
	Resurrected int `json:"resurrected"`
	Conflict    int `json:"conflict"`
	Drift       int `json:"drift"`
}

type PermissionManifestResult struct {
	Mode        PermissionManifestMode    `json:"mode"`
	ManifestID  string                    `json:"manifestId"`
	Revision    string                    `json:"revision"`
	Fingerprint string                    `json:"fingerprint"`
	Applied     bool                      `json:"applied"`
	Results     []PermissionManifestItem  `json:"results"`
	Drift       []PermissionManifestDrift `json:"drift"`
	Counts      PermissionManifestCounts  `json:"counts"`
}

type PermissionManifestClientConfig struct {
	IssuerEndpoint    string
	PortalAPIEndpoint string
	ClientID          string
	ClientSecret      string
	Timeout           time.Duration
	TokenSkew         time.Duration
	MaxRetries        int
	MaxRetryDelay     time.Duration
	HTTPClient        *http.Client
	Observer          func(PermissionManifestObservation)
}

type PermissionManifestObservation struct {
	Mode     PermissionManifestMode
	Outcome  string
	Status   int
	Duration time.Duration
}

type PermissionManifestError struct {
	Status            int
	Code              string
	Message           string
	CorrelationID     string
	RetryAfterSeconds int
	Body              string
}

func (e *PermissionManifestError) Error() string {
	if e.Status == 0 {
		return "iam permission manifest: " + e.Code + ": " + e.Message
	}
	return fmt.Sprintf("iam permission manifest: %s: HTTP %d: %s", e.Code, e.Status, e.Message)
}

type PermissionManifestClient struct {
	issuerEndpoint    string
	portalAPIEndpoint string
	clientID          string
	clientSecret      string
	tokenSkew         time.Duration
	maxRetries        int
	maxRetryDelay     time.Duration
	http              *http.Client
	observer          func(PermissionManifestObservation)
	mu                sync.Mutex
	token             *permissionManifestToken
}

type permissionManifestToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

var (
	manifestIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	revisionPattern         = regexp.MustCompile(`^[A-Za-z0-9._:@/+~-]{1,128}$`)
	segmentPattern          = regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)
	fingerprintPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idempotencyPattern      = regexp.MustCompile(`^[\x21-\x7e]{8,128}$`)
	retryableManifestStatus = map[int]bool{408: true, 429: true, 502: true, 503: true, 504: true}
)

func PreparePermissionManifest(manifest PermissionManifest, mode PermissionManifestMode) (PreparedPermissionManifest, error) {
	if mode != PermissionManifestValidate && mode != PermissionManifestUpsert {
		return PreparedPermissionManifest{}, errors.New("iam permission manifest: mode must be validate or upsert")
	}
	if !manifestIDPattern.MatchString(manifest.ManifestID) {
		return PreparedPermissionManifest{}, errors.New("iam permission manifest: invalid manifestId")
	}
	if !revisionPattern.MatchString(manifest.Revision) {
		return PreparedPermissionManifest{}, errors.New("iam permission manifest: invalid revision")
	}
	if manifest.Permissions == nil || len(manifest.Permissions) > 1000 {
		return PreparedPermissionManifest{}, errors.New("iam permission manifest: permissions must contain at most 1000 declarations")
	}
	permissions := append([]PermissionManifestDeclaration(nil), manifest.Permissions...)
	for _, declaration := range permissions {
		if err := validateManifestDeclaration(declaration); err != nil {
			return PreparedPermissionManifest{}, err
		}
	}
	sort.Slice(permissions, func(i, j int) bool { return permissions[i].Key() < permissions[j].Key() })
	for i := 1; i < len(permissions); i++ {
		if permissions[i-1].Key() == permissions[i].Key() {
			return PreparedPermissionManifest{}, errors.New("iam permission manifest: duplicate permission key")
		}
	}
	return PreparedPermissionManifest{Mode: mode, ManifestID: manifest.ManifestID, Revision: manifest.Revision, Fingerprint: sha256Hex(canonicalManifest(permissions)), Permissions: permissions}, nil
}

func PermissionDeclarationRevision(declaration PermissionManifestDeclaration) (string, error) {
	if err := validateManifestDeclaration(declaration); err != nil {
		return "", err
	}
	return sha256Hex(canonicalDeclaration(declaration)), nil
}

func NewPermissionManifestClient(cfg PermissionManifestClientConfig) (*PermissionManifestClient, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.IssuerEndpoint), "/")
	portal := strings.TrimRight(strings.TrimSpace(cfg.PortalAPIEndpoint), "/")
	clientID := strings.TrimSpace(cfg.ClientID)
	clientSecret := strings.TrimSpace(cfg.ClientSecret)
	if issuer == "" || portal == "" || clientID == "" || clientSecret == "" {
		return nil, errors.New("iam permission manifest: issuerEndpoint, portalApiEndpoint, clientId and clientSecret are required")
	}
	if cfg.TokenSkew < 0 || cfg.MaxRetries < 0 || cfg.MaxRetryDelay < 0 {
		return nil, errors.New("iam permission manifest: retry and token skew values must be non-negative")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 5*time.Second {
		return nil, errors.New("iam permission manifest: timeout exceeds five seconds")
	}
	tokenSkew := cfg.TokenSkew
	if tokenSkew == 0 {
		tokenSkew = 30 * time.Second
	}
	maxRetryDelay := cfg.MaxRetryDelay
	if maxRetryDelay == 0 {
		maxRetryDelay = 5 * time.Second
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &PermissionManifestClient{issuerEndpoint: issuer, portalAPIEndpoint: portal, clientID: clientID, clientSecret: clientSecret, tokenSkew: tokenSkew, maxRetries: cfg.MaxRetries, maxRetryDelay: maxRetryDelay, http: httpClient, observer: cfg.Observer}, nil
}

func (c *PermissionManifestClient) ValidatePermissionManifest(ctx context.Context, manifest PermissionManifest) (*PermissionManifestResult, error) {
	prepared, err := PreparePermissionManifest(manifest, PermissionManifestValidate)
	if err != nil {
		return nil, err
	}
	return c.observed(ctx, prepared, "/open/v1/permission-manifests:sync", "")
}

func (c *PermissionManifestClient) UpsertPermissionManifest(ctx context.Context, manifest PermissionManifest, idempotencyKey string) (*PermissionManifestResult, error) {
	if err := requireManifestIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	prepared, err := PreparePermissionManifest(manifest, PermissionManifestUpsert)
	if err != nil {
		return nil, err
	}
	return c.observed(ctx, prepared, "/open/v1/permission-manifests:sync", idempotencyKey)
}

func (c *PermissionManifestClient) observed(ctx context.Context, prepared PreparedPermissionManifest, path, idempotencyKey string) (*PermissionManifestResult, error) {
	started := time.Now()
	result, err := c.send(ctx, prepared, path, idempotencyKey)
	if c.observer != nil {
		status := 200
		outcome := "SUCCESS"
		if err != nil {
			outcome = "ERROR"
			status = 0
			var protocol *PermissionManifestError
			if errors.As(err, &protocol) {
				status = protocol.Status
			}
		}
		c.observer(PermissionManifestObservation{Mode: prepared.Mode, Outcome: outcome, Status: status, Duration: time.Since(started)})
	}
	return result, err
}

func (c *PermissionManifestClient) ClearPermissionManifestTokenCache() {
	c.mu.Lock()
	c.token = nil
	c.mu.Unlock()
}

func (c *PermissionManifestClient) send(ctx context.Context, prepared PreparedPermissionManifest, path, idempotencyKey string) (*PermissionManifestResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	budget := &permissionManifestBudget{attempts: 3}
	token, err := c.machineToken(ctx, budget)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(prepared)
	if err != nil {
		return nil, fmt.Errorf("iam permission manifest: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.portalAPIEndpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, responseBody, err := c.execute(ctx, req, budget)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parsePermissionManifestError(resp, responseBody)
	}
	var wire permissionManifestResultWire
	if err := decodeStrictJSON(responseBody, &wire); err != nil {
		return nil, &PermissionManifestError{Code: "INVALID_MANIFEST_RESPONSE", Message: err.Error(), Body: string(responseBody)}
	}
	result, err := wire.result()
	if err != nil {
		return nil, &PermissionManifestError{Code: "INVALID_MANIFEST_RESPONSE", Message: err.Error(), Body: string(responseBody)}
	}
	if err := validateManifestResult(result, prepared); err != nil {
		return nil, &PermissionManifestError{Code: "INVALID_MANIFEST_RESPONSE", Message: err.Error(), Body: string(responseBody)}
	}
	return &result, nil
}

func (c *PermissionManifestClient) machineToken(ctx context.Context, budget *permissionManifestBudget) (*permissionManifestToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil && c.token.ExpiresAt.After(time.Now()) {
		value := *c.token
		return &value, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {PermissionsSyncScope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuerEndpoint+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.clientID+":"+c.clientSecret)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, body, err := c.execute(ctx, req, budget)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parsePermissionManifestTokenError(resp, body)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := decodeStrictJSON(body, &payload); err != nil || payload.AccessToken == "" || !strings.EqualFold(payload.TokenType, "bearer") || payload.ExpiresIn <= 0 || payload.Scope != PermissionsSyncScope {
		return nil, &PermissionManifestError{Status: resp.StatusCode, Code: "INVALID_TOKEN_RESPONSE", Message: "invalid exact-scope machine token response"}
	}
	ttl := time.Duration(payload.ExpiresIn)*time.Second - c.tokenSkew
	if ttl < 0 {
		ttl = 0
	}
	c.token = &permissionManifestToken{AccessToken: payload.AccessToken, ExpiresAt: time.Now().Add(ttl)}
	value := *c.token
	return &value, nil
}

func parsePermissionManifestTokenError(resp *http.Response, body []byte) error {
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := decodeStrictJSON(body, &payload); err == nil && payload.Error != "" {
		return &PermissionManifestError{Status: resp.StatusCode, Code: payload.Error, Message: "permission manifest machine token request failed"}
	}
	return &PermissionManifestError{Status: resp.StatusCode, Code: "INVALID_ERROR_RESPONSE", Message: "invalid machine token error response"}
}

func (c *PermissionManifestClient) execute(ctx context.Context, request *http.Request, budget *permissionManifestBudget) (*http.Response, []byte, error) {
	var last error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if !budget.consume() {
			return nil, nil, &PermissionManifestError{Code: "COMMAND_TIMEOUT", Message: "permission manifest command budget exhausted"}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		clone := request.Clone(attemptCtx)
		if request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				cancel()
				return nil, nil, err
			}
			clone.Body = body
		}
		resp, err := c.http.Do(clone)
		if err != nil {
			cancel()
			last = err
			if attempt == c.maxRetries || budget.empty() {
				break
			}
			if err := waitContext(ctx, minDuration(time.Duration(250*(1<<attempt))*time.Millisecond, c.maxRetryDelay)); err != nil {
				return nil, nil, err
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
		resp.Body.Close()
		cancel()
		if err != nil {
			last = err
			if attempt == c.maxRetries {
				break
			}
			continue
		}
		if len(body) > 1024*1024 {
			return nil, nil, &PermissionManifestError{Status: resp.StatusCode, Code: "RESPONSE_SIZE_EXCEEDED", Message: "IAM response exceeds 1 MiB"}
		}
		if !retryableManifestStatus[resp.StatusCode] || attempt == c.maxRetries || budget.empty() {
			return resp, body, nil
		}
		delay := time.Duration(250*(1<<attempt)) * time.Millisecond
		if seconds, ok := parseManifestRetryAfter(resp.Header.Get("Retry-After")); ok {
			delay = time.Duration(seconds) * time.Second
		}
		if err := waitContext(ctx, minDuration(delay, c.maxRetryDelay)); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, &PermissionManifestError{Code: "TRANSPORT_ERROR", Message: last.Error()}
}

type permissionManifestBudget struct{ attempts int }

func (b *permissionManifestBudget) consume() bool {
	if b.attempts == 0 {
		return false
	}
	b.attempts--
	return true
}
func (b *permissionManifestBudget) empty() bool { return b.attempts == 0 }

type permissionManifestCountsWire struct {
	Created     *int `json:"created"`
	Updated     *int `json:"updated"`
	Unchanged   *int `json:"unchanged"`
	Resurrected *int `json:"resurrected"`
	Conflict    *int `json:"conflict"`
	Drift       *int `json:"drift"`
}
type permissionManifestResultWire struct {
	Mode        *PermissionManifestMode       `json:"mode"`
	ManifestID  *string                       `json:"manifestId"`
	Revision    *string                       `json:"revision"`
	Fingerprint *string                       `json:"fingerprint"`
	Applied     *bool                         `json:"applied"`
	Results     *[]PermissionManifestItem     `json:"results"`
	Drift       *[]PermissionManifestDrift    `json:"drift"`
	Counts      *permissionManifestCountsWire `json:"counts"`
}

func (w permissionManifestResultWire) result() (PermissionManifestResult, error) {
	if w.Mode == nil || w.ManifestID == nil || w.Revision == nil || w.Fingerprint == nil || w.Applied == nil || w.Results == nil || w.Drift == nil || w.Counts == nil || w.Counts.Created == nil || w.Counts.Updated == nil || w.Counts.Unchanged == nil || w.Counts.Resurrected == nil || w.Counts.Conflict == nil || w.Counts.Drift == nil {
		return PermissionManifestResult{}, errors.New("missing required manifest result field")
	}
	return PermissionManifestResult{Mode: *w.Mode, ManifestID: *w.ManifestID, Revision: *w.Revision, Fingerprint: *w.Fingerprint, Applied: *w.Applied, Results: *w.Results, Drift: *w.Drift, Counts: PermissionManifestCounts{Created: *w.Counts.Created, Updated: *w.Counts.Updated, Unchanged: *w.Counts.Unchanged, Resurrected: *w.Counts.Resurrected, Conflict: *w.Counts.Conflict, Drift: *w.Counts.Drift}}, nil
}

type PermissionManifestStartupMode int

const (
	PermissionManifestDisabled PermissionManifestStartupMode = iota
	PermissionManifestCIValidate
	PermissionManifestDeploymentUpsert
	PermissionManifestDevelopmentStartup
)

type PermissionManifestFailurePolicy int

const (
	PermissionManifestFailurePolicyUnset PermissionManifestFailurePolicy = iota
	PermissionManifestFailFast
	PermissionManifestContinue
)

type PermissionManifestStartupOptions struct {
	Mode            PermissionManifestStartupMode
	FailurePolicy   PermissionManifestFailurePolicy
	IdempotencyKey  string
	OnContinueError func(PermissionManifestContinueEvent)
}

type PermissionManifestContinueEvent struct {
	Mode    string
	Outcome string
	Status  int
	Code    string
}

type PermissionManifestStartupResult struct {
	NetworkAttempted bool
	Continued        bool
	Result           *PermissionManifestResult
}

func RunPermissionManifestStartup(ctx context.Context, client *PermissionManifestClient, manifest PermissionManifest, options PermissionManifestStartupOptions) (PermissionManifestStartupResult, error) {
	if options.Mode == PermissionManifestDisabled {
		return PermissionManifestStartupResult{NetworkAttempted: false}, nil
	}
	if options.Mode == PermissionManifestDevelopmentStartup && options.FailurePolicy == PermissionManifestFailurePolicyUnset {
		return PermissionManifestStartupResult{}, errors.New("iam permission manifest: DEVELOPMENT_STARTUP requires explicit failurePolicy")
	}
	if options.Mode == PermissionManifestDevelopmentStartup && options.FailurePolicy == PermissionManifestContinue && options.OnContinueError == nil {
		return PermissionManifestStartupResult{}, errors.New("iam permission manifest: DEVELOPMENT_STARTUP with CONTINUE requires OnContinueError")
	}
	if client == nil {
		return PermissionManifestStartupResult{}, errors.New("iam permission manifest: client is required")
	}
	var result *PermissionManifestResult
	var err error
	switch options.Mode {
	case PermissionManifestCIValidate:
		result, err = client.ValidatePermissionManifest(ctx, manifest)
	case PermissionManifestDeploymentUpsert, PermissionManifestDevelopmentStartup:
		result, err = client.UpsertPermissionManifest(ctx, manifest, options.IdempotencyKey)
	default:
		return PermissionManifestStartupResult{}, errors.New("iam permission manifest: unknown startup mode")
	}
	if err != nil && options.Mode == PermissionManifestDevelopmentStartup && options.FailurePolicy == PermissionManifestContinue {
		status, code := 0, "UNEXPECTED_ERROR"
		var protocol *PermissionManifestError
		if errors.As(err, &protocol) {
			status, code = protocol.Status, protocol.Code
		}
		options.OnContinueError(PermissionManifestContinueEvent{Mode: "DEVELOPMENT_STARTUP", Outcome: "CONTINUED", Status: status, Code: code})
		return PermissionManifestStartupResult{NetworkAttempted: true, Continued: true}, nil
	}
	return PermissionManifestStartupResult{NetworkAttempted: true, Result: result}, err
}

func validateManifestDeclaration(value PermissionManifestDeclaration) error {
	if !segmentPattern.MatchString(value.Resource) || !segmentPattern.MatchString(value.Action) {
		return errors.New("iam permission manifest: invalid concrete permission key")
	}
	if err := validateManifestText(value.Name, 128, "name"); err != nil {
		return err
	}
	if value.Description != nil {
		if err := validateManifestText(*value.Description, 512, "description"); err != nil {
			return err
		}
	}
	for field, text := range map[string]string{"resource": value.Resource, "action": value.Action, "name": value.Name} {
		if !utf8.ValidString(text) || !norm.NFC.IsNormalString(text) {
			return fmt.Errorf("iam permission manifest: %s must already be NFC", field)
		}
	}
	if value.Description != nil && (!utf8.ValidString(*value.Description) || !norm.NFC.IsNormalString(*value.Description)) {
		return errors.New("iam permission manifest: description must already be NFC")
	}
	return nil
}

func validateManifestText(value string, max int, field string) error {
	if value == "" || utf16Length(value) > max || strings.TrimSpace(value) != value {
		return fmt.Errorf("iam permission manifest: invalid %s", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("iam permission manifest: invalid %s", field)
		}
	}
	return nil
}

func utf16Length(value string) int {
	length := 0
	for _, r := range value {
		length += utf16.RuneLen(r)
	}
	return length
}

func canonicalManifest(permissions []PermissionManifestDeclaration) []byte {
	var b strings.Builder
	b.WriteString(`{"permissions":[`)
	for i, p := range permissions {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(canonicalDeclaration(p))
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}
func canonicalDeclaration(value PermissionManifestDeclaration) []byte {
	var b strings.Builder
	b.WriteString(`{"action":`)
	appendJCSString(&b, value.Action)
	b.WriteString(`,"description":`)
	if value.Description == nil {
		b.WriteString("null")
	} else {
		appendJCSString(&b, *value.Description)
	}
	b.WriteString(`,"name":`)
	appendJCSString(&b, value.Name)
	b.WriteString(`,"resource":`)
	appendJCSString(&b, value.Resource)
	b.WriteByte('}')
	return []byte(b.String())
}
func appendJCSString(b *strings.Builder, value string) {
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r <= 0x1f {
				b.WriteString(`\u`)
				b.WriteString(fmt.Sprintf("%04x", r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
func sha256Hex(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }

func decodeStrictJSON(body []byte, target any) error {
	if err := rejectDuplicateJSONMembers(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}
func rejectDuplicateJSONMembers(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate JSON member %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}

func validateManifestResult(result PermissionManifestResult, request PreparedPermissionManifest) error {
	if result.Mode != request.Mode || result.ManifestID != request.ManifestID || result.Revision != request.Revision || result.Fingerprint != request.Fingerprint || !fingerprintPattern.MatchString(result.Fingerprint) || result.Applied != (request.Mode == PermissionManifestUpsert) {
		return errors.New("manifest identity or applied state mismatch")
	}
	operations := map[string]int{"CREATE": 0, "UPDATE": 0, "UNCHANGED": 0, "RESURRECT": 0, "CONFLICT": 0}
	reasons := map[string]bool{"DECLARATION_ACCEPTED": true, "MANUAL_COLLISION": true, "LEGACY_CODE_UNATTRIBUTED": true, "CODE_OWNER_COLLISION": true}
	driftKinds := map[string]bool{"MANUAL_COLLISION": true, "LEGACY_CODE_UNATTRIBUTED": true, "CODE_OWNER_COLLISION": true, "ABSENT_DECLARATION": true}
	last := ""
	for _, item := range result.Results {
		if !validManifestKey(item.Key) || item.Key <= last || !reasons[item.Reason] {
			return errors.New("invalid manifest result item")
		}
		if _, ok := operations[item.Operation]; !ok {
			return errors.New("unknown manifest operation")
		}
		operations[item.Operation]++
		last = item.Key
	}
	last = ""
	for _, item := range result.Drift {
		if !validManifestKey(item.Key) || item.Key <= last || !driftKinds[item.Kind] || (item.Source != "CODE" && item.Source != "MANUAL") {
			return errors.New("invalid manifest drift")
		}
		last = item.Key
	}
	if result.Counts.Created != operations["CREATE"] || result.Counts.Updated != operations["UPDATE"] || result.Counts.Unchanged != operations["UNCHANGED"] || result.Counts.Resurrected != operations["RESURRECT"] || result.Counts.Conflict != operations["CONFLICT"] || result.Counts.Drift != len(result.Drift) {
		return errors.New("manifest result counts mismatch")
	}
	return nil
}

func parsePermissionManifestError(resp *http.Response, body []byte) error {
	var payload struct {
		Status        int    `json:"status"`
		Error         string `json:"error"`
		Message       string `json:"message"`
		Timestamp     string `json:"timestamp"`
		CorrelationID string `json:"correlationId"`
	}
	if err := decodeStrictJSON(body, &payload); err != nil || payload.Status != resp.StatusCode || payload.Error == "" || payload.Message == "" || payload.Timestamp == "" {
		return &PermissionManifestError{Status: resp.StatusCode, Code: "INVALID_ERROR_RESPONSE", Message: "invalid permission manifest error response", Body: string(body)}
	}
	seconds, _ := parseManifestRetryAfter(resp.Header.Get("Retry-After"))
	return &PermissionManifestError{Status: payload.Status, Code: payload.Error, Message: payload.Message, CorrelationID: payload.CorrelationID, RetryAfterSeconds: seconds, Body: string(body)}
}
func parseManifestRetryAfter(value string) (int, bool) {
	if value == "" || len(value) > 5 || value[0] == '0' {
		return 0, false
	}
	seconds, err := strconv.Atoi(value)
	return seconds, err == nil && seconds > 0 && seconds <= 86400
}
func requireManifestIdempotencyKey(value string) error {
	if !idempotencyPattern.MatchString(value) {
		return errors.New("iam permission manifest: Idempotency-Key must be 8-128 visible ASCII characters")
	}
	return nil
}
func validManifestKey(value string) bool {
	parts := strings.Split(value, ":")
	return len(parts) == 2 && segmentPattern.MatchString(parts[0]) && segmentPattern.MatchString(parts[1])
}
func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
