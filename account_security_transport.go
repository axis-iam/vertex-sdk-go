package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// AccountSecurityError retains only stable producer metadata, never a raw error body.
type AccountSecurityError struct {
	Status            int
	Code              string
	RetryAfterSeconds *int
}

func (e *AccountSecurityError) Error() string {
	return fmt.Sprintf("iam account security: HTTP %d %s", e.Status, e.Code)
}

// AccountSecurityProtocolError indicates a missing or malformed known wire field.
type AccountSecurityProtocolError struct{}

func (*AccountSecurityProtocolError) Error() string {
	return "iam: invalid or unsupported account security response"
}

// AccountSecurityTransportError means a mutation may have committed. It is never retried by this SDK.
type AccountSecurityTransportError struct {
	OutcomeUnknown bool
	cause          error
}

func (*AccountSecurityTransportError) Error() string {
	return "iam: account security transport failed; no automatic replay"
}
func (e *AccountSecurityTransportError) Unwrap() error { return e.cause }

var securityUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var securityProviderReference = regexp.MustCompile(`^[0-9a-f]{64}$`)
var securityCode = regexp.MustCompile(`^[0-9]{6}$`)
var securityPKCE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var securityVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var securityErrorCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
var securityRetry = regexp.MustCompile(`^[0-9]{1,10}$`)

func securityInputError() error {
	return errors.New("iam: invalid or missing typed security request field")
}
func securityToken(value string) (string, error) {
	token := strings.TrimPrefix(value, "Bearer ")
	if token == "" {
		return "", securityInputError()
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return "", securityInputError()
		}
	}
	return token, nil
}
func securityKey(key string) bool {
	if strings.TrimSpace(key) == "" || len(key) > 256 {
		return false
	}
	for _, c := range key {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func securityEnum(value, name string) bool {
	allowed, ok := securityEnums[name]
	if !ok {
		return false
	}
	for _, s := range strings.Fields(allowed) {
		if value == s {
			return true
		}
	}
	return false
}
func validateSecurityRequest(request any) error {
	if request == nil {
		return securityInputError()
	}
	v := reflect.ValueOf(request)
	if v.Kind() != reflect.Struct {
		return securityInputError()
	}
	t := v.Type()
	if t.PkgPath() != reflect.TypeOf(MFAOperationCreate{}).PkgPath() || !securityRequestTypes[t.Name()] {
		return securityInputError()
	}
	for i := 0; i < v.NumField(); i++ {
		f := t.Field(i)
		item := v.Field(i)
		if item.Kind() == reflect.Interface {
			if item.IsNil() {
				return securityInputError()
			}
			if err := validateSecurityRequest(item.Interface()); err != nil {
				return err
			}
		} else if item.Kind() == reflect.Pointer {
			if item.IsNil() {
				if f.Tag.Get("wire") == "optional" {
					continue
				}
				return securityInputError()
			}
			item = item.Elem()
		}
		if item.Kind() == reflect.Struct {
			if err := validateSecurityRequest(item.Interface()); err != nil {
				return err
			}
		}
		if item.Kind() == reflect.String {
			value := item.String()
			if strings.TrimSpace(value) == "" {
				return securityInputError()
			}
			if _, ok := securityEnums[item.Type().Name()]; ok && !securityEnum(value, item.Type().Name()) {
				return securityInputError()
			}
			if strings.HasSuffix(f.Name, "ID") && f.Name != "MethodID" && f.Name != "RequestID" && !(f.Name == "ChallengeID" && t.Name() != "EmailOTPReauthentication") && !securityUUID.MatchString(value) {
				return securityInputError()
			}
			if f.Name == "Code" && !securityCode.MatchString(value) {
				return securityInputError()
			}
		}
		if f.Name == "ExpectedLoginMethodVersion" && item.Int() < 0 {
			return securityInputError()
		}
		if item.Kind() == reflect.Slice {
			if item.IsNil() {
				return securityInputError()
			}
			for k := 0; k < item.Len(); k++ {
				if err := validateSecurityRequest(item.Index(k).Interface()); err != nil {
					return err
				}
			}
		}
	}
	switch r := request.(type) {
	case IdentityOperationCreate:
		switch r.Payload.(type) {
		case AddIdentity, VerifyIdentity, SetPrimaryIdentity, RemoveIdentity, ReplaceIdentity, LinkIdentity, UnlinkIdentity, TransferIdentity:
		default:
			return securityInputError()
		}
	case PasswordReauthentication:
		if len(r.Password) > 128 {
			return securityInputError()
		}
	case ProviderExchange:
		if !securityVerifier.MatchString(r.CodeVerifier) {
			return securityInputError()
		}
	case MFAProviderAuthorize:
		if r.CodeChallengeMethod != "S256" || !securityPKCE.MatchString(r.CodeChallenge) {
			return securityInputError()
		}
	case IdentityProviderAuthorize:
		if r.CodeChallengeMethod != "S256" || !securityPKCE.MatchString(r.CodeChallenge) {
			return securityInputError()
		}
	case IdentityOperationComplete:
		if len(r.Proofs) > 1 {
			return securityInputError()
		}
	}
	return nil
}
func (c *Client) accountSecurityRequest(ctx context.Context, method, path, token, key string, body, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return securityInputError()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint()+path, bytes.NewReader(raw))
	if err != nil {
		return securityInputError()
	}
	// Idempotency-Key must not enable net/http's automatic request-body replay.
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	scoped := *c.http
	scoped.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := scoped.Do(req)
	if err != nil {
		return &AccountSecurityTransportError{OutcomeUnknown: method != "GET", cause: err}
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil {
		return &AccountSecurityTransportError{OutcomeUnknown: method != "GET", cause: err}
	}
	if len(raw) > 1048576 {
		return &AccountSecurityProtocolError{}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return securityAPIError(response.StatusCode, raw, response.Header.Get("Retry-After"))
	}
	if err := decodeSecurityJSON(raw, out); err != nil {
		return &AccountSecurityProtocolError{}
	}
	if err := validateSecurityJSON(raw, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	return nil
}
func securityAPIError(status int, raw []byte, retry string) error {
	var wire struct {
		Status    int             `json:"status"`
		Error     string          `json:"error"`
		Message   string          `json:"message"`
		Timestamp string          `json:"timestamp"`
		Details   json.RawMessage `json:"details"`
	}
	if err := decodeSecurityJSON(raw, &wire); err != nil || wire.Status != status || !securityErrorCode.MatchString(wire.Error) {
		return &AccountSecurityProtocolError{}
	}
	var delay *int
	if securityRetry.MatchString(retry) {
		n, err := strconv.ParseInt(retry, 10, 64)
		if err == nil && n <= 2147483647 {
			v := int(n)
			delay = &v
		}
	}
	return &AccountSecurityError{Status: status, Code: wire.Error, RetryAfterSeconds: delay}
}
func validateSecurityJSON(raw []byte, t reflect.Type) error {
	fail := func() error { return &AccountSecurityProtocolError{} }
	if bytes.Equal(raw, []byte("null")) {
		return fail()
	}
	switch t.Kind() {
	case reflect.Pointer:
		return validateSecurityJSON(raw, t.Elem())
	case reflect.Slice:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil || items == nil {
			return fail()
		}
		for _, v := range items {
			if err := validateSecurityJSON(v, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var items map[string]json.RawMessage
		if json.Unmarshal(raw, &items) != nil || items == nil {
			return fail()
		}
		for key, v := range items {
			encodedKey, _ := json.Marshal(key)
			if err := validateSecurityJSON(encodedKey, t.Key()); err != nil {
				return err
			}
			if err := validateSecurityJSON(v, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return fail()
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			v, ok := fields[key]
			if !ok || bytes.Equal(v, []byte("null")) {
				if f.Type.Kind() == reflect.Pointer || f.Tag.Get("wire") == "optional" {
					delete(fields, key)
					continue
				}
				return fail()
			}
			if err := validateSecurityJSON(v, f.Type); err != nil {
				return err
			}
			delete(fields, key)
		}
		return securitySemantic(raw, t.Name())
	case reflect.String:
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return fail()
		}
		if _, ok := securityEnums[t.Name()]; ok && !securityEnum(value, t.Name()) {
			return fail()
		}
	case reflect.Bool:
		var v bool
		if json.Unmarshal(raw, &v) != nil {
			return fail()
		}
	case reflect.Int64:
		var v int64
		if json.Unmarshal(raw, &v) != nil {
			return fail()
		}
	default:
		return fail()
	}
	return nil
}
func securitySemantic(raw []byte, name string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return &AccountSecurityProtocolError{}
	}
	text := func(key string) string { var s string; _ = json.Unmarshal(fields[key], &s); return s }
	present := func(key string) bool { v, ok := fields[key]; return ok && !bytes.Equal(v, []byte("null")) }
	fail := func() error { return &AccountSecurityProtocolError{} }
	switch name {
	case "RecoveryCodesRemaining":
		var count int64
		_ = json.Unmarshal(fields["remaining"], &count)
		if count < 0 || present("codes") || present("recoveryCodes") || present("material") {
			return fail()
		}
	case "ProviderTarget":
		if !securityUUID.MatchString(text("providerId")) || !securityProviderReference.MatchString(text("reference")) {
			return fail()
		}
	case "IdentityOperation":
		if present("providerTarget") && (text("type") != "LINK" || text("state") == "CANCELLED" || text("state") == "EXPIRED" || text("state") == "REJECTED") {
			return fail()
		}
	case "IdentifierCapability":
		var allowed bool
		var reasons []string
		var ids []string
		_ = json.Unmarshal(fields["allowed"], &allowed)
		_ = json.Unmarshal(fields["unavailableReasons"], &reasons)
		_ = json.Unmarshal(fields["replacementPrimaryIds"], &ids)
		if allowed != (len(reasons) == 0) {
			return fail()
		}
		for _, id := range ids {
			if !securityUUID.MatchString(id) {
				return fail()
			}
		}

	case "MFAOperation":
		if present("material") || present("recoveryCodes") {
			return fail()
		}
		if (text("state") == "COMMITTED") != present("result") {
			return fail()
		}
	case "TOTPBeginResult":
		if (text("delivery") == "AVAILABLE") != present("material") || text("delivery") == "NOT_APPLICABLE" {
			return fail()
		}
	case "MFACompletionResult":
		if (text("delivery") == "AVAILABLE") != present("recoveryCodes") {
			return fail()
		}
	case "RecoveryCodes":
		var codes []string
		var count int64
		_ = json.Unmarshal(fields["codes"], &codes)
		_ = json.Unmarshal(fields["count"], &count)
		if count != int64(len(codes)) {
			return fail()
		}
	case "MFAAction":
		var allowed bool
		var options []json.RawMessage
		_ = json.Unmarshal(fields["allowed"], &allowed)
		_ = json.Unmarshal(fields["proofOptions"], &options)
		if allowed && text("proofRequirement") != "SESSION" && len(options) == 0 {
			return fail()
		}
	case "OperationProofOption":
		expected := map[string][]string{"PASSWORD": {}, "EMAIL_OTP": {"identifierId", "maskedIdentifier"}, "PROVIDER": {"methodId", "displayName"}, "STEP_UP_PROOF": {"availableMethods"}}[text("method")]
		for _, key := range []string{"identifierId", "maskedIdentifier", "methodId", "displayName", "availableMethods"} {
			want := false
			for _, k := range expected {
				if key == k {
					want = true
				}
			}
			if want != present(key) {
				return fail()
			}
		}
		switch text("method") {
		case "EMAIL_OTP":
			if !present("identifierId") || !present("maskedIdentifier") {
				return fail()
			}
		case "PROVIDER":
			if !present("methodId") || !present("displayName") {
				return fail()
			}
		case "STEP_UP_PROOF":
			var methods []string
			if json.Unmarshal(fields["availableMethods"], &methods) != nil || len(methods) == 0 {
				return fail()
			}
			for _, m := range methods {
				if m != "TOTP" && m != "WEBAUTHN" {
					return fail()
				}
			}
		}
	}
	return nil
}

var securityRequestTypes = map[string]bool{"MFAOperationCreate": true, "LoginIdentifier": true, "AddIdentity": true, "VerifyIdentity": true, "SetPrimaryIdentity": true, "RemoveIdentity": true, "ReplaceIdentity": true, "LinkIdentity": true, "UnlinkIdentity": true, "TransferIdentity": true, "PasswordReauthentication": true, "EmailOTPReauthentication": true, "OperationStepUpVerify": true, "OperationWebAuthnVerify": true, "ProviderExchange": true, "MFAProviderAuthorize": true, "IdentityProviderAuthorize": true, "IdentityTargetProof": true, "IdentityOperationComplete": true, "IdentityOperationCreate": true}

// Additive response members are ignored; duplicate members and trailing JSON still fail.
func decodeSecurityJSON(raw []byte, out any) error {
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return &AccountSecurityProtocolError{}
	}
	return nil
}
