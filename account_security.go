package iam

import "context"

// ListAccountIdentifiers calls GET /api/v1/auth/me/identifiers without mutation replay.
func (c *Client) ListAccountIdentifiers(ctx context.Context, accessToken string) (*AccountIdentifiers, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	var out AccountIdentifiers
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/me/identifiers", token, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAccountLoginMethods calls GET /api/v1/auth/me/login-methods without mutation replay.
func (c *Client) ListAccountLoginMethods(ctx context.Context, accessToken string) (*AccountLoginMethods, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	var out AccountLoginMethods
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/me/login-methods", token, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListLinkableIdentityProviders calls GET /api/v1/auth/me/linkable-identity-providers without mutation replay.
func (c *Client) ListLinkableIdentityProviders(ctx context.Context, accessToken string) ([]LinkableIdentityProvider, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	var out []LinkableIdentityProvider
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/me/linkable-identity-providers", token, "", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateIdentityOperation calls POST /api/v1/auth/me/identity-operations without mutation replay.
func (c *Client) CreateIdentityOperation(ctx context.Context, accessToken string, request IdentityOperationCreate, idempotencyKey string) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	if !securityKey(idempotencyKey) {
		return nil, securityInputError()
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations", token, idempotencyKey, request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetIdentityOperation calls GET /api/v1/auth/me/identity-operations/{id} without mutation replay.
func (c *Client) GetIdentityOperation(ctx context.Context, accessToken string, operationID string) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/me/identity-operations/"+operationID+"", token, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListIdentityTransfers calls GET /api/v1/auth/me/identity-operations/transfers without mutation replay.
func (c *Client) ListIdentityTransfers(ctx context.Context, accessToken string) ([]IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	var out []IdentityOperation
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/me/identity-operations/transfers", token, "", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReauthenticateIdentityOperation calls POST /api/v1/auth/me/identity-operations/{id}/reauthenticate without mutation replay.
func (c *Client) ReauthenticateIdentityOperation(ctx context.Context, accessToken string, operationID string, request Reauthentication) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/reauthenticate", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChallengeIdentityOperation calls POST /api/v1/auth/me/identity-operations/{id}/challenges without mutation replay.
func (c *Client) ChallengeIdentityOperation(ctx context.Context, accessToken string, operationID string, targetProofMethod TargetProofMethod) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if !securityEnum(string(targetProofMethod), "TargetProofMethod") {
		return nil, securityInputError()
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/challenges", token, "", map[string]any{"targetProofMethod": targetProofMethod}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChallengeIdentityCurrentAccount calls POST /api/v1/auth/me/identity-operations/{id}/current-account/challenges without mutation replay.
func (c *Client) ChallengeIdentityCurrentAccount(ctx context.Context, accessToken string, operationID string, identifierID string) (*IdentityChallengeResult, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if !securityUUID.MatchString(identifierID) {
		return nil, securityInputError()
	}
	var out IdentityChallengeResult
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/current-account/challenges", token, "", map[string]any{"identifierId": identifierID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompleteIdentityOperation calls POST /api/v1/auth/me/identity-operations/{id}/complete without mutation replay.
func (c *Client) CompleteIdentityOperation(ctx context.Context, accessToken string, operationID string, request IdentityOperationComplete) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/complete", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelIdentityOperation calls POST /api/v1/auth/me/identity-operations/{id}/cancel without mutation replay.
func (c *Client) CancelIdentityOperation(ctx context.Context, accessToken string, operationID string) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/cancel", token, "", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfirmIdentityTransfer calls POST /api/v1/auth/me/identity-operations/{id}/confirm-transfer without mutation replay.
func (c *Client) ConfirmIdentityTransfer(ctx context.Context, accessToken string, operationID string, decision TransferDecision) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if !securityEnum(string(decision), "TransferDecision") {
		return nil, securityInputError()
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/confirm-transfer", token, "", map[string]any{"decision": decision}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuthorizeIdentityOperation calls POST /api/v1/auth/me/identity-operations/{id}/authorize without mutation replay.
func (c *Client) AuthorizeIdentityOperation(ctx context.Context, accessToken string, operationID string, request IdentityProviderAuthorize) (*ProviderAuthorization, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out ProviderAuthorization
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/authorize", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompleteIdentityProviderAuthorization calls POST /api/v1/auth/me/identity-operations/{id}/provider-callback without mutation replay.
func (c *Client) CompleteIdentityProviderAuthorization(ctx context.Context, accessToken string, operationID string, request ProviderExchange) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/provider-callback", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMFACapabilities calls GET /api/v1/auth/mfa/capabilities without mutation replay.
func (c *Client) GetMFACapabilities(ctx context.Context, accessToken string) (*MFACapabilities, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	var out MFACapabilities
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/mfa/capabilities", token, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateMFAOperation calls POST /api/v1/auth/mfa/operations without mutation replay.
func (c *Client) CreateMFAOperation(ctx context.Context, accessToken string, request MFAOperationCreate, idempotencyKey string) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	if !securityKey(idempotencyKey) {
		return nil, securityInputError()
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations", token, idempotencyKey, request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMFAOperation calls GET /api/v1/auth/mfa/operations/{id} without mutation replay.
func (c *Client) GetMFAOperation(ctx context.Context, accessToken string, operationID string) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/mfa/operations/"+operationID+"", token, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReauthenticateMFAOperation calls POST /api/v1/auth/mfa/operations/{id}/reauthenticate without mutation replay.
func (c *Client) ReauthenticateMFAOperation(ctx context.Context, accessToken string, operationID string, request Reauthentication) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/reauthenticate", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChallengeMFAOperation calls POST /api/v1/auth/mfa/operations/{id}/challenges without mutation replay.
func (c *Client) ChallengeMFAOperation(ctx context.Context, accessToken string, operationID string, identifierID string) (*MFAChallengeResult, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if !securityUUID.MatchString(identifierID) {
		return nil, securityInputError()
	}
	var out MFAChallengeResult
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/challenges", token, "", map[string]any{"method": "EMAIL_OTP", "identifierId": identifierID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuthorizeMFAOperation calls POST /api/v1/auth/mfa/operations/{id}/authorize without mutation replay.
func (c *Client) AuthorizeMFAOperation(ctx context.Context, accessToken string, operationID string, request MFAProviderAuthorize) (*ProviderAuthorization, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out ProviderAuthorization
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/authorize", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompleteMFAProviderAuthorization calls POST /api/v1/auth/mfa/operations/{id}/provider-callback without mutation replay.
func (c *Client) CompleteMFAProviderAuthorization(ctx context.Context, accessToken string, operationID string, request ProviderExchange) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/provider-callback", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BeginTOTPEnrollmentOperation calls POST /api/v1/auth/mfa/operations/{id}/begin without mutation replay.
func (c *Client) BeginTOTPEnrollmentOperation(ctx context.Context, accessToken string, operationID string) (*TOTPBeginResult, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out TOTPBeginResult
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/begin", token, "", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompleteMFAOperation calls POST /api/v1/auth/mfa/operations/{id}/complete without mutation replay.
func (c *Client) CompleteMFAOperation(ctx context.Context, accessToken string, operationID string, code *string) (*MFACompletionResult, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if code != nil && !securityCode.MatchString(*code) {
		return nil, securityInputError()
	}
	var out MFACompletionResult
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/complete", token, "", struct {
		Code *string `json:"code,omitempty"`
	}{code}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelMFAOperation calls POST /api/v1/auth/mfa/operations/{id}/cancel without mutation replay.
func (c *Client) CancelMFAOperation(ctx context.Context, accessToken string, operationID string) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/cancel", token, "", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StartIdentityOperationStepUp calls POST /api/v1/auth/me/identity-operations/{id}/step-up/start without mutation replay.
func (c *Client) StartIdentityOperationStepUp(ctx context.Context, accessToken string, operationID string) (*OperationStepUpChallenge, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out OperationStepUpChallenge
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/step-up/start", token, "", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyIdentityOperationStepUp calls POST /api/v1/auth/me/identity-operations/{id}/step-up/verify without mutation replay.
func (c *Client) VerifyIdentityOperationStepUp(ctx context.Context, accessToken string, operationID string, request OperationStepUpVerify) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/step-up/verify", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StartIdentityOperationWebAuthn calls POST /api/v1/auth/me/identity-operations/{id}/step-up/webauthn/start without mutation replay.
func (c *Client) StartIdentityOperationWebAuthn(ctx context.Context, accessToken string, operationID string, challengeID string) (*OperationWebAuthnStart, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if challengeID == "" {
		return nil, securityInputError()
	}
	var out OperationWebAuthnStart
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/step-up/webauthn/start", token, "", map[string]any{"challengeId": challengeID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyIdentityOperationWebAuthn calls POST /api/v1/auth/me/identity-operations/{id}/step-up/webauthn/verify without mutation replay.
func (c *Client) VerifyIdentityOperationWebAuthn(ctx context.Context, accessToken string, operationID string, request OperationWebAuthnVerify) (*IdentityOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out IdentityOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/me/identity-operations/"+operationID+"/step-up/webauthn/verify", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StartMFAOperationStepUp calls POST /api/v1/auth/mfa/operations/{id}/step-up/start without mutation replay.
func (c *Client) StartMFAOperationStepUp(ctx context.Context, accessToken string, operationID string) (*OperationStepUpChallenge, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	var out OperationStepUpChallenge
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/step-up/start", token, "", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyMFAOperationStepUp calls POST /api/v1/auth/mfa/operations/{id}/step-up/verify without mutation replay.
func (c *Client) VerifyMFAOperationStepUp(ctx context.Context, accessToken string, operationID string, request OperationStepUpVerify) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/step-up/verify", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StartMFAOperationWebAuthn calls POST /api/v1/auth/mfa/operations/{id}/step-up/webauthn/start without mutation replay.
func (c *Client) StartMFAOperationWebAuthn(ctx context.Context, accessToken string, operationID string, challengeID string) (*OperationWebAuthnStart, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if challengeID == "" {
		return nil, securityInputError()
	}
	var out OperationWebAuthnStart
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/step-up/webauthn/start", token, "", map[string]any{"challengeId": challengeID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyMFAOperationWebAuthn calls POST /api/v1/auth/mfa/operations/{id}/step-up/webauthn/verify without mutation replay.
func (c *Client) VerifyMFAOperationWebAuthn(ctx context.Context, accessToken string, operationID string, request OperationWebAuthnVerify) (*MFAOperation, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !securityUUID.MatchString(operationID) {
		return nil, securityInputError()
	}
	if err := validateSecurityRequest(request); err != nil {
		return nil, err
	}
	var out MFAOperation
	if err := c.accountSecurityRequest(ctx, "POST", "/api/v1/auth/mfa/operations/"+operationID+"/step-up/webauthn/verify", token, "", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRecoveryCodesRemaining reads the current user's live unused recovery-code count.
func (c *Client) GetRecoveryCodesRemaining(ctx context.Context, accessToken string) (*RecoveryCodesRemaining, error) {
	token, err := securityToken(accessToken)
	if err != nil {
		return nil, err
	}
	var out RecoveryCodesRemaining
	if err := c.accountSecurityRequest(ctx, "GET", "/api/v1/auth/mfa/recovery-codes/remaining", token, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
