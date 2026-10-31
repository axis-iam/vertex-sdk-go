package iam

import "context"

// ListAccountIdentifiers delegates to the explicit current-user client.
func (s *SDK) ListAccountIdentifiers(ctx context.Context, accessToken string) (*AccountIdentifiers, error) {
	return s.client.ListAccountIdentifiers(ctx, accessToken)
}

// ListAccountLoginMethods delegates to the explicit current-user client.
func (s *SDK) ListAccountLoginMethods(ctx context.Context, accessToken string) (*AccountLoginMethods, error) {
	return s.client.ListAccountLoginMethods(ctx, accessToken)
}

// ListLinkableIdentityProviders delegates to the explicit current-user client.
func (s *SDK) ListLinkableIdentityProviders(ctx context.Context, accessToken string) ([]LinkableIdentityProvider, error) {
	return s.client.ListLinkableIdentityProviders(ctx, accessToken)
}

// CreateIdentityOperation delegates to the explicit current-user client.
func (s *SDK) CreateIdentityOperation(ctx context.Context, accessToken string, request IdentityOperationCreate, idempotencyKey string) (*IdentityOperation, error) {
	return s.client.CreateIdentityOperation(ctx, accessToken, request, idempotencyKey)
}

// GetIdentityOperation delegates to the explicit current-user client.
func (s *SDK) GetIdentityOperation(ctx context.Context, accessToken string, operationID string) (*IdentityOperation, error) {
	return s.client.GetIdentityOperation(ctx, accessToken, operationID)
}

// ListIdentityTransfers delegates to the explicit current-user client.
func (s *SDK) ListIdentityTransfers(ctx context.Context, accessToken string) ([]IdentityOperation, error) {
	return s.client.ListIdentityTransfers(ctx, accessToken)
}

// ReauthenticateIdentityOperation delegates to the explicit current-user client.
func (s *SDK) ReauthenticateIdentityOperation(ctx context.Context, accessToken string, operationID string, request Reauthentication) (*IdentityOperation, error) {
	return s.client.ReauthenticateIdentityOperation(ctx, accessToken, operationID, request)
}

// ChallengeIdentityOperation delegates to the explicit current-user client.
func (s *SDK) ChallengeIdentityOperation(ctx context.Context, accessToken string, operationID string, targetProofMethod TargetProofMethod) (*IdentityOperation, error) {
	return s.client.ChallengeIdentityOperation(ctx, accessToken, operationID, targetProofMethod)
}

// ChallengeIdentityCurrentAccount delegates to the explicit current-user client.
func (s *SDK) ChallengeIdentityCurrentAccount(ctx context.Context, accessToken string, operationID string, identifierID string) (*IdentityChallengeResult, error) {
	return s.client.ChallengeIdentityCurrentAccount(ctx, accessToken, operationID, identifierID)
}

// CompleteIdentityOperation delegates to the explicit current-user client.
func (s *SDK) CompleteIdentityOperation(ctx context.Context, accessToken string, operationID string, request IdentityOperationComplete) (*IdentityOperation, error) {
	return s.client.CompleteIdentityOperation(ctx, accessToken, operationID, request)
}

// CancelIdentityOperation delegates to the explicit current-user client.
func (s *SDK) CancelIdentityOperation(ctx context.Context, accessToken string, operationID string) (*IdentityOperation, error) {
	return s.client.CancelIdentityOperation(ctx, accessToken, operationID)
}

// ConfirmIdentityTransfer delegates to the explicit current-user client.
func (s *SDK) ConfirmIdentityTransfer(ctx context.Context, accessToken string, operationID string, decision TransferDecision) (*IdentityOperation, error) {
	return s.client.ConfirmIdentityTransfer(ctx, accessToken, operationID, decision)
}

// AuthorizeIdentityOperation delegates to the explicit current-user client.
func (s *SDK) AuthorizeIdentityOperation(ctx context.Context, accessToken string, operationID string, request IdentityProviderAuthorize) (*ProviderAuthorization, error) {
	return s.client.AuthorizeIdentityOperation(ctx, accessToken, operationID, request)
}

// CompleteIdentityProviderAuthorization delegates to the explicit current-user client.
func (s *SDK) CompleteIdentityProviderAuthorization(ctx context.Context, accessToken string, operationID string, request ProviderExchange) (*IdentityOperation, error) {
	return s.client.CompleteIdentityProviderAuthorization(ctx, accessToken, operationID, request)
}

// GetMFACapabilities delegates to the explicit current-user client.
func (s *SDK) GetMFACapabilities(ctx context.Context, accessToken string) (*MFACapabilities, error) {
	return s.client.GetMFACapabilities(ctx, accessToken)
}

// CreateMFAOperation delegates to the explicit current-user client.
func (s *SDK) CreateMFAOperation(ctx context.Context, accessToken string, request MFAOperationCreate, idempotencyKey string) (*MFAOperation, error) {
	return s.client.CreateMFAOperation(ctx, accessToken, request, idempotencyKey)
}

// GetMFAOperation delegates to the explicit current-user client.
func (s *SDK) GetMFAOperation(ctx context.Context, accessToken string, operationID string) (*MFAOperation, error) {
	return s.client.GetMFAOperation(ctx, accessToken, operationID)
}

// ReauthenticateMFAOperation delegates to the explicit current-user client.
func (s *SDK) ReauthenticateMFAOperation(ctx context.Context, accessToken string, operationID string, request Reauthentication) (*MFAOperation, error) {
	return s.client.ReauthenticateMFAOperation(ctx, accessToken, operationID, request)
}

// ChallengeMFAOperation delegates to the explicit current-user client.
func (s *SDK) ChallengeMFAOperation(ctx context.Context, accessToken string, operationID string, identifierID string) (*MFAChallengeResult, error) {
	return s.client.ChallengeMFAOperation(ctx, accessToken, operationID, identifierID)
}

// AuthorizeMFAOperation delegates to the explicit current-user client.
func (s *SDK) AuthorizeMFAOperation(ctx context.Context, accessToken string, operationID string, request MFAProviderAuthorize) (*ProviderAuthorization, error) {
	return s.client.AuthorizeMFAOperation(ctx, accessToken, operationID, request)
}

// CompleteMFAProviderAuthorization delegates to the explicit current-user client.
func (s *SDK) CompleteMFAProviderAuthorization(ctx context.Context, accessToken string, operationID string, request ProviderExchange) (*MFAOperation, error) {
	return s.client.CompleteMFAProviderAuthorization(ctx, accessToken, operationID, request)
}

// BeginTOTPEnrollmentOperation delegates to the explicit current-user client.
func (s *SDK) BeginTOTPEnrollmentOperation(ctx context.Context, accessToken string, operationID string) (*TOTPBeginResult, error) {
	return s.client.BeginTOTPEnrollmentOperation(ctx, accessToken, operationID)
}

// CompleteMFAOperation delegates to the explicit current-user client.
func (s *SDK) CompleteMFAOperation(ctx context.Context, accessToken string, operationID string, code *string) (*MFACompletionResult, error) {
	return s.client.CompleteMFAOperation(ctx, accessToken, operationID, code)
}

// CancelMFAOperation delegates to the explicit current-user client.
func (s *SDK) CancelMFAOperation(ctx context.Context, accessToken string, operationID string) (*MFAOperation, error) {
	return s.client.CancelMFAOperation(ctx, accessToken, operationID)
}

// StartIdentityOperationStepUp delegates to the explicit current-user client.
func (s *SDK) StartIdentityOperationStepUp(ctx context.Context, accessToken string, operationID string) (*OperationStepUpChallenge, error) {
	return s.client.StartIdentityOperationStepUp(ctx, accessToken, operationID)
}

// VerifyIdentityOperationStepUp delegates to the explicit current-user client.
func (s *SDK) VerifyIdentityOperationStepUp(ctx context.Context, accessToken string, operationID string, request OperationStepUpVerify) (*IdentityOperation, error) {
	return s.client.VerifyIdentityOperationStepUp(ctx, accessToken, operationID, request)
}

// StartIdentityOperationWebAuthn delegates to the explicit current-user client.
func (s *SDK) StartIdentityOperationWebAuthn(ctx context.Context, accessToken string, operationID string, challengeID string) (*OperationWebAuthnStart, error) {
	return s.client.StartIdentityOperationWebAuthn(ctx, accessToken, operationID, challengeID)
}

// VerifyIdentityOperationWebAuthn delegates to the explicit current-user client.
func (s *SDK) VerifyIdentityOperationWebAuthn(ctx context.Context, accessToken string, operationID string, request OperationWebAuthnVerify) (*IdentityOperation, error) {
	return s.client.VerifyIdentityOperationWebAuthn(ctx, accessToken, operationID, request)
}

// StartMFAOperationStepUp delegates to the explicit current-user client.
func (s *SDK) StartMFAOperationStepUp(ctx context.Context, accessToken string, operationID string) (*OperationStepUpChallenge, error) {
	return s.client.StartMFAOperationStepUp(ctx, accessToken, operationID)
}

// VerifyMFAOperationStepUp delegates to the explicit current-user client.
func (s *SDK) VerifyMFAOperationStepUp(ctx context.Context, accessToken string, operationID string, request OperationStepUpVerify) (*MFAOperation, error) {
	return s.client.VerifyMFAOperationStepUp(ctx, accessToken, operationID, request)
}

// StartMFAOperationWebAuthn delegates to the explicit current-user client.
func (s *SDK) StartMFAOperationWebAuthn(ctx context.Context, accessToken string, operationID string, challengeID string) (*OperationWebAuthnStart, error) {
	return s.client.StartMFAOperationWebAuthn(ctx, accessToken, operationID, challengeID)
}

// VerifyMFAOperationWebAuthn delegates to the explicit current-user client.
func (s *SDK) VerifyMFAOperationWebAuthn(ctx context.Context, accessToken string, operationID string, request OperationWebAuthnVerify) (*MFAOperation, error) {
	return s.client.VerifyMFAOperationWebAuthn(ctx, accessToken, operationID, request)
}

// GetRecoveryCodesRemaining reads the current user's unused recovery-code count through the shared Client.
func (s *SDK) GetRecoveryCodesRemaining(ctx context.Context, accessToken string) (*RecoveryCodesRemaining, error) {
	return s.client.GetRecoveryCodesRemaining(ctx, accessToken)
}
