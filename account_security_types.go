package iam

import (
	"encoding/json"
	"fmt"
)

// MFAOperationType is an operation wire enum; unsupported response values fail closed.
type MFAOperationType string

const (
	MFAOperationTypeTOTPEnroll            MFAOperationType = "TOTP_ENROLL"
	MFAOperationTypeTOTPDisable           MFAOperationType = "TOTP_DISABLE"
	MFAOperationTypeRecoveryCodesGenerate MFAOperationType = "RECOVERY_CODES_GENERATE"
)

// MFAOperationState is an operation wire enum; unsupported response values fail closed.
type MFAOperationState string

const (
	MFAOperationStateAwaitingReauth       MFAOperationState = "AWAITING_REAUTH"
	MFAOperationStateReady                MFAOperationState = "READY"
	MFAOperationStateAwaitingConfirmation MFAOperationState = "AWAITING_CONFIRMATION"
	MFAOperationStateCommitted            MFAOperationState = "COMMITTED"
	MFAOperationStateCancelled            MFAOperationState = "CANCELLED"
	MFAOperationStateExpired              MFAOperationState = "EXPIRED"
)

// ProofRequirement is an operation wire enum; unsupported response values fail closed.
type ProofRequirement string

const (
	ProofRequirementSession          ProofRequirement = "SESSION"
	ProofRequirementReauthentication ProofRequirement = "REAUTHENTICATION"
	ProofRequirementStepUp           ProofRequirement = "STEP_UP"
)

// ProofMethod is an operation wire enum; unsupported response values fail closed.
type ProofMethod string

const (
	ProofMethodPassword    ProofMethod = "PASSWORD"
	ProofMethodEmailOTP    ProofMethod = "EMAIL_OTP"
	ProofMethodProvider    ProofMethod = "PROVIDER"
	ProofMethodStepUpProof ProofMethod = "STEP_UP_PROOF"
)

// SessionImpact is an operation wire enum; unsupported response values fail closed.
type SessionImpact string

const (
	SessionImpactUnchanged              SessionImpact = "UNCHANGED"
	SessionImpactCurrentSessionRetained SessionImpact = "CURRENT_SESSION_RETAINED"
	SessionImpactReauthenticate         SessionImpact = "REAUTHENTICATE"
)

// SensitiveDelivery is an operation wire enum; unsupported response values fail closed.
type SensitiveDelivery string

const (
	SensitiveDeliveryAvailable        SensitiveDelivery = "AVAILABLE"
	SensitiveDeliveryAlreadyDelivered SensitiveDelivery = "ALREADY_DELIVERED"
	SensitiveDeliveryNotApplicable    SensitiveDelivery = "NOT_APPLICABLE"
)

// IdentityOperationType is an operation wire enum; unsupported response values fail closed.
type IdentityOperationType string

const (
	IdentityOperationTypeAdd           IdentityOperationType = "ADD"
	IdentityOperationTypeVerify        IdentityOperationType = "VERIFY"
	IdentityOperationTypeSetPrimary    IdentityOperationType = "SET_PRIMARY"
	IdentityOperationTypeRemove        IdentityOperationType = "REMOVE"
	IdentityOperationTypeReplace       IdentityOperationType = "REPLACE"
	IdentityOperationTypeLink          IdentityOperationType = "LINK"
	IdentityOperationTypeUnlink        IdentityOperationType = "UNLINK"
	IdentityOperationTypeTransfer      IdentityOperationType = "TRANSFER"
	IdentityOperationTypeAccountDelete IdentityOperationType = "ACCOUNT_DELETE"
)

// IdentityOperationState is an operation wire enum; unsupported response values fail closed.
type IdentityOperationState string

const (
	IdentityOperationStateAwaitingReauth IdentityOperationState = "AWAITING_REAUTH"
	IdentityOperationStateAwaitingProof  IdentityOperationState = "AWAITING_PROOF"
	IdentityOperationStateReady          IdentityOperationState = "READY"
	IdentityOperationStateCommitted      IdentityOperationState = "COMMITTED"
	IdentityOperationStateCancelled      IdentityOperationState = "CANCELLED"
	IdentityOperationStateExpired        IdentityOperationState = "EXPIRED"
	IdentityOperationStateRejected       IdentityOperationState = "REJECTED"
)

// IdentifierKind is an operation wire enum; unsupported response values fail closed.
type IdentifierKind string

const (
	IdentifierKindUsername IdentifierKind = "USERNAME"
	IdentifierKindEmail    IdentifierKind = "EMAIL"
	IdentifierKindPhone    IdentifierKind = "PHONE"
)

// TargetProofMethod is an operation wire enum; unsupported response values fail closed.
type TargetProofMethod string

const (
	TargetProofMethodEmailOTP TargetProofMethod = "EMAIL_OTP"
	TargetProofMethodPhoneOTP TargetProofMethod = "PHONE_OTP"
)

// AuthorizationPurpose is an operation wire enum; unsupported response values fail closed.
type AuthorizationPurpose string

const (
	AuthorizationPurposeCurrentAccount      AuthorizationPurpose = "CURRENT_ACCOUNT"
	AuthorizationPurposeTargetOwnership     AuthorizationPurpose = "TARGET_OWNERSHIP"
	AuthorizationPurposeTransferCounterpart AuthorizationPurpose = "TRANSFER_COUNTERPART"
)

// TransferDecision is an operation wire enum; unsupported response values fail closed.
type TransferDecision string

const (
	TransferDecisionAccept TransferDecision = "ACCEPT"
	TransferDecisionReject TransferDecision = "REJECT"
)

// IdentityPayload is a closed set of self-service identifier/provider mutations.
type IdentityPayload interface{ identityPayload() }

// Reauthentication cannot carry unrelated fields or a generic step-up grant.
type Reauthentication interface{ reauthentication() }

// OperationProofOption mirrors the current-user producer contract.
type OperationProofOption struct {
	Method           ProofMethod `json:"method"`
	IdentifierID     *string     `json:"identifierId,omitempty" wire:"optional"`
	MaskedIdentifier *string     `json:"maskedIdentifier,omitempty" wire:"optional"`
	MethodID         *string     `json:"methodId,omitempty" wire:"optional"`
	DisplayName      *string     `json:"displayName,omitempty" wire:"optional"`
	AvailableMethods []string    `json:"availableMethods,omitempty" wire:"optional"`
}

// OperationCompletion mirrors the current-user producer contract.
type OperationCompletion struct {
	CompletedAt             string        `json:"completedAt"`
	FinalLoginMethodVersion int64         `json:"finalLoginMethodVersion"`
	SessionImpact           SessionImpact `json:"sessionImpact"`
}

// MFAOperationResult mirrors the current-user producer contract.
type MFAOperationResult struct {
	CompletedAt             string        `json:"completedAt"`
	FinalLoginMethodVersion int64         `json:"finalLoginMethodVersion"`
	SessionImpact           SessionImpact `json:"sessionImpact"`
	RecoveryBatchID         *string       `json:"recoveryBatchId,omitempty" wire:"optional"`
	RecoveryCount           *int64        `json:"recoveryCount,omitempty" wire:"optional"`
}

// MFAAction mirrors the current-user producer contract.
type MFAAction struct {
	Allowed          bool                   `json:"allowed"`
	ReasonCode       *string                `json:"reasonCode,omitempty" wire:"optional"`
	ProofRequirement ProofRequirement       `json:"proofRequirement"`
	ProofOptions     []OperationProofOption `json:"proofOptions"`
}

// MFACapabilities mirrors the current-user producer contract.
type MFACapabilities struct {
	LoginMethodVersion    int64     `json:"loginMethodVersion"`
	TOTPEnroll            MFAAction `json:"totpEnroll"`
	TOTPDisable           MFAAction `json:"totpDisable"`
	RecoveryCodesGenerate MFAAction `json:"recoveryCodesGenerate"`
}

// MFAOperation mirrors the current-user producer contract.
type MFAOperation struct {
	ID                         string                 `json:"id"`
	Type                       MFAOperationType       `json:"type"`
	State                      MFAOperationState      `json:"state"`
	CreatedAt                  string                 `json:"createdAt"`
	ExpiresAt                  string                 `json:"expiresAt"`
	ExpectedLoginMethodVersion int64                  `json:"expectedLoginMethodVersion"`
	ProofRequirement           ProofRequirement       `json:"proofRequirement"`
	ProofOptions               []OperationProofOption `json:"proofOptions"`
	ProofSatisfied             bool                   `json:"proofSatisfied"`
	NextChallengeAt            *string                `json:"nextChallengeAt,omitempty" wire:"optional"`
	ReasonCode                 *string                `json:"reasonCode,omitempty" wire:"optional"`
	Result                     *MFAOperationResult    `json:"result,omitempty" wire:"optional"`
}

// TOTPMaterial mirrors the current-user producer contract.
type TOTPMaterial struct {
	Secret    string `json:"secret"`
	QRCodeURI string `json:"qrCodeUri"`
	Issuer    string `json:"issuer"`
}

func (TOTPMaterial) String() string   { return "TOTPMaterial[redacted]" }
func (TOTPMaterial) GoString() string { return "TOTPMaterial[redacted]" }

// TOTPBeginResult mirrors the current-user producer contract.
type TOTPBeginResult struct {
	Operation MFAOperation      `json:"operation"`
	Delivery  SensitiveDelivery `json:"delivery"`
	Material  *TOTPMaterial     `json:"material,omitempty" wire:"optional"`
}

func (TOTPBeginResult) String() string   { return "TOTPBeginResult[redacted]" }
func (TOTPBeginResult) GoString() string { return "TOTPBeginResult[redacted]" }

// RecoveryCodes mirrors the current-user producer contract.
type RecoveryCodes struct {
	Codes []string `json:"codes"`
	Count int64    `json:"count"`
}

func (RecoveryCodes) String() string   { return "RecoveryCodes[redacted]" }
func (RecoveryCodes) GoString() string { return "RecoveryCodes[redacted]" }

// MFACompletionResult mirrors the current-user producer contract.
type MFACompletionResult struct {
	Operation     MFAOperation      `json:"operation"`
	Delivery      SensitiveDelivery `json:"delivery"`
	RecoveryCodes *RecoveryCodes    `json:"recoveryCodes,omitempty" wire:"optional"`
}

func (MFACompletionResult) String() string   { return "MFACompletionResult[redacted]" }
func (MFACompletionResult) GoString() string { return "MFACompletionResult[redacted]" }

// MFAChallengeResult mirrors the current-user producer contract.
type MFAChallengeResult struct {
	Operation       MFAOperation `json:"operation"`
	ChallengeID     string       `json:"challengeId"`
	NextChallengeAt string       `json:"nextChallengeAt"`
}

// IdentityRequiredProof mirrors the current-user producer contract.
type IdentityRequiredProof struct {
	Purpose   string   `json:"purpose"`
	Methods   []string `json:"methods"`
	Strength  string   `json:"strength"`
	Satisfied bool     `json:"satisfied"`
}

// IdentityOperation mirrors the current-user producer contract.
type ProviderTarget struct {
	ProviderID        string  `json:"providerId"`
	MaskedDisplayName *string `json:"maskedDisplayName,omitempty"`
	MaskedEmail       *string `json:"maskedEmail,omitempty"`
	Reference         string  `json:"reference"`
}

type IdentityOperation struct {
	ID               string                  `json:"id"`
	Type             IdentityOperationType   `json:"type"`
	State            IdentityOperationState  `json:"state"`
	ExpiresAt        string                  `json:"expiresAt"`
	RequiredProofs   []IdentityRequiredProof `json:"requiredProofs"`
	Result           map[string]string       `json:"result,omitempty" wire:"optional"`
	MaskedIdentifier *string                 `json:"maskedIdentifier,omitempty" wire:"optional"`
	NextChallengeAt  *string                 `json:"nextChallengeAt,omitempty" wire:"optional"`
	Completion       *OperationCompletion    `json:"completion,omitempty" wire:"optional"`
	ProofOptions     []OperationProofOption  `json:"proofOptions"`
	ProviderTarget   *ProviderTarget         `json:"providerTarget,omitempty"`
}

// IdentityChallengeResult mirrors the current-user producer contract.
type IdentityChallengeResult struct {
	Operation       IdentityOperation `json:"operation"`
	ChallengeID     string            `json:"challengeId"`
	NextChallengeAt string            `json:"nextChallengeAt"`
}

// ProviderAuthorization mirrors the current-user producer contract.
type ProviderAuthorization struct {
	AuthorizationID  string `json:"authorizationId"`
	AuthorizationURL string `json:"authorizationUrl"`
	ExpiresAt        string `json:"expiresAt"`
}

// OperationStepUpChallenge mirrors the current-user producer contract.
type OperationStepUpChallenge struct {
	ChallengeID      string   `json:"challengeId"`
	AvailableMethods []string `json:"availableMethods"`
}

// OperationWebAuthnStart mirrors the current-user producer contract.
type OperationWebAuthnStart struct {
	RequestID string `json:"requestId"`
	PublicKey string `json:"publicKey"`
}

// AccountIdentifier mirrors the current-user producer contract.
type AccountIdentifier struct {
	Capabilities       map[IdentifierAction]IdentifierCapability `json:"capabilities,omitempty" wire:"optional"`
	ID                 string                                    `json:"id"`
	Kind               IdentifierKind                            `json:"kind"`
	DisplayValue       string                                    `json:"displayValue"`
	Status             string                                    `json:"status"`
	VerificationState  string                                    `json:"verificationState"`
	VerifiedAt         *string                                   `json:"verifiedAt,omitempty" wire:"optional"`
	VerificationSource *string                                   `json:"verificationSource,omitempty" wire:"optional"`
	IsPrimary          bool                                      `json:"isPrimary"`
	ManagedBy          *string                                   `json:"managedBy,omitempty" wire:"optional"`
}

// AccountIdentifiers mirrors the current-user producer contract.
type AccountIdentifiers struct {
	Management         *IdentifierManagement `json:"management,omitempty"`
	LoginMethodVersion int64                 `json:"loginMethodVersion"`
	Items              []AccountIdentifier   `json:"items"`
}

// AccountLoginMethod mirrors the current-user producer contract.
type AccountLoginMethod struct {
	MethodID           string          `json:"methodId"`
	Kind               string          `json:"kind"`
	Roles              []string        `json:"roles"`
	Status             string          `json:"status"`
	IdentifierID       *string         `json:"identifierId,omitempty" wire:"optional"`
	CredentialID       *string         `json:"credentialId,omitempty" wire:"optional"`
	IdentityID         *string         `json:"identityId,omitempty" wire:"optional"`
	ProviderID         *string         `json:"providerId,omitempty" wire:"optional"`
	Capabilities       map[string]bool `json:"capabilities"`
	UnavailableReasons []string        `json:"unavailableReasons"`
}

// AccountLoginMethods mirrors the current-user producer contract.
type AccountLoginMethods struct {
	LoginMethodVersion int64                `json:"loginMethodVersion"`
	Methods            []AccountLoginMethod `json:"methods"`
}

// LinkableIdentityProvider mirrors the current-user producer contract.
type LinkableIdentityProvider struct {
	ID                     string   `json:"id"`
	ProviderType           string   `json:"providerType"`
	Protocol               string   `json:"protocol"`
	DisplayName            string   `json:"displayName"`
	Enabled                bool     `json:"enabled"`
	Linked                 bool     `json:"linked"`
	LinkedAt               *string  `json:"linkedAt,omitempty" wire:"optional"`
	SupportsAccountLinking bool     `json:"supportsAccountLinking"`
	CanLink                bool     `json:"canLink"`
	CanReauthenticate      bool     `json:"canReauthenticate"`
	UnavailableReasons     []string `json:"unavailableReasons"`
}

// MFAOperationCreate mirrors the current-user producer contract.
type MFAOperationCreate struct {
	Type                       MFAOperationType `json:"type"`
	ExpectedLoginMethodVersion int64            `json:"expectedLoginMethodVersion"`
}

// LoginIdentifier mirrors the current-user producer contract.
type LoginIdentifier struct {
	Kind   IdentifierKind `json:"kind"`
	Value  string         `json:"value"`
	Region *string        `json:"region,omitempty" wire:"optional"`
}

// AddIdentity mirrors the current-user producer contract.
type AddIdentity struct {
	Identifier LoginIdentifier `json:"identifier"`
}

func (AddIdentity) identityPayload() {}

// VerifyIdentity mirrors the current-user producer contract.
type VerifyIdentity struct {
	IdentifierID string `json:"identifierId"`
}

func (VerifyIdentity) identityPayload() {}

// SetPrimaryIdentity mirrors the current-user producer contract.
type SetPrimaryIdentity struct {
	IdentifierID string `json:"identifierId"`
}

func (SetPrimaryIdentity) identityPayload() {}

// RemoveIdentity mirrors the current-user producer contract.
type RemoveIdentity struct {
	IdentifierID         string  `json:"identifierId"`
	ReplacementPrimaryID *string `json:"replacementPrimaryId,omitempty" wire:"optional"`
}

func (RemoveIdentity) identityPayload() {}

// ReplaceIdentity mirrors the current-user producer contract.
type ReplaceIdentity struct {
	IdentifierID         string          `json:"identifierId"`
	Replacement          LoginIdentifier `json:"replacement"`
	RemoveOld            bool            `json:"removeOld"`
	ReplacementPrimaryID *string         `json:"replacementPrimaryId,omitempty" wire:"optional"`
}

func (ReplaceIdentity) identityPayload() {}

// LinkIdentity mirrors the current-user producer contract.
type LinkIdentity struct {
	ProviderID string `json:"providerId"`
}

func (LinkIdentity) identityPayload() {}

// UnlinkIdentity mirrors the current-user producer contract.
type UnlinkIdentity struct {
	MethodID string `json:"methodId"`
}

func (UnlinkIdentity) identityPayload() {}

// TransferIdentity mirrors the current-user producer contract.
type TransferIdentity struct {
	IdentifierID               string  `json:"identifierId"`
	TargetUserID               string  `json:"targetUserId"`
	SourceReplacementPrimaryID *string `json:"sourceReplacementPrimaryId,omitempty" wire:"optional"`
}

func (TransferIdentity) identityPayload() {}

// PasswordReauthentication mirrors the current-user producer contract.
type PasswordReauthentication struct {
	Password string `json:"password"`
}

func (PasswordReauthentication) reauthentication() {}
func (PasswordReauthentication) String() string    { return "PasswordReauthentication[redacted]" }
func (PasswordReauthentication) GoString() string  { return "PasswordReauthentication[redacted]" }

// EmailOTPReauthentication mirrors the current-user producer contract.
type EmailOTPReauthentication struct {
	ChallengeID string `json:"challengeId"`
	Code        string `json:"code"`
}

func (EmailOTPReauthentication) reauthentication() {}
func (EmailOTPReauthentication) String() string    { return "EmailOTPReauthentication[redacted]" }
func (EmailOTPReauthentication) GoString() string  { return "EmailOTPReauthentication[redacted]" }

// OperationStepUpVerify mirrors the current-user producer contract.
type OperationStepUpVerify struct {
	ChallengeID string `json:"challengeId"`
	Code        string `json:"code"`
}

func (OperationStepUpVerify) String() string   { return "OperationStepUpVerify[redacted]" }
func (OperationStepUpVerify) GoString() string { return "OperationStepUpVerify[redacted]" }

// OperationWebAuthnVerify mirrors the current-user producer contract.
type OperationWebAuthnVerify struct {
	ChallengeID string `json:"challengeId"`
	RequestID   string `json:"requestId"`
	Credential  string `json:"credential"`
}

func (OperationWebAuthnVerify) String() string   { return "OperationWebAuthnVerify[redacted]" }
func (OperationWebAuthnVerify) GoString() string { return "OperationWebAuthnVerify[redacted]" }

// ProviderExchange mirrors the current-user producer contract.
type ProviderExchange struct {
	AuthorizationID string `json:"authorizationId"`
	CodeVerifier    string `json:"codeVerifier"`
}

func (ProviderExchange) String() string   { return "ProviderExchange[redacted]" }
func (ProviderExchange) GoString() string { return "ProviderExchange[redacted]" }

// MFAProviderAuthorize mirrors the current-user producer contract.
type MFAProviderAuthorize struct {
	MethodID            string `json:"methodId"`
	RedirectURI         string `json:"redirectUri"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
}

// IdentityProviderAuthorize mirrors the current-user producer contract.
type IdentityProviderAuthorize struct {
	Purpose             AuthorizationPurpose `json:"purpose"`
	RedirectURI         string               `json:"redirectUri"`
	CodeChallenge       string               `json:"codeChallenge"`
	CodeChallengeMethod string               `json:"codeChallengeMethod"`
	MethodID            *string              `json:"methodId,omitempty" wire:"optional"`
}

// IdentityTargetProof mirrors the current-user producer contract.
type IdentityTargetProof struct {
	Method TargetProofMethod `json:"method"`
	Code   string            `json:"code"`
}

func (IdentityTargetProof) String() string   { return "IdentityTargetProof[redacted]" }
func (IdentityTargetProof) GoString() string { return "IdentityTargetProof[redacted]" }

// IdentityOperationComplete mirrors the current-user producer contract.
type IdentityOperationComplete struct {
	Proofs []IdentityTargetProof `json:"proofs"`
}

func (IdentityOperationComplete) String() string   { return "IdentityOperationComplete[redacted]" }
func (IdentityOperationComplete) GoString() string { return "IdentityOperationComplete[redacted]" }

// IdentityOperationCreate derives its discriminator from the closed payload type.
type IdentityOperationCreate struct {
	ExpectedLoginMethodVersion int64           `json:"expectedLoginMethodVersion"`
	Payload                    IdentityPayload `json:"payload"`
}

func (r IdentityOperationCreate) MarshalJSON() ([]byte, error) {
	var kind IdentityOperationType
	switch r.Payload.(type) {
	case AddIdentity:
		kind = IdentityOperationType("ADD")
	case VerifyIdentity:
		kind = IdentityOperationType("VERIFY")
	case SetPrimaryIdentity:
		kind = IdentityOperationType("SET_PRIMARY")
	case RemoveIdentity:
		kind = IdentityOperationType("REMOVE")
	case ReplaceIdentity:
		kind = IdentityOperationType("REPLACE")
	case LinkIdentity:
		kind = IdentityOperationType("LINK")
	case UnlinkIdentity:
		kind = IdentityOperationType("UNLINK")
	case TransferIdentity:
		kind = IdentityOperationType("TRANSFER")
	default:
		return nil, fmt.Errorf("iam: unsupported identity payload")
	}
	return json.Marshal(struct {
		Type                       IdentityOperationType `json:"type"`
		ExpectedLoginMethodVersion int64                 `json:"expectedLoginMethodVersion"`
		Payload                    IdentityPayload       `json:"payload"`
	}{kind, r.ExpectedLoginMethodVersion, r.Payload})
}
func (r PasswordReauthentication) MarshalJSON() ([]byte, error) {
	type raw PasswordReauthentication
	return json.Marshal(struct {
		raw
		Discriminator string `json:"method"`
	}{raw(r), "PASSWORD"})
}
func (r EmailOTPReauthentication) MarshalJSON() ([]byte, error) {
	type raw EmailOTPReauthentication
	return json.Marshal(struct {
		raw
		Discriminator string `json:"method"`
	}{raw(r), "EMAIL_OTP"})
}
func (r IdentityTargetProof) MarshalJSON() ([]byte, error) {
	type raw IdentityTargetProof
	return json.Marshal(struct {
		raw
		Discriminator string `json:"purpose"`
	}{raw(r), "TARGET_OWNERSHIP"})
}

// IdentifierCapability is an authenticated advisory snapshot; every mutation is revalidated.
type IdentifierCapability struct {
	Allowed               bool                    `json:"allowed"`
	UnavailableReasons    []IdentifierDenial      `json:"unavailableReasons"`
	Requirements          []IdentifierRequirement `json:"requirements"`
	ReplacementPrimaryIDs []string                `json:"replacementPrimaryIds"`
}
type IdentifierManagement struct {
	Add          map[IdentifierKind]IdentifierCapability `json:"add"`
	ProofOptions []OperationProofOption                  `json:"proofOptions"`
}
type IdentifierAction string

const (
	IdentifierActionVerify     IdentifierAction = "VERIFY"
	IdentifierActionSetPrimary IdentifierAction = "SET_PRIMARY"
	IdentifierActionRemove     IdentifierAction = "REMOVE"
	IdentifierActionReplace    IdentifierAction = "REPLACE"
	IdentifierActionTransfer   IdentifierAction = "TRANSFER"
)

type IdentifierDenial string

const (
	IdentifierDenialAccountInactive               IdentifierDenial = "ACCOUNT_INACTIVE"
	IdentifierDenialManagedIdentifier             IdentifierDenial = "MANAGED_IDENTIFIER"
	IdentifierDenialMethodUnavailable             IdentifierDenial = "METHOD_UNAVAILABLE"
	IdentifierDenialReauthMethodUnavailable       IdentifierDenial = "REAUTH_METHOD_UNAVAILABLE"
	IdentifierDenialTargetProofUnavailable        IdentifierDenial = "TARGET_PROOF_UNAVAILABLE"
	IdentifierDenialIdentifierAlreadyExists       IdentifierDenial = "IDENTIFIER_ALREADY_EXISTS"
	IdentifierDenialNotApplicable                 IdentifierDenial = "NOT_APPLICABLE"
	IdentifierDenialAlreadyVerified               IdentifierDenial = "ALREADY_VERIFIED"
	IdentifierDenialAlreadyPrimary                IdentifierDenial = "ALREADY_PRIMARY"
	IdentifierDenialIdentifierUnverified          IdentifierDenial = "IDENTIFIER_UNVERIFIED"
	IdentifierDenialIdentifierRangeRejected       IdentifierDenial = "IDENTIFIER_RANGE_REJECTED"
	IdentifierDenialLastLoginMethod               IdentifierDenial = "LAST_LOGIN_METHOD"
	IdentifierDenialPrimaryReplacementUnavailable IdentifierDenial = "PRIMARY_REPLACEMENT_UNAVAILABLE"
)

type IdentifierRequirement string

const (
	IdentifierRequirementCurrentAccountProof     IdentifierRequirement = "CURRENT_ACCOUNT_PROOF"
	IdentifierRequirementNewIdentifier           IdentifierRequirement = "NEW_IDENTIFIER"
	IdentifierRequirementTargetEmailOtp          IdentifierRequirement = "TARGET_EMAIL_OTP"
	IdentifierRequirementTargetPhoneOtp          IdentifierRequirement = "TARGET_PHONE_OTP"
	IdentifierRequirementReplacementPrimary      IdentifierRequirement = "REPLACEMENT_PRIMARY"
	IdentifierRequirementRemoveOld               IdentifierRequirement = "REMOVE_OLD"
	IdentifierRequirementCounterpartConfirmation IdentifierRequirement = "COUNTERPART_CONFIRMATION"
	IdentifierRequirementRemainingLoginPath      IdentifierRequirement = "REMAINING_LOGIN_PATH"
)

// RecoveryCodesRemaining is the current unused count, not generation-time delivery.
type RecoveryCodesRemaining struct {
	Remaining int64 `json:"remaining"`
}
