package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"unicode"
)

// RegistrationGrantDeliveryRequest queues an explicitly addressed LINK or CODE email.
type RegistrationGrantDeliveryRequest struct {
	Recipient string `json:"recipient"`
	Locale    string `json:"locale,omitempty"`
	Variant   string `json:"variant"`
}

// RegistrationGrantDelivery is safe status, never invitation credentials.
type RegistrationGrantDelivery struct {
	ID            string  `json:"id"`
	GrantID       string  `json:"grantId"`
	Recipient     string  `json:"recipient"`
	Variant       string  `json:"variant"`
	Status        string  `json:"status"`
	FailureCode   *string `json:"failureCode"`
	AttemptCount  int     `json:"attemptCount"`
	MaxAttempts   *int    `json:"maxAttempts"`
	NextAttemptAt *string `json:"nextAttemptAt"`
	Retryable     bool    `json:"retryable"`
	ExpiresAt     string  `json:"expiresAt"`
	CreatedAt     string  `json:"createdAt"`
}

func (delivery *RegistrationGrantDelivery) UnmarshalJSON(data []byte) error {
	type plain RegistrationGrantDelivery
	var value struct {
		*plain
		AttemptCount *int  `json:"attemptCount"`
		Retryable    *bool `json:"retryable"`
	}
	value.plain = (*plain)(delivery)
	if err := json.Unmarshal(data, &value); err != nil {
		return invalidRegistrationGrantResponse()
	}
	if value.AttemptCount == nil || *value.AttemptCount < 0 || value.Retryable == nil ||
		strings.TrimSpace(delivery.ID) == "" || strings.TrimSpace(delivery.GrantID) == "" ||
		strings.TrimSpace(delivery.Recipient) == "" || strings.TrimSpace(delivery.ExpiresAt) == "" ||
		strings.TrimSpace(delivery.CreatedAt) == "" || (delivery.MaxAttempts != nil && *delivery.MaxAttempts < 1) ||
		(delivery.Variant != "LINK" && delivery.Variant != "CODE") || !delivery.validStatus() {
		return invalidRegistrationGrantResponse()
	}
	delivery.AttemptCount = *value.AttemptCount
	delivery.Retryable = *value.Retryable
	return nil
}

func (grant *RegistrationGrant) UnmarshalJSON(data []byte) error {
	type plain RegistrationGrant
	var value struct {
		*plain
		Version *int64 `json:"version"`
	}
	value.plain = (*plain)(grant)
	if err := json.Unmarshal(data, &value); err != nil || value.Version == nil || *value.Version < 0 {
		return invalidRegistrationGrantResponse()
	}
	grant.Version = *value.Version
	return nil
}

func (created *CreatedRegistrationGrant) UnmarshalJSON(data []byte) error {
	type plain CreatedRegistrationGrant
	var value struct {
		*plain
		SecretAlreadyIssued *bool `json:"secretAlreadyIssued"`
	}
	value.plain = (*plain)(created)
	if err := json.Unmarshal(data, &value); err != nil || value.SecretAlreadyIssued == nil {
		return invalidRegistrationGrantResponse()
	}
	created.SecretAlreadyIssued = *value.SecretAlreadyIssued
	return created.validate()
}

func registrationCommandHeaders(key string) (http.Header, error) {
	if strings.TrimSpace(key) == "" || len([]rune(key)) > 200 || strings.ContainsFunc(key, unicode.IsControl) {
		return nil, &PortalOpenAPIError{Code: "invalid_idempotency_key"}
	}
	return http.Header{"Idempotency-Key": {key}}, nil
}

// RotateRegistrationGrant rotates the last observed version without automatically retrying.
func (c *PortalOpenAPIClient) RotateRegistrationGrant(ctx context.Context, grantID string, expectedVersion int64, idempotencyKey string) (*CreatedRegistrationGrant, error) {
	path, err := registrationGrantPath(grantID)
	if err != nil {
		return nil, err
	}
	if expectedVersion < 0 {
		return nil, invalidRegistrationGrantResponse()
	}
	headers, err := registrationCommandHeaders(idempotencyKey)
	if err != nil {
		return nil, err
	}
	var response CreatedRegistrationGrant
	body := struct {
		ExpectedVersion int64 `json:"expectedVersion"`
	}{expectedVersion}
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, path+"/rotate", RegistrationGrantsWriteScope, body, &response, headers)
	if err != nil {
		return nil, err
	}
	if response.Grant.ID != grantID {
		return nil, invalidRegistrationGrantResponse()
	}
	return &response, nil
}

// DeliverRegistrationGrant queues one email using registration_grants:write.
func (c *PortalOpenAPIClient) DeliverRegistrationGrant(ctx context.Context, grantID string, request RegistrationGrantDeliveryRequest, idempotencyKey string) (*RegistrationGrantDelivery, error) {
	path, err := registrationGrantPath(grantID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Recipient) == "" || (request.Variant != "LINK" && request.Variant != "CODE") {
		return nil, invalidRegistrationGrantResponse()
	}
	headers, err := registrationCommandHeaders(idempotencyKey)
	if err != nil {
		return nil, err
	}
	var response RegistrationGrantDelivery
	_, err = c.requestJSONWithScopeAndHeaders(ctx, http.MethodPost, path+"/deliveries", RegistrationGrantsWriteScope, request, &response, headers)
	if err != nil {
		return nil, err
	}
	if response.GrantID != grantID || response.Variant != request.Variant || !response.validStatus() {
		return nil, invalidRegistrationGrantResponse()
	}
	return &response, nil
}

// GetRegistrationGrantDelivery reads authoritative status using registration_grants:read.
func (c *PortalOpenAPIClient) GetRegistrationGrantDelivery(ctx context.Context, grantID, deliveryID string) (*RegistrationGrantDelivery, error) {
	path, err := registrationGrantPath(grantID)
	if err != nil {
		return nil, err
	}
	if _, err := registrationGrantPath(deliveryID); err != nil {
		return nil, err
	}
	var response RegistrationGrantDelivery
	if err := c.requestJSONWithScope(ctx, http.MethodGet, path+"/deliveries/"+deliveryID, RegistrationGrantsReadScope, nil, &response); err != nil {
		return nil, err
	}
	if response.GrantID != grantID || response.ID != deliveryID || (response.Variant != "LINK" && response.Variant != "CODE") || !response.validStatus() {
		return nil, invalidRegistrationGrantResponse()
	}
	return &response, nil
}

func (delivery RegistrationGrantDelivery) validStatus() bool {
	switch delivery.Status {
	case "QUEUED", "SENDING", "DELIVERED", "FAILED", "UNKNOWN":
		return true
	default:
		return false
	}
}
