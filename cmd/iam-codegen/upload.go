package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	iam "github.com/axis-iam/vertex-sdk-go"
)

func runUpload(args []string) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "Path to a structured permission manifest JSON file")
	issuer := fs.String("issuer-endpoint", os.Getenv("IAM_ISSUER_ENDPOINT"), "IAM OAuth issuer endpoint")
	portal := fs.String("portal-api-endpoint", os.Getenv("IAM_PORTAL_API_ENDPOINT"), "IAM Portal API endpoint")
	clientID := fs.String("client-id", os.Getenv("IAM_CLIENT_ID"), "M2M client id")
	clientSecret := fs.String("client-secret", os.Getenv("IAM_CLIENT_SECRET"), "M2M client secret")
	mode := fs.String("mode", "validate", "validate or upsert")
	idempotencyKey := fs.String("idempotency-key", "", "Required for upsert")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *issuer == "" || *portal == "" || *clientID == "" || *clientSecret == "" {
		return errors.New("manifest, issuer endpoint, Portal endpoint, client id and client secret are required")
	}
	manifest, err := loadPermissionManifest(*manifestPath)
	if err != nil {
		return err
	}
	client, err := iam.NewPermissionManifestClient(iam.PermissionManifestClientConfig{
		IssuerEndpoint: *issuer, PortalAPIEndpoint: *portal, ClientID: *clientID, ClientSecret: *clientSecret,
	})
	if err != nil {
		return err
	}
	var result *iam.PermissionManifestResult
	switch *mode {
	case "validate":
		result, err = client.ValidatePermissionManifest(context.Background(), manifest)
	case "upsert":
		result, err = client.UpsertPermissionManifest(context.Background(), manifest, *idempotencyKey)
	default:
		return errors.New("mode must be validate or upsert")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "mode=%s created=%d updated=%d unchanged=%d conflict=%d drift=%d\n", result.Mode, result.Counts.Created, result.Counts.Updated, result.Counts.Unchanged, result.Counts.Conflict, result.Counts.Drift)
	return nil
}

func loadPermissionManifest(path string) (iam.PermissionManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return iam.PermissionManifest{}, err
	}
	structure := json.NewDecoder(bytes.NewReader(data))
	if err := rejectDuplicateJSONMembers(structure); err != nil {
		return iam.PermissionManifest{}, fmt.Errorf("decode structured manifest: %w", err)
	}
	if _, err := structure.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		return iam.PermissionManifest{}, fmt.Errorf("decode structured manifest: %w", err)
	}
	if err := requireExactManifestFields(data); err != nil {
		return iam.PermissionManifest{}, fmt.Errorf("decode structured manifest: %w", err)
	}
	var manifest iam.PermissionManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return iam.PermissionManifest{}, fmt.Errorf("decode structured manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		return iam.PermissionManifest{}, fmt.Errorf("decode structured manifest: %w", err)
	}
	return manifest, nil
}

func requireExactManifestFields(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	if !hasExactFields(root, "manifestId", "revision", "permissions") {
		return errors.New("manifest fields must be exactly manifestId, revision and permissions")
	}
	var declarations []map[string]json.RawMessage
	if err := json.Unmarshal(root["permissions"], &declarations); err != nil {
		return errors.New("manifest permissions must be an array of objects")
	}
	for _, declaration := range declarations {
		if !hasExactFields(declaration, "resource", "action", "name", "description") {
			return errors.New("permission declaration fields must be exactly resource, action, name and description")
		}
	}
	return nil
}

func hasExactFields(value map[string]json.RawMessage, fields ...string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := value[field]; !exists {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONMembers(decoder *json.Decoder) error {
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
		members := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object member name must be a string")
			}
			if _, exists := members[name]; exists {
				return fmt.Errorf("duplicate JSON member %q", name)
			}
			members[name] = struct{}{}
			if err := rejectDuplicateJSONMembers(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := rejectDuplicateJSONMembers(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if expected := map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter]; closing != expected {
		return errors.New("invalid JSON closing delimiter")
	}
	return nil
}
