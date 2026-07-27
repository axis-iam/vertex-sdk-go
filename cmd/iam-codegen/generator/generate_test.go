package generator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
)

type codeGenerationPermission struct {
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type codeGenerationFixture struct {
	CodeGeneration struct {
		Permissions   []codeGenerationPermission `json:"permissions"`
		ExpectedNames struct {
			Go []string `json:"go"`
		} `json:"expectedNames"`
		Reject []struct {
			Name           string                     `json:"name"`
			Classification string                     `json:"classification"`
			Permissions    []codeGenerationPermission `json:"permissions"`
		} `json:"reject"`
	} `json:"codeGeneration"`
}

func TestConstName(t *testing.T) {
	cases := map[[2]string]string{
		{"posts", "read"}:        "PostsRead",
		{"signing-keys", "read"}: "SigningKeysRead",
		{"posts", "write"}:       "PostsWrite",
		{"snake_case", "do"}:     "SnakeCaseDo",
	}
	for in, want := range cases {
		if got := ConstName(in[0], in[1]); got != want {
			t.Errorf("ConstName(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestRender(t *testing.T) {
	src, err := Render(Input{
		Package: "perms",
		Permissions: []authz.PermissionDefinition{
			{Resource: "posts", Action: "read", Description: "Read posts"},
			{Resource: "posts", Action: "write", Description: "Write posts"},
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "package perms") {
		t.Fatal("missing package header")
	}
	if !strings.Contains(s, "PostsRead") || !strings.Contains(s, "PostsWrite") {
		t.Fatal("missing const names")
	}
	if !strings.Contains(s, "var All = []authz.PermissionDefinition") {
		t.Fatal("missing All slice")
	}
	if !strings.Contains(s, `"Read posts"`) {
		t.Fatal("description not emitted")
	}
}

func TestRender_Deterministic(t *testing.T) {
	defs := []authz.PermissionDefinition{
		{Resource: "b", Action: "y"},
		{Resource: "a", Action: "x"},
	}
	a, _ := Render(Input{Package: "p", Permissions: defs})
	defs[0], defs[1] = defs[1], defs[0]
	b, _ := Render(Input{Package: "p", Permissions: defs})
	if string(a) != string(b) {
		t.Fatal("render is non-deterministic")
	}
}

func TestRenderRejectsGeneratedNameCollision(t *testing.T) {
	_, err := Render(Input{Package: "p", Permissions: []authz.PermissionDefinition{
		{Resource: "billing-events", Action: "read"},
		{Resource: "billing_events", Action: "read"},
	}})
	if err == nil || !strings.Contains(err.Error(), "name collision") {
		t.Fatalf("expected name collision, got %v", err)
	}
}

func TestRenderRejectsWildcardAndDuplicateKeys(t *testing.T) {
	for _, definitions := range [][]authz.PermissionDefinition{
		{{Resource: "orders", Action: "*"}},
		{{Resource: "*", Action: "*"}},
		{{Resource: "orders", Action: "read"}, {Resource: "orders", Action: "read"}},
	} {
		if _, err := Render(Input{Package: "p", Permissions: definitions}); err == nil {
			t.Fatalf("expected generator rejection for %#v", definitions)
		}
	}
}

func TestConstNamePrefixesLeadingDigit(t *testing.T) {
	if got := ConstName("2fa", "read"); got != "P2faRead" {
		t.Fatalf("ConstName() = %q", got)
	}
}

func TestRenderConsumesSharedCodeGenerationVector(t *testing.T) {
	fixture := loadCodeGenerationFixture(t)
	definitions := make([]authz.PermissionDefinition, len(fixture.CodeGeneration.Permissions))
	for i, permission := range fixture.CodeGeneration.Permissions {
		description := ""
		if permission.Description != nil {
			description = *permission.Description
		}
		definitions[i] = authz.PermissionDefinition{Resource: permission.Resource, Action: permission.Action, Description: description}
	}
	source, err := Render(Input{Package: "perms", Permissions: definitions})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range fixture.CodeGeneration.ExpectedNames.Go {
		if !strings.Contains(string(source), "\t"+name) {
			t.Fatalf("missing shared name %s", name)
		}
	}
}

func TestRenderExecutesEverySharedRejectionVector(t *testing.T) {
	fixture := loadCodeGenerationFixture(t)
	for _, vector := range fixture.CodeGeneration.Reject {
		t.Run(vector.Name, func(t *testing.T) {
			manifest := iam.PermissionManifest{ManifestID: "codegen", Revision: "1"}
			for _, permission := range vector.Permissions {
				manifest.Permissions = append(manifest.Permissions, iam.PermissionManifestDeclaration{
					Resource: permission.Resource, Action: permission.Action,
					Name: permission.Name, Description: permission.Description,
				})
			}
			classification := "NONE"
			prepared, err := iam.PreparePermissionManifest(manifest, iam.PermissionManifestValidate)
			if err == nil {
				definitions := make([]authz.PermissionDefinition, len(prepared.Permissions))
				for i, permission := range prepared.Permissions {
					description := ""
					if permission.Description != nil {
						description = *permission.Description
					}
					definitions[i] = authz.PermissionDefinition{Resource: permission.Resource, Action: permission.Action, Description: description}
				}
				_, err = Render(Input{Package: "perms", Permissions: definitions})
			}
			if err != nil {
				classification = classifyCodeGenerationError(err, vector.Permissions)
			}
			if classification != vector.Classification {
				t.Fatalf("classification = %s, want %s: %v", classification, vector.Classification, err)
			}
		})
	}
}

func loadCodeGenerationFixture(t *testing.T) codeGenerationFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "permission-manifest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture codeGenerationFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func classifyCodeGenerationError(err error, permissions []codeGenerationPermission) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "duplicate permission key"):
		return "DUPLICATE_KEY"
	case strings.Contains(message, "NFC"):
		return "NON_NFC"
	case strings.Contains(message, "name collision"):
		return "NAME_COLLISION"
	}
	for _, permission := range permissions {
		if permission.Resource == "*" || permission.Action == "*" {
			return "WILDCARD_KEY"
		}
	}
	if strings.Contains(message, "invalid concrete permission key") {
		return "MALFORMED_KEY"
	}
	return "UNKNOWN"
}
