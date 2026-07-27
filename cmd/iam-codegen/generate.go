package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	iam "github.com/axis-iam/vertex-sdk-go"
	"github.com/axis-iam/vertex-sdk-go/authz"
	"github.com/axis-iam/vertex-sdk-go/cmd/iam-codegen/generator"
)

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "Path to a structured permission manifest JSON file")
	pkg := fs.String("package", "perms", "Go package name for the generated file")
	out := fs.String("output", "permissions.gen.go", "Output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return fmt.Errorf("missing --manifest")
	}
	manifest, err := loadPermissionManifest(*manifestPath)
	if err != nil {
		return err
	}
	prepared, err := iam.PreparePermissionManifest(manifest, iam.PermissionManifestValidate)
	if err != nil {
		return err
	}
	definitions := make([]authz.PermissionDefinition, len(prepared.Permissions))
	for i, permission := range prepared.Permissions {
		description := ""
		if permission.Description != nil {
			description = *permission.Description
		}
		definitions[i] = authz.PermissionDefinition{Resource: permission.Resource, Action: permission.Action, Description: description}
	}
	source, err := generator.Render(generator.Input{Package: *pkg, Permissions: definitions})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, source, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "wrote %d permission(s) -> %s\n", len(definitions), *out)
	return nil
}
