package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageIsManifestFirst(t *testing.T) {
	var output bytes.Buffer
	writeUsage(&output)
	help := output.String()
	for _, expected := range []string{
		"iam-codegen generate --manifest permissions.json",
		"publish structured manifests explicitly",
		"no Go source scanning",
	} {
		if !strings.Contains(help, expected) {
			t.Fatalf("help is missing %q:\n%s", expected, help)
		}
	}
}
