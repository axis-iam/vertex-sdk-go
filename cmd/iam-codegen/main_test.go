package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestUsageIsManifestFirst(t *testing.T) {
	var output bytes.Buffer
	if err := writeUsage(&output); err != nil {
		t.Fatal(err)
	}
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

type usageErrorWriter struct{}

func (usageErrorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestUsagePropagatesWriteFailure(t *testing.T) {
	if err := writeUsage(usageErrorWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write failure lost: %v", err)
	}
}
