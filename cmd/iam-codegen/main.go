// iam-codegen generates constants locally and validates/upserts structured manifests explicitly.
//
//	iam-codegen generate — generate Go constants from a local structured manifest
//	iam-codegen upload   — validate/upsert a structured manifest from a server-only job
//
// See `iam-codegen help` for flag details.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = runGenerate(os.Args[2:])
	case "upload":
		err = runUpload(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	case "version":
		fmt.Println("iam-codegen", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const version = "0.1.1"

func usage() {
	writeUsage(os.Stderr)
}

func writeUsage(output io.Writer) {
	fmt.Fprint(output, `iam-codegen — generate constants locally and publish structured manifests explicitly.

Usage:
  iam-codegen generate --manifest permissions.json --package perms \
                       --output internal/perms/permissions.gen.go

  iam-codegen upload --issuer-endpoint URL --portal-api-endpoint URL \
                     --client-id ID --client-secret SECRET --manifest permissions.json --mode validate

Common flags:
  --endpoint       IAM base URL (env: IAM_ENDPOINT)
  --client-id      ApplicationClient.clientId from a WEB/M2M confidential client (env: IAM_CLIENT_ID)
  --client-secret  WEB/M2M confidential ApplicationClient secret (env: IAM_CLIENT_SECRET)

Generate flags:
  --manifest       Structured permission manifest JSON file
  --package        Go package name for generated constants
  --output         Path to write the generated .go file

Upload flags:
  --manifest       Structured permission manifest JSON file; no Go source scanning
  --mode           validate or upsert (upsert also requires --idempotency-key)
`)
}
