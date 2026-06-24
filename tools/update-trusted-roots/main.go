// Command update-trusted-roots re-vendors the embedded public-good Sigstore
// trusted root (pkg/root/public-trusted-root.json) from the canonical Sigstore
// TUF repo (sigstore/root-signing). Run it via `task vendor-public-trusted-root`
// after a Sigstore key rotation instead of hand-editing the file. Verification
// at runtime stays on the embedded snapshot, so this is a maintenance step, not
// a runtime dependency.
package main

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

const out = "pkg/root/public-trusted-root.json"

func main() {
	client, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "tuf client: %v\n", err)
		os.Exit(1)
	}
	data, err := client.GetTarget("trusted_root.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch trusted_root.json: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", out, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes) from the Sigstore public-good TUF repo\n", out, len(data))
}
