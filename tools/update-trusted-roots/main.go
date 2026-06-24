// Command update-trusted-roots re-vendors the embedded public-good Sigstore
// trusted root (pkg/root/public-trusted-root.json) from the canonical Sigstore
// TUF repo (sigstore/root-signing). Run it via `task vendor-public-trusted-root`
// after a Sigstore key rotation instead of hand-editing the file. Verification
// at runtime stays on the embedded snapshot, so this is a maintenance step, not
// a runtime dependency.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// must be run from the repo root (e.g. via `task vendor-public-trusted-root`).
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
	// fail loudly rather than vendor a truncated/garbage root.
	if len(data) < 512 || !json.Valid(data) {
		fmt.Fprintf(os.Stderr, "fetched trusted_root.json looks invalid (%d bytes); refusing to overwrite\n", len(data))
		os.Exit(1)
	}
	// normalize to indented JSON so re-running on an unchanged upstream yields a
	// clean, review-friendly diff instead of collapsing to one line.
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "indent trusted_root.json: %v\n", err)
		os.Exit(1)
	}
	buf.WriteByte('\n')
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", out, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes) from the Sigstore public-good TUF repo\n", out, buf.Len())
}
