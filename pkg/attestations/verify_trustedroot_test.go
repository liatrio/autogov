package attestations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bundleutils "github.com/liatrio/autogov/pkg/bundle"
	"github.com/liatrio/autogov/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigstorego_root "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// loadTestBundle loads a Sigstore bundle from testdata.
func loadTestBundle(t *testing.T, name string) *bundle.Bundle {
	t.Helper()
	b, err := bundle.LoadJSONFromPath(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load bundle %s: %v", name, err)
	}
	return b
}

// verifyTimestamps runs the timestamp-only portion of verification (no identity,
// no artifact) against the given trusted root and options — enough to exercise
// the integrated-timestamp path that regressed.
func verifyTimestamps(t *testing.T, b *bundle.Bundle, tr *sigstorego_root.TrustedRoot, opts []verify.VerifierOption) error {
	t.Helper()
	v, err := verify.NewVerifier(tr, opts...)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	_, err = v.Verify(b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe()))
	return err
}

// A public-good GitHub attestation (Fulcio sigstore.dev cert, Rekor integrated
// timestamp, no TSA) must verify: the public-good root is selected and the
// transparency-log entry is required so its integrated timestamp counts.
func TestPublicGoodBundleVerifies(t *testing.T) {
	b := loadTestBundle(t, "bundle-public-good.jsonl")

	der := bundleutils.LeafCertDER(b)
	if len(der) == 0 {
		t.Fatal("expected a signing certificate in the bundle")
	}
	src, err := root.DetectTrustedRootFromCert(der)
	if err != nil || src != root.TrustedRootSourcePublic {
		t.Fatalf("expected public-good trusted root, got %q (err %v)", src, err)
	}
	if len(b.GetVerificationMaterial().GetTlogEntries()) == 0 {
		t.Fatal("expected a transparency-log entry")
	}

	// github trust path is unused for a public-good cert but required by the API.
	githubTrust := writeGitHubTrust(t)
	tr, err := selectOnlineTrustedRoot(der, githubTrust)
	if err != nil {
		t.Fatalf("select trusted root: %v", err)
	}

	// production options: observer + transparency log -> PASS
	if err := verifyTimestamps(t, b, tr, timestampVerifierOpts(b)); err != nil {
		t.Fatalf("public-good bundle should verify with the integrated timestamp: %v", err)
	}

	// regression lock: observer-only (the pre-fix online config) -> FAIL
	err = verifyTimestamps(t, b, tr, []verify.VerifierOption{verify.WithObserverTimestamps(1)})
	if err == nil {
		t.Fatal("observer-only verification should fail without requiring the transparency log")
	}
	if !strings.Contains(err.Error(), "threshold not met") {
		t.Fatalf("expected a timestamp-threshold error, got: %v", err)
	}
}

// A GitHub-internal attestation (Fulcio githubapp.com cert, RFC3161 TSA, no log
// entry) must route to the GitHub root and must not require a transparency log.
func TestGitHubInternalBundleRouting(t *testing.T) {
	b := loadTestBundle(t, "bundle-github-internal.jsonl")

	der := bundleutils.LeafCertDER(b)
	if len(der) == 0 {
		t.Fatal("expected a signing certificate in the bundle")
	}
	src, err := root.DetectTrustedRootFromCert(der)
	if err != nil || src != root.TrustedRootSourceGitHub {
		t.Fatalf("expected GitHub trusted root, got %q (err %v)", src, err)
	}
	if len(b.GetVerificationMaterial().GetTlogEntries()) != 0 {
		t.Fatal("expected no transparency-log entry for a GitHub-internal bundle")
	}
	// no log entry -> the transparency-log option must not be added
	if got := len(timestampVerifierOpts(b)); got != 1 {
		t.Fatalf("expected only the observer-timestamps option, got %d options", got)
	}
}

// writeGitHubTrust writes the embedded GitHub trusted root to a temp file.
func writeGitHubTrust(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "github-trusted-root.json")
	if err := os.WriteFile(p, root.GetGitHubTrustedRoot(), 0600); err != nil {
		t.Fatalf("write github trusted root: %v", err)
	}
	return p
}
