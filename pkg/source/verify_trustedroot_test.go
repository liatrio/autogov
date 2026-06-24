package source

import (
	"path/filepath"
	"strings"
	"testing"

	bundleutils "github.com/liatrio/autogov/pkg/bundle"
	localroot "github.com/liatrio/autogov/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func loadBundle(t *testing.T, name string) *bundle.Bundle {
	t.Helper()
	b, err := bundle.LoadJSONFromPath(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load bundle %s: %v", name, err)
	}
	return b
}

// observerOpts mirrors VerifySourceProvenance's verifier options.
func observerOpts(b *bundle.Bundle) []verify.VerifierOption {
	opts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if len(b.GetVerificationMaterial().GetTlogEntries()) > 0 {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	return opts
}

// A public-good source bundle (Fulcio sigstore.dev, Rekor integrated timestamp,
// no TSA) must select the public-good root and verify with the log entry required.
func TestSelectTrustedRootPublicGoodVerifies(t *testing.T) {
	b := loadBundle(t, "bundle-public-good.jsonl")

	if src, err := localroot.DetectTrustedRootFromCert(bundleutils.LeafCertDER(b)); err != nil || src != localroot.TrustedRootSourcePublic {
		t.Fatalf("expected public-good trusted root, got %q (err %v)", src, err)
	}

	tr, err := selectTrustedRootForBundle(b)
	if err != nil {
		t.Fatalf("select trusted root: %v", err)
	}

	v, err := verify.NewVerifier(tr, observerOpts(b)...)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if _, err := v.Verify(b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe())); err != nil {
		t.Fatalf("public-good bundle should verify: %v", err)
	}

	// regression lock: observer-only (no transparency log) must fail.
	vBad, _ := verify.NewVerifier(tr, verify.WithObserverTimestamps(1))
	_, err = vBad.Verify(b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe()))
	if err == nil || !strings.Contains(err.Error(), "threshold not met") {
		t.Fatalf("observer-only verification should fail with a timestamp-threshold error, got: %v", err)
	}
}

// A GitHub-internal bundle must route to the GitHub root and not require a log.
func TestSelectTrustedRootGitHubInternalRouting(t *testing.T) {
	b := loadBundle(t, "bundle-github-internal.jsonl")

	if src, err := localroot.DetectTrustedRootFromCert(bundleutils.LeafCertDER(b)); err != nil || src != localroot.TrustedRootSourceGitHub {
		t.Fatalf("expected GitHub trusted root, got %q (err %v)", src, err)
	}
	if len(b.GetVerificationMaterial().GetTlogEntries()) != 0 {
		t.Fatal("expected no transparency-log entry")
	}
	if got := len(observerOpts(b)); got != 1 {
		t.Fatalf("expected only the observer-timestamps option, got %d", got)
	}
}
