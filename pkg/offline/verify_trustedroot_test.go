package offline

import (
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

func loadOfflineBundle(t *testing.T, name string) *bundle.Bundle {
	t.Helper()
	b, err := bundle.LoadJSONFromPath(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load bundle %s: %v", name, err)
	}
	return b
}

// verifierOpts must require the transparency log for a public-good bundle (which
// carries a Rekor integrated timestamp and no TSA) and must not for a
// GitHub-internal bundle (TSA, no log entry). SkipTLogVerify forces it off.
func TestOfflineVerifierOptsByBundle(t *testing.T) {
	pub := loadOfflineBundle(t, "bundle-public-good.jsonl")
	gh := loadOfflineBundle(t, "bundle-github-internal.jsonl")

	ov := &OfflineVerifier{options: VerifyOptions{}}
	if got := len(ov.verifierOpts(pub)); got != 2 {
		t.Fatalf("public-good: want observer+transparency-log (2 options), got %d", got)
	}
	if got := len(ov.verifierOpts(gh)); got != 1 {
		t.Fatalf("github-internal: want observer only (1 option), got %d", got)
	}

	ovSkip := &OfflineVerifier{options: VerifyOptions{SkipTLogVerify: true}}
	if got := len(ovSkip.verifierOpts(pub)); got != 1 {
		t.Fatalf("SkipTLogVerify: want observer only (1 option), got %d", got)
	}
}

// A public-good bundle must verify end-to-end through the offline verifier with
// auto root selection (the regression: previously the GitHub root + dropped
// transparency log failed it with "0 < 1" timestamps).
func TestOfflineVerifyPublicGood(t *testing.T) {
	v, err := NewOfflineVerifier("", VerifyOptions{Quiet: true, TrustedRootSource: "auto"})
	if err != nil {
		t.Fatalf("new offline verifier: %v", err)
	}
	if v.trustedRoot != nil {
		t.Fatal("auto source should not pin a root up-front")
	}
	if err := v.LoadBundlesFromFile("testdata/bundle-public-good.jsonl"); err != nil {
		t.Fatalf("load bundles: %v", err)
	}
	res, err := v.VerifyArtifactDigest("")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Verified {
		t.Fatalf("public-good bundle should verify offline; errors=%v", res.Errors)
	}
}

// A GitHub-internal bundle (Fulcio O=GitHub, RFC3161 TSA, no tlog) must still
// verify end-to-end via auto root selection — the TSA satisfies the observer
// threshold and no transparency-log entry is required (no regression to the
// historically-shipped path). The short-lived cert is validated at the TSA's
// timestamp, so expiry since signing is fine.
func TestOfflineVerifyGitHubInternal(t *testing.T) {
	v, err := NewOfflineVerifier("", VerifyOptions{Quiet: true, TrustedRootSource: "auto"})
	if err != nil {
		t.Fatalf("new offline verifier: %v", err)
	}
	if err := v.LoadBundlesFromFile("testdata/bundle-github-internal.jsonl"); err != nil {
		t.Fatalf("load bundles: %v", err)
	}
	res, err := v.VerifyArtifactDigest("")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Verified {
		t.Fatalf("github-internal bundle should verify offline; errors=%v", res.Errors)
	}
}
