package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/liatrio/autogov/pkg/gitpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeneratePolicyVSA_RecordsFalseForUnboundSigner asserts that the policy VSA
// records false for the signer/verification dimensions when a signer dimension is
// not satisfied (ac8). generatePolicyVSA is unexported, so this test lives in the
// in-package (package verify) test file rather than the external verify_test
// package, which cannot reach it.
//
// the result mirrors the interim-posture case the story calls out: commit
// signatures are CMS-valid but transparency-unbound, so they are excluded from
// SignedCommitCount and AllSigned. the VSA must not paint over that with a passing
// signer dimension.
func TestGeneratePolicyVSA_RecordsFalseForUnboundSigner(t *testing.T) {
	dir := t.TempDir()
	vsaOut := filepath.Join(dir, "vsa.json")

	result := &gitpolicy.VerificationResult{
		Ref:      "refs/heads/main",
		Verified: false, // overall fails because a signer dimension is false
		BranchProtection: &gitpolicy.BranchProtectionStatus{
			RequireSignedCommits: true,
			TotalCommitCount:     3,
			SignedCommitCount:    0, // none counted: all signatures transparency-unbound
			Verified:             false,
		},
		SignerPolicy: &gitpolicy.SignerPolicyStatus{
			RequiredSigners: []string{"https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main"},
			MissingSigners:  []string{"https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main"},
			AllSigned:       false,
		},
	}

	err := generatePolicyVSA(result, dir, vsaOut, "https://example.com/policy")
	require.NoError(t, err)

	raw, err := os.ReadFile(vsaOut)
	require.NoError(t, err)

	var parsed struct {
		Metadata struct {
			Details map[string]bool `json:"autogov.verification.details"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	details := parsed.Metadata.Details
	require.NotNil(t, details)
	assert.False(t, details["policy.verification"], "policy.verification must record false")
	assert.False(t, details["policy.signer_policy"], "policy.signer_policy must record false for an unbound signer")
	assert.False(t, details["policy.branch_protection"], "policy.branch_protection must record false")
}
