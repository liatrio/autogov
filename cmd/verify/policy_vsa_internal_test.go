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

// TestGeneratePolicyVSA_RecordsFalseForUnsignedSignerDimensions proves the VSA
// records false for the signer/verification keys when a signer dimension fails
// (ac8). generatePolicyVSA is unexported, so this test lives in-package
// (package verify) — the external cmd/verify/policy_test.go cannot reach it.
//
// This is the vsa-records-false case the story calls out: the overall policy
// result is still true (no RequireSignedCommits ref to flip BranchProtection),
// yet a signer dimension is false. The VSA's verificationResults must reflect
// that — i.e. transparency-unbound signatures cannot mint a "passing" signer
// dimension into a signed VSA.
func TestGeneratePolicyVSA_RecordsFalseForUnsignedSignerDimensions(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "vsa.json")

	result := &gitpolicy.VerificationResult{
		Ref:      "refs/heads/main",
		Verified: true, // overall policy still true (no RequireSignedCommits)
		BranchProtection: &gitpolicy.BranchProtectionStatus{
			Verified:          true,
			SignedCommitCount: 0,
			TotalCommitCount:  3, // none of the 3 commits transparency-bound
		},
		SignerPolicy: &gitpolicy.SignerPolicyStatus{
			RequiredSigners: []string{"required@example.com"},
			AllSigned:       false, // signer dimension fails
			MissingSigners:  []string{"required@example.com"},
		},
	}

	err := generatePolicyVSA(result, dir, out, "https://example.com/policy")
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var vsa struct {
		Predicate struct {
			VerificationResult string `json:"verificationResult"`
		} `json:"predicate"`
		Metadata struct {
			Details map[string]bool `json:"autogov.verification.details"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(data, &vsa))

	details := vsa.Metadata.Details
	require.NotNil(t, details)
	assert.False(t, details["policy.signer_policy"],
		"signer policy must record false when AllSigned is false")
	// overall verificationResult must be FAILED because a sub-key is false.
	assert.Equal(t, "FAILED", vsa.Predicate.VerificationResult,
		"a false signer dimension must flip the overall VSA result to FAILED")
}
