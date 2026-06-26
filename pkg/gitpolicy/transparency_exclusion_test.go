package gitpolicy

import (
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/liatrio/autogov/pkg/gitsign/cmstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyBranchProtection_TransparencyUnboundExcluded proves a CMS-valid but
// transparency-unbound commit (a real "SIGNED MESSAGE" signature with no RFC3161
// timestamp token and no rekor entry) does NOT count toward SignedCommitCount
// (ac7). This differs from the unsigned-commit case: the commit DOES carry a
// signature, so it reaches the cms/transparency path rather than short-circuiting
// as unsigned — the exclusion is therefore exercised by the new logic.
func TestVerifyBranchProtection_TransparencyUnboundExcluded(t *testing.T) {
	repoDir := createTestRepo(t, []string{"feat: initial"})
	// add a commit carrying a structurally valid CMS signature but no
	// transparency anchor.
	cmstest.AddUnboundSignedCommit(t, repoDir, "feat: cms-signed but unbound", "payload\n")

	repo, err := git.PlainOpen(repoDir)
	require.NoError(t, err)

	policy := &Policy{
		ProtectedBranches: map[string]BranchProtectionConfig{
			"refs/heads/master": {
				RequireSignedCommits: true,
			},
		},
	}

	status, err := VerifyBranchProtection(repo, "refs/heads/master", policy, 50)
	require.NoError(t, err)

	assert.Equal(t, 2, status.TotalCommitCount)
	assert.Equal(t, 0, status.SignedCommitCount,
		"a transparency-unbound CMS signature must not count as a signed commit")
	assert.False(t, status.Verified,
		"RequireSignedCommits cannot pass on presence-only signatures")
}

// TestVerifySignerPolicy_TransparencyUnboundExcluded proves a CMS-valid but
// transparency-unbound commit does NOT populate AllSigned / VerifiedSigners
// (ac7).
func TestVerifySignerPolicy_TransparencyUnboundExcluded(t *testing.T) {
	repoDir := createTestRepo(t, []string{"feat: initial"})
	cmstest.AddUnboundSignedCommit(t, repoDir, "feat: cms-signed but unbound", "payload\n")

	repo, err := git.PlainOpen(repoDir)
	require.NoError(t, err)

	policy := &Policy{
		RequiredSigners: map[string][]string{
			"refs/heads/master": {cmstest.SignerEmail},
		},
	}
	opts := VerifyOptions{
		RepoPath:  repoDir,
		TargetRef: "refs/heads/master",
	}

	status, err := VerifySignerPolicy(repo, "refs/heads/master", policy, opts)
	require.NoError(t, err)

	assert.False(t, status.AllSigned,
		"a transparency-unbound signer must not satisfy a required-signer policy")
	assert.Empty(t, status.VerifiedSigners,
		"transparency-unbound signers must not be collected")
	assert.Contains(t, status.MissingSigners, cmstest.SignerEmail)
}
