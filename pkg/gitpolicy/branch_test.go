package gitpolicy

import (
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyBranchProtection_UnsignedCommits(t *testing.T) {
	repoDir := createTestRepo(t, []string{
		"feat: first commit",
		"feat: second commit",
		"feat: third commit",
	})

	repo, err := git.PlainOpen(repoDir)
	require.NoError(t, err)

	policy := &Policy{
		ProtectedBranches: map[string]BranchProtectionConfig{
			"refs/heads/master": {
				RequirePR:            true,
				RequireSignedCommits: true,
			},
		},
	}

	status, err := VerifyBranchProtection(repo, "refs/heads/master", policy, 50)
	require.NoError(t, err)

	assert.Equal(t, 3, status.TotalCommitCount)
	assert.Equal(t, 0, status.SignedCommitCount)
	assert.Equal(t, 0, status.MergeCommitCount)
	assert.False(t, status.Verified, "should fail: no signed commits, no merge commits")
}

func TestVerifyBranchProtection_NoPolicyConfig(t *testing.T) {
	repoDir := createTestRepo(t, []string{"feat: initial"})

	repo, err := git.PlainOpen(repoDir)
	require.NoError(t, err)

	policy := &Policy{
		ProtectedBranches: map[string]BranchProtectionConfig{},
	}

	status, err := VerifyBranchProtection(repo, "refs/heads/master", policy, 50)
	require.NoError(t, err)

	// No policy config — verification is lenient.
	assert.Equal(t, 1, status.TotalCommitCount)
}

func TestEvaluateBranchProtection(t *testing.T) {
	tests := []struct {
		name      string
		status    *BranchProtectionStatus
		hasConfig bool
		expected  bool
	}{
		{
			name: "no config, has merge commits",
			status: &BranchProtectionStatus{
				MergeCommitCount: 3,
				TotalCommitCount: 5,
			},
			hasConfig: false,
			expected:  true,
		},
		{
			name: "no config, no evidence",
			status: &BranchProtectionStatus{
				TotalCommitCount: 5,
			},
			hasConfig: false,
			expected:  false,
		},
		{
			name: "PR required but no merge commits",
			status: &BranchProtectionStatus{
				RequirePR:        true,
				TotalCommitCount: 5,
			},
			hasConfig: true,
			expected:  false,
		},
		{
			name: "PR required and has merge commits",
			status: &BranchProtectionStatus{
				RequirePR:        true,
				MergeCommitCount: 3,
				TotalCommitCount: 5,
			},
			hasConfig: true,
			expected:  true,
		},
		{
			name: "signed commits required, all signed",
			status: &BranchProtectionStatus{
				RequireSignedCommits: true,
				SignedCommitCount:    5,
				TotalCommitCount:    5,
			},
			hasConfig: true,
			expected:  true,
		},
		{
			name: "signed commits required, some unsigned",
			status: &BranchProtectionStatus{
				RequireSignedCommits: true,
				SignedCommitCount:    3,
				TotalCommitCount:    5,
			},
			hasConfig: true,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, evaluateBranchProtection(tt.status, tt.hasConfig))
		})
	}
}
