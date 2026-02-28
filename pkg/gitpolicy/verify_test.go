package gitpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRepo creates a temp git repo with unsigned commits.
func createTestRepo(t *testing.T, commitMsgs []string) string {
	t.Helper()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	for i, msg := range commitMsgs {
		content := []byte(fmt.Sprintf("content %d\n", i))
		err = os.WriteFile(filepath.Join(dir, "file.txt"), content, 0o644)
		require.NoError(t, err)

		_, err = wt.Add("file.txt")
		require.NoError(t, err)

		_, err = wt.Commit(msg, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test User",
				Email: "test@example.com",
				When:  time.Date(2025, 1, i+1, 0, 0, 0, 0, time.UTC),
			},
		})
		require.NoError(t, err)
	}

	return dir
}

// createPolicyFile creates a simple policy file in the given directory.
func createPolicyFile(t *testing.T, dir string) string {
	t.Helper()
	policyDir := filepath.Join(dir, ".gittuf")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	policyFile := filepath.Join(policyDir, "policy.json")
	data := []byte(`{
		"rules": [{"name": "signed-commits", "pattern": "refs/heads/master"}],
		"protected_branches": {
			"refs/heads/master": {
				"require_pr": true,
				"require_signed_commits": true
			}
		},
		"required_signers": {}
	}`)
	require.NoError(t, os.WriteFile(policyFile, data, 0o644))
	return policyFile
}

func TestVerifyPolicy_WithExplicitPolicy(t *testing.T) {
	repoDir := createTestRepo(t, []string{
		"feat: initial commit",
		"feat: second commit",
	})
	policyFile := createPolicyFile(t, repoDir)

	result, err := VerifyPolicy(VerifyOptions{
		RepoPath:   repoDir,
		TargetRef:  "refs/heads/master",
		PolicyPath: policyFile,
	})

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "refs/heads/master", result.Ref)
	// Unsigned commits, no merge commits — branch protection should fail.
	if result.BranchProtection != nil {
		assert.Equal(t, 2, result.BranchProtection.TotalCommitCount)
		assert.Equal(t, 0, result.BranchProtection.SignedCommitCount)
		assert.Equal(t, 0, result.BranchProtection.MergeCommitCount)
	}
}

func TestVerifyPolicy_NoPolicy(t *testing.T) {
	repoDir := createTestRepo(t, []string{"feat: initial commit"})

	result, err := VerifyPolicy(VerifyOptions{
		RepoPath:  repoDir,
		TargetRef: "refs/heads/master",
	})

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.ErrorMsg, "expected error about no policy found")
}

func TestVerifyPolicy_InvalidRepo(t *testing.T) {
	_, err := VerifyPolicy(VerifyOptions{
		RepoPath:  "/nonexistent",
		TargetRef: "refs/heads/main",
	})
	assert.Error(t, err)
}

func TestComputeOverallStatus(t *testing.T) {
	tests := []struct {
		name     string
		result   *VerificationResult
		expected bool
	}{
		{
			name:     "error message present",
			result:   &VerificationResult{ErrorMsg: "something failed"},
			expected: false,
		},
		{
			name: "branch protection verified, no signer policy",
			result: &VerificationResult{
				BranchProtection: &BranchProtectionStatus{Verified: true},
			},
			expected: true,
		},
		{
			name: "branch protection failed",
			result: &VerificationResult{
				BranchProtection: &BranchProtectionStatus{Verified: false},
			},
			expected: false,
		},
		{
			name: "signer policy all signed",
			result: &VerificationResult{
				SignerPolicy: &SignerPolicyStatus{AllSigned: true},
			},
			expected: true,
		},
		{
			name: "signer policy missing signers",
			result: &VerificationResult{
				SignerPolicy: &SignerPolicyStatus{AllSigned: false},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, computeOverallStatus(tt.result))
		})
	}
}

func TestBuildPolicyRules(t *testing.T) {
	policy := &Policy{
		ProtectedBranches: map[string]BranchProtectionConfig{
			"refs/heads/main": {
				RequirePR:            true,
				RequireSignedCommits: true,
				RequireReviews:       true,
				MinReviewers:         2,
			},
		},
		RequiredSigners: map[string][]string{
			"refs/heads/main": {"user@example.com"},
		},
	}

	rules := buildPolicyRules(policy, "refs/heads/main")
	assert.GreaterOrEqual(t, len(rules), 3) // require-pr, require-reviews, require-signed-commits, required-signers

	ruleNames := make([]string, len(rules))
	for i, r := range rules {
		ruleNames[i] = r.Name
	}
	assert.Contains(t, ruleNames, "require-pr")
	assert.Contains(t, ruleNames, "require-signed-commits")
	assert.Contains(t, ruleNames, "required-signers")
}

func TestBuildPolicyRules_NoMatchingRef(t *testing.T) {
	policy := &Policy{
		ProtectedBranches: map[string]BranchProtectionConfig{
			"refs/heads/main": {RequirePR: true},
		},
	}

	rules := buildPolicyRules(policy, "refs/heads/develop")
	assert.Empty(t, rules)
}
