package gitpolicy

import (
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		required string
		seen     map[string]bool
		expected bool
	}{
		{
			name:     "exact match",
			required: "user@example.com",
			seen:     map[string]bool{"user@example.com": true},
			expected: true,
		},
		{
			name:     "case insensitive match",
			required: "User@Example.com",
			seen:     map[string]bool{"user@example.com": true},
			expected: true,
		},
		{
			name:     "prefix match with path boundary",
			required: "https://github.com/org/repo",
			seen:     map[string]bool{"https://github.com/org/repo/.github/workflows/ci.yml": true},
			expected: true,
		},
		{
			name:     "prefix match with @ boundary",
			required: "https://github.com/org/repo",
			seen:     map[string]bool{"https://github.com/org/repo@refs/heads/main": true},
			expected: true,
		},
		{
			name:     "no match",
			required: "user@example.com",
			seen:     map[string]bool{"other@example.com": true},
			expected: false,
		},
		{
			name:     "prefix without boundary does not match",
			required: "https://github.com/org/repo",
			seen:     map[string]bool{"https://github.com/org/repo-evil": true},
			expected: false,
		},
		{
			name:     "empty seen map",
			required: "user@example.com",
			seen:     map[string]bool{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, signerMatchesAny(tt.required, tt.seen))
		})
	}
}

func TestVerifySignerPolicy_UnsignedCommits(t *testing.T) {
	// Create a repo with unsigned commits and a policy requiring signers.
	repoDir := createTestRepo(t, []string{
		"feat: first commit",
		"feat: second commit",
	})

	repo, err := git.PlainOpen(repoDir)
	require.NoError(t, err)

	policy := &Policy{
		RequiredSigners: map[string][]string{
			"refs/heads/master": {"user@example.com"},
		},
	}

	opts := VerifyOptions{
		RepoPath:  repoDir,
		TargetRef: "refs/heads/master",
	}

	status, err := VerifySignerPolicy(repo, "refs/heads/master", policy, opts)
	require.NoError(t, err)

	assert.False(t, status.AllSigned, "should fail: no signed commits")
	assert.Contains(t, status.MissingSigners, "user@example.com")
	assert.Empty(t, status.VerifiedSigners)
}

func TestVerifySignerPolicy_NoRequiredSigners(t *testing.T) {
	repoDir := createTestRepo(t, []string{"feat: commit"})

	repo, err := git.PlainOpen(repoDir)
	require.NoError(t, err)

	policy := &Policy{
		RequiredSigners: map[string][]string{},
	}

	opts := VerifyOptions{
		RepoPath:  repoDir,
		TargetRef: "refs/heads/master",
	}

	status, err := VerifySignerPolicy(repo, "refs/heads/master", policy, opts)
	require.NoError(t, err)

	assert.True(t, status.AllSigned, "should pass: no signers required")
	assert.Empty(t, status.MissingSigners)
}
