package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeRepoURI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain https", "https://github.com/org/repo", "github.com/org/repo"},
		{"git+https", "git+https://github.com/org/repo", "github.com/org/repo"},
		{"with .git suffix", "https://github.com/org/repo.git", "github.com/org/repo"},
		{"with trailing slash", "https://github.com/org/repo/", "github.com/org/repo"},
		{"with @ref", "git+https://github.com/org/repo@refs/heads/main", "github.com/org/repo"},
		{"bare domain", "github.com/org/repo", "github.com/org/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeRepoURI(tt.input))
		})
	}
}

func TestMatchRepoURI(t *testing.T) {
	tests := []struct {
		name        string
		attestation string
		expected    string
		match       bool
	}{
		{"exact match", "https://github.com/org/repo", "https://github.com/org/repo", true},
		{"git+ prefix vs plain", "git+https://github.com/org/repo", "https://github.com/org/repo", true},
		{"bare vs https", "github.com/org/repo", "https://github.com/org/repo", true},
		{"case insensitive", "https://github.com/Org/Repo", "https://github.com/org/repo", true},
		{"different repo", "https://github.com/org/other", "https://github.com/org/repo", false},
		{"with @ref", "git+https://github.com/org/repo@refs/heads/main", "https://github.com/org/repo", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, matchRepoURI(tt.attestation, tt.expected))
		})
	}
}

func TestMatchCommitSHA(t *testing.T) {
	fullSHA := "abc1234567890def1234567890abcdef12345678"

	tests := []struct {
		name        string
		attestation string
		expected    string
		match       bool
	}{
		{"exact match", fullSHA, fullSHA, true},
		{"short expected matches long (7 chars)", fullSHA, "abc1234", true},
		{"short attestation matches long (7 chars)", "abc1234", fullSHA, true},
		{"mismatch", fullSHA, "def4567890", false},
		{"case insensitive", "ABC1234567890DEF1234567890ABCDEF12345678", fullSHA, true},
		{"too short prefix rejected (6 chars)", fullSHA, "abc123", false},
		{"too short prefix rejected (4 chars)", fullSHA, "abc1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, matchCommitSHA(tt.attestation, tt.expected))
		})
	}
}

func TestIsAcceptedPredicateType(t *testing.T) {
	assert.True(t, isAcceptedPredicateType("https://slsa.dev/provenance/v1"))
	assert.True(t, isAcceptedPredicateType("https://slsa.dev/source-provenance/v0.1"))
	assert.False(t, isAcceptedPredicateType("https://example.com/unknown"))
}

func TestComputeSLSASourceLevel(t *testing.T) {
	tests := []struct {
		name     string
		verified bool
		pred     SourceProvenancePredicate
		expected string
	}{
		{
			name:     "unverified signature returns L1",
			verified: false,
			pred:     SourceProvenancePredicate{},
			expected: "SLSA_SOURCE_LEVEL_1",
		},
		{
			name:     "verified signature without controlled builder returns L2",
			verified: true,
			pred:     SourceProvenancePredicate{},
			expected: "SLSA_SOURCE_LEVEL_2",
		},
		{
			name:     "verified with SLSA framework builder and build type returns L3",
			verified: true,
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.RunDetails.Builder.ID = "https://github.com/slsa-framework/slsa-github-generator"
				p.BuildDefinition.BuildType = "https://slsa.dev/source/v0.1"
				return p
			}(),
			expected: "SLSA_SOURCE_LEVEL_3",
		},
		{
			name:     "verified with GitHub Actions builder returns L3",
			verified: true,
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.RunDetails.Builder.ID = "https://github.com/actions/runner"
				p.BuildDefinition.BuildType = "https://github.com/actions/buildtype/v1"
				return p
			}(),
			expected: "SLSA_SOURCE_LEVEL_3",
		},
		{
			name:     "spoofed builder ID does not achieve L3",
			verified: true,
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.RunDetails.Builder.ID = "https://evil.com/github.com/slsa-framework/fake"
				p.BuildDefinition.BuildType = "https://slsa.dev/source/v0.1"
				return p
			}(),
			expected: "SLSA_SOURCE_LEVEL_2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ComputeSLSASourceLevel(tt.verified, tt.pred))
		})
	}
}

func TestExtractRepoURI(t *testing.T) {
	tests := []struct {
		name      string
		statement inTotoStatement
		pred      SourceProvenancePredicate
		expected  string
	}{
		{
			name: "from externalParameters.repository",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ExternalParameters.Repository = "https://github.com/org/repo"
				return p
			}(),
			expected: "https://github.com/org/repo",
		},
		{
			name: "from workflow.repository",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ExternalParameters.Workflow.Repository = "https://github.com/org/repo"
				return p
			}(),
			expected: "https://github.com/org/repo",
		},
		{
			name: "from resolvedDependencies",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ResolvedDependencies = []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				}{
					{URI: "git+https://github.com/org/repo@refs/heads/main"},
				}
				return p
			}(),
			expected: "github.com/org/repo",
		},
		{
			name: "from statement subject",
			statement: inTotoStatement{
				Subject: []statementSubject{
					{URI: "git+https://github.com/org/repo"},
				},
			},
			expected: "github.com/org/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractRepoURI(tt.statement, tt.pred))
		})
	}
}

func TestExtractCommitSHA(t *testing.T) {
	tests := []struct {
		name      string
		statement inTotoStatement
		pred      SourceProvenancePredicate
		expected  string
	}{
		{
			name: "from resolvedDependencies gitCommit digest",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ResolvedDependencies = []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				}{
					{Digest: map[string]string{"gitCommit": "abc123"}},
				}
				return p
			}(),
			expected: "abc123",
		},
		{
			name: "from statement subject gitCommit digest",
			statement: inTotoStatement{
				Subject: []statementSubject{
					{Digest: map[string]string{"gitCommit": "def456"}},
				},
			},
			expected: "def456",
		},
		{
			name:      "empty when no commit found",
			statement: inTotoStatement{},
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractCommitSHA(tt.statement, tt.pred))
		})
	}
}

func TestExtractSourceRef(t *testing.T) {
	tests := []struct {
		name     string
		pred     SourceProvenancePredicate
		expected string
	}{
		{
			name: "from externalParameters.ref",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ExternalParameters.Ref = "refs/heads/main"
				return p
			}(),
			expected: "refs/heads/main",
		},
		{
			name: "from workflow.ref",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ExternalParameters.Workflow.Ref = "refs/tags/v1.0.0"
				return p
			}(),
			expected: "refs/tags/v1.0.0",
		},
		{
			name: "from resolvedDependencies URI",
			pred: func() SourceProvenancePredicate {
				var p SourceProvenancePredicate
				p.BuildDefinition.ResolvedDependencies = []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				}{
					{URI: "git+https://github.com/org/repo@refs/heads/main"},
				}
				return p
			}(),
			expected: "refs/heads/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractSourceRef(tt.pred))
		})
	}
}

func TestExtractRefFromURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{"with refs/heads", "git+https://github.com/org/repo@refs/heads/main", "refs/heads/main"},
		{"with refs/tags", "git+https://github.com/org/repo@refs/tags/v1.0", "refs/tags/v1.0"},
		{"no ref", "git+https://github.com/org/repo", ""},
		{"@ but no refs/", "git+https://github.com/org/repo@main", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractRefFromURI(tt.uri))
		})
	}
}
