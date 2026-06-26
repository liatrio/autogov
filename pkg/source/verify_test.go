package source

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestMapToCanonicalSourceLevel(t *testing.T) {
	// evidence is mapped conservatively: a verified source-provenance signature
	// proves L1 (version control + provenance), nothing higher; unverified is L0.
	// The level is never inferred from the builder identity, and there is no
	// numbered L4 — honest L2/L3 require recorded + enforced branch controls.
	assert.Equal(t, "SLSA_SOURCE_LEVEL_0", MapToCanonicalSourceLevel(false))
	assert.Equal(t, "SLSA_SOURCE_LEVEL_1", MapToCanonicalSourceLevel(true))
}

func TestVerifySourceProvenance_VerifiedBundleReportsLevel1(t *testing.T) {
	// End-to-end honesty lock: a genuinely-verified public-good source bundle
	// reports the honest floor SLSA_SOURCE_LEVEL_1 — never a higher level
	// inferred from the builder identity. The fixture verifies offline against
	// the embedded public-good trusted root (see
	// TestSelectTrustedRootPublicGoodVerifies); empty VerifyOptions skip the
	// repo/commit/identity constraints so the signature alone drives the result.
	result, err := VerifySourceProvenance(filepath.Join("testdata", "bundle-public-good.jsonl"), VerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Verified, "public-good source bundle should verify: %s", result.ErrorMsg)
	assert.Equal(t, "SLSA_SOURCE_LEVEL_1", result.SLSASourceLevel)
}

func TestVerifySourceProvenance_UnverifiedReportsLevel0(t *testing.T) {
	// The honest floor on a failed verification: pointing the verifier at the
	// real bundle with a non-matching expected commit yields Verified==false and
	// the level present as SLSA_SOURCE_LEVEL_0 (not empty) so callers can
	// distinguish an honest L0 from missing data.
	result, err := VerifySourceProvenance(
		filepath.Join("testdata", "bundle-public-good.jsonl"),
		VerifyOptions{Commit: "0000000000000000000000000000000000000000"},
	)
	require.NoError(t, err)
	assert.False(t, result.Verified)
	assert.Equal(t, "SLSA_SOURCE_LEVEL_0", result.SLSASourceLevel)
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
