package vsa

import (
	"testing"

	"github.com/liatrio/autogov/pkg/attestations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSourceVSA(t *testing.T) {
	opts := SourceVSAOptions{
		RepoURI:     "https://github.com/org/repo",
		Commit:      "ABCDEF1234567890abcdef1234567890abcdef12",
		SourceLevel: "SLSA_SOURCE_LEVEL_1",
		Passed:      true,
		PolicyURI:   "https://example.com/policy",
		AdditionalVerifiers: map[string]string{
			"autogov": "v0.30.0",
		},
	}

	v, err := GenerateSourceVSA(opts)
	require.NoError(t, err)

	// standards-shaped statement.
	assert.Equal(t, "https://in-toto.io/Statement/v1", v.Type)
	assert.Equal(t, attestations.PredicateTypeVSA, v.PredicateType)
	assert.Equal(t, "https://slsa.dev/verification_summary/v1", v.PredicateType)

	// subject is the revision: repo URI plus lowercased gitCommit digest.
	require.Len(t, v.Subject, 1)
	assert.Equal(t, "https://github.com/org/repo", v.Subject[0].URI)
	assert.Equal(t, "abcdef1234567890abcdef1234567890abcdef12", v.Subject[0].Digest["gitCommit"])

	// resourceUri is the repository.
	assert.Equal(t, "https://github.com/org/repo", v.Predicate.ResourceURI)

	// verifiedLevels carries only the numbered level here.
	assert.Equal(t, []string{"SLSA_SOURCE_LEVEL_1"}, v.Predicate.VerifiedLevels)
	assert.Equal(t, "PASSED", v.Predicate.VerificationResult)
	assert.Equal(t, "v0.30.0", v.Predicate.Verifier.Version["autogov"])
}

func TestGenerateSourceVSAWithControlledBuilderAnnotation(t *testing.T) {
	opts := SourceVSAOptions{
		RepoURI:          "https://github.com/org/repo",
		Commit:           "abcdef1234567890abcdef1234567890abcdef12",
		SourceLevel:      "SLSA_SOURCE_LEVEL_1",
		AdditionalLevels: []string{"ORG_SOURCE_CONTROLLED_BUILDER"},
		Passed:           true,
		PolicyURI:        "https://example.com/policy",
	}

	v, err := GenerateSourceVSA(opts)
	require.NoError(t, err)

	// the controlled-builder annotation rides alongside the numbered level, not as a higher level.
	assert.Equal(t, []string{"SLSA_SOURCE_LEVEL_1", "ORG_SOURCE_CONTROLLED_BUILDER"}, v.Predicate.VerifiedLevels)
}

func TestGenerateSourceVSARejectsNumberedAdditionalLevel(t *testing.T) {
	// a numbered SLSA track token in AdditionalLevels would inflate the asserted
	// level when a consumer reads verifiedLevels, so the API must reject it.
	opts := SourceVSAOptions{
		RepoURI:          "https://github.com/org/repo",
		Commit:           "abcdef1234567890abcdef1234567890abcdef12",
		SourceLevel:      "SLSA_SOURCE_LEVEL_1",
		AdditionalLevels: []string{"SLSA_SOURCE_LEVEL_3"},
		Passed:           true,
		PolicyURI:        "https://example.com/policy",
	}

	_, err := GenerateSourceVSA(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-numbered annotation")
}

func TestGenerateSourceVSADedupesAdditionalLevels(t *testing.T) {
	opts := SourceVSAOptions{
		RepoURI:          "https://github.com/org/repo",
		Commit:           "abcdef1234567890abcdef1234567890abcdef12",
		SourceLevel:      "SLSA_SOURCE_LEVEL_1",
		AdditionalLevels: []string{"ORG_SOURCE_CONTROLLED_BUILDER", "ORG_SOURCE_CONTROLLED_BUILDER"},
		Passed:           true,
		PolicyURI:        "https://example.com/policy",
	}

	v, err := GenerateSourceVSA(opts)
	require.NoError(t, err)
	assert.Equal(t, []string{"SLSA_SOURCE_LEVEL_1", "ORG_SOURCE_CONTROLLED_BUILDER"}, v.Predicate.VerifiedLevels)
}

func TestGenerateSourceVSAFailed(t *testing.T) {
	opts := SourceVSAOptions{
		RepoURI:     "https://github.com/org/repo",
		Commit:      "abcdef1234567890abcdef1234567890abcdef12",
		SourceLevel: "SLSA_SOURCE_LEVEL_0",
		Passed:      false,
		PolicyURI:   "https://example.com/policy",
	}

	v, err := GenerateSourceVSA(opts)
	require.NoError(t, err)
	assert.Equal(t, "FAILED", v.Predicate.VerificationResult)
	assert.Equal(t, []string{"SLSA_SOURCE_LEVEL_0"}, v.Predicate.VerifiedLevels)
}

func TestGenerateSourceVSAValidation(t *testing.T) {
	tests := []struct {
		name string
		opts SourceVSAOptions
	}{
		{
			name: "missing repo",
			opts: SourceVSAOptions{Commit: "abc1234", SourceLevel: "SLSA_SOURCE_LEVEL_1"},
		},
		{
			name: "missing commit",
			opts: SourceVSAOptions{RepoURI: "https://github.com/org/repo", SourceLevel: "SLSA_SOURCE_LEVEL_1"},
		},
		{
			name: "invalid level",
			opts: SourceVSAOptions{RepoURI: "https://github.com/org/repo", Commit: "abc1234", SourceLevel: "SLSA_SOURCE_LEVEL_9"},
		},
		{
			name: "build level rejected for source VSA",
			opts: SourceVSAOptions{RepoURI: "https://github.com/org/repo", Commit: "abc1234", SourceLevel: "SLSA_BUILD_LEVEL_3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateSourceVSA(tt.opts)
			assert.Error(t, err)
		})
	}
}

func TestExtractSLSATrackLevelsSource(t *testing.T) {
	levels, err := ExtractSLSATrackLevels([]string{"SLSA_SOURCE_LEVEL_2", "SLSA_BUILD_LEVEL_3"})
	require.NoError(t, err)
	assert.Equal(t, 2, levels.SourceTrack)
	assert.Equal(t, 3, levels.BuildTrack)
}
