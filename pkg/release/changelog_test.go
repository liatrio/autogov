package release

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateChangelog(t *testing.T) {
	commits := []ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Scope: "api", Subject: "add new endpoint"},
		{Hash: "def1234567890", Type: "fix", Subject: "fix bug in auth"},
		{Hash: "ghi1234567890", Type: "docs", Subject: "update readme"},
	}

	opts := &ChangelogOptions{
		Version:    "v1.1.0",
		IncludeAll: true,
	}

	changelog, err := GenerateChangelog(commits, opts)
	require.NoError(t, err)

	assert.Contains(t, changelog, "## v1.1.0")
	assert.Contains(t, changelog, "Features")
	assert.Contains(t, changelog, "add new endpoint")
	assert.Contains(t, changelog, "abc1234")
	assert.Contains(t, changelog, "Bug Fixes")
	assert.Contains(t, changelog, "fix bug in auth")
	assert.Contains(t, changelog, "Documentation")
}

func TestGenerateChangelogWithBreakingChanges(t *testing.T) {
	commits := []ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Scope: "api", Subject: "breaking change", Breaking: true},
		{Hash: "def1234567890", Type: "fix", Subject: "normal fix"},
	}

	opts := &ChangelogOptions{Version: "v2.0.0"}
	changelog, err := GenerateChangelog(commits, opts)
	require.NoError(t, err)

	assert.Contains(t, changelog, "Breaking Changes")
	assert.Contains(t, changelog, "api: breaking change")
}

func TestGenerateChangelogWithoutNonReleasable(t *testing.T) {
	commits := []ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
		{Hash: "def1234567890", Type: "docs", Subject: "update docs"},
		{Hash: "ghi1234567890", Type: "chore", Subject: "update deps"},
	}

	opts := &ChangelogOptions{
		Version:    "v1.1.0",
		IncludeAll: false,
	}

	changelog, err := GenerateChangelog(commits, opts)
	require.NoError(t, err)

	assert.Contains(t, changelog, "Features")
	assert.Contains(t, changelog, "new feature")
	// docs and chore should not be included when IncludeAll is false
	assert.NotContains(t, changelog, "Documentation")
	assert.NotContains(t, changelog, "Chores")
}

func TestGenerateChangelogPreview(t *testing.T) {
	commits := []ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
		{Hash: "def1234567890", Type: "fix", Subject: "bug fix"},
	}

	preview, err := GenerateChangelogPreview(commits, "v1.1.0")
	require.NoError(t, err)

	assert.Contains(t, preview, "v1.1.0")
	assert.Contains(t, preview, "new feature")
	assert.Contains(t, preview, "bug fix")
}

func TestGetCommitStats(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "feat", Breaking: true},
		{Type: "feat"},
		{Type: "fix"},
		{Type: "docs"},
	}

	stats := GetCommitStats(commits)

	assert.Equal(t, 4, stats["total"])
	assert.Equal(t, 2, stats["feat"])
	assert.Equal(t, 1, stats["fix"])
	assert.Equal(t, 1, stats["docs"])
	assert.Equal(t, 1, stats["breaking"])
}

func TestSortCommitsByType(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "docs", Subject: "docs commit"},
		{Type: "feat", Subject: "feat commit"},
		{Type: "fix", Subject: "fix commit"},
		{Type: "chore", Subject: "chore commit"},
	}

	sorted := SortCommitsByType(commits)

	// order should be: feat, fix, docs, chore
	assert.Equal(t, "feat", sorted[0].Type)
	assert.Equal(t, "fix", sorted[1].Type)
	assert.Equal(t, "docs", sorted[2].Type)
	assert.Equal(t, "chore", sorted[3].Type)
}

func TestGenerateChangelogNilOpts(t *testing.T) {
	commits := []ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
	}

	changelog, err := GenerateChangelog(commits, nil)
	require.NoError(t, err)
	assert.Contains(t, changelog, "new feature")
}

func TestGenerateChangelogCustomTemplate(t *testing.T) {
	commits := []ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
	}

	opts := &ChangelogOptions{
		Version:  "v1.0.0",
		Template: "Release {{.Version}}: {{len .Groups}} groups",
	}

	changelog, err := GenerateChangelog(commits, opts)
	require.NoError(t, err)
	assert.Equal(t, "Release v1.0.0: 1 groups", changelog)
}
