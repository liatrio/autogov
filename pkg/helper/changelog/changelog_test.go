package changelog

import (
	"regexp"
	"testing"

	"github.com/liatrio/autogov/pkg/helper/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emojiPattern matches common Unicode emoji ranges used in conventional commit tooling.
var emojiPattern = regexp.MustCompile(`[\x{1F300}-\x{1F9FF}\x{2600}-\x{27BF}]`)

func TestGenerateChangelog(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Scope: "api", Subject: "add new endpoint"},
		{Hash: "def1234567890", Type: "fix", Subject: "fix bug in auth"},
		{Hash: "ghi1234567890", Type: "docs", Subject: "update readme"},
	}

	opts := &Options{
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
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Scope: "api", Subject: "breaking change", Breaking: true},
		{Hash: "def1234567890", Type: "fix", Subject: "normal fix"},
	}

	opts := &Options{Version: "v2.0.0"}
	changelog, err := GenerateChangelog(commits, opts)
	require.NoError(t, err)

	assert.Contains(t, changelog, "Breaking Changes")
	assert.Contains(t, changelog, "api: breaking change")
}

func TestGenerateChangelogWithoutNonReleasable(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
		{Hash: "def1234567890", Type: "docs", Subject: "update docs"},
		{Hash: "ghi1234567890", Type: "chore", Subject: "update deps"},
	}

	opts := &Options{
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
	commits := []version.ParsedCommit{
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
	commits := []version.ParsedCommit{
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

func TestGenerateChangelogNilOpts(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
	}

	changelog, err := GenerateChangelog(commits, nil)
	require.NoError(t, err)
	assert.Contains(t, changelog, "new feature")
}

func TestGenerateChangelogCustomTemplate(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "new feature"},
	}

	opts := &Options{
		Version:  "v1.0.0",
		Template: "Release {{.Version}}: {{len .Groups}} groups",
	}

	changelog, err := GenerateChangelog(commits, opts)
	require.NoError(t, err)
	assert.Equal(t, "Release v1.0.0: 1 groups", changelog)
}

func TestGenerateChangelogJSON(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Scope: "api", Subject: "add endpoint", Breaking: true},
		{Hash: "def1234567890", Type: "fix", Subject: "fix crash"},
		{Hash: "ghi1234567890", Type: "docs", Subject: "update readme"},
	}

	result := GenerateChangelogJSON(commits, &Options{
		Version:    "v2.0.0",
		IncludeAll: true,
	})

	assert.Equal(t, "v2.0.0", result.Version)
	assert.NotEmpty(t, result.BreakingChanges)
	assert.Contains(t, result.BreakingChanges, "api: add endpoint")

	// verify groups
	assert.NotEmpty(t, result.Groups)
	var groupTypes []string
	for _, g := range result.Groups {
		groupTypes = append(groupTypes, g.Type)
	}
	assert.Contains(t, groupTypes, "feat")
	assert.Contains(t, groupTypes, "fix")
	assert.Contains(t, groupTypes, "docs")

	// verify stats
	assert.Equal(t, 3, result.Stats["total"])
	assert.Equal(t, 1, result.Stats["feat"])
	assert.Equal(t, 1, result.Stats["fix"])
	assert.Equal(t, 1, result.Stats["docs"])
	assert.Equal(t, 1, result.Stats["breaking"])
}

func TestGenerateChangelogJSONWithoutIncludeAll(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "feature"},
		{Hash: "def1234567890", Type: "docs", Subject: "docs change"},
		{Hash: "ghi1234567890", Type: "chore", Subject: "chore task"},
	}

	result := GenerateChangelogJSON(commits, &Options{
		Version:    "v1.0.0",
		IncludeAll: false,
	})

	var groupTypes []string
	for _, g := range result.Groups {
		groupTypes = append(groupTypes, g.Type)
	}
	assert.Contains(t, groupTypes, "feat")
	assert.NotContains(t, groupTypes, "docs")
	assert.NotContains(t, groupTypes, "chore")
}

func TestGenerateChangelogJSONNilOpts(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "feature"},
	}

	result := GenerateChangelogJSON(commits, nil)
	assert.NotNil(t, result)
	assert.Empty(t, result.Version)
	assert.NotEmpty(t, result.Groups)
}

func TestGenerateChangelogJSONCommitFields(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Scope: "auth", Subject: "add login", Breaking: true},
	}

	result := GenerateChangelogJSON(commits, &Options{Version: "v1.0.0"})

	require.Len(t, result.Groups, 1)
	require.Len(t, result.Groups[0].Commits, 1)

	c := result.Groups[0].Commits[0]
	assert.Equal(t, "abc1234567890", c.Hash)
	assert.Equal(t, "feat", c.Type)
	assert.Equal(t, "auth", c.Scope)
	assert.Equal(t, "add login", c.Subject)
	assert.True(t, c.Breaking)
}

func TestGenerateChangelogJSONGroupNames(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "a", Type: "feat", Subject: "f"},
		{Hash: "b", Type: "fix", Subject: "x"},
	}

	result := GenerateChangelogJSON(commits, &Options{IncludeAll: true})

	nameMap := make(map[string]string)
	for _, g := range result.Groups {
		nameMap[g.Type] = g.Name
	}

	assert.Equal(t, "Features", nameMap["feat"])
	assert.Equal(t, "Bug Fixes", nameMap["fix"])
}

// TestChangelogNoEmojis verifies the default template contains no Unicode emoji codepoints.
func TestChangelogNoEmojis(t *testing.T) {
	commits := []version.ParsedCommit{
		{Hash: "abc1234567890", Type: "feat", Subject: "add feature", Breaking: true},
		{Hash: "def1234567890", Type: "fix", Subject: "fix bug"},
		{Hash: "ghi1234567890", Type: "perf", Subject: "improve speed"},
		{Hash: "jkl1234567890", Type: "docs", Subject: "update readme"},
		{Hash: "mno1234567890", Type: "chore", Subject: "update deps"},
	}

	changelog, err := GenerateChangelog(commits, &Options{Version: "v2.0.0", IncludeAll: true})
	require.NoError(t, err)

	// the default template must not contain any emoji
	match := emojiPattern.FindString(changelog)
	assert.Empty(t, match, "changelog must not contain Unicode emoji, found: %s", match)
	assert.Contains(t, changelog, "Breaking Changes")
}

func TestGenerateChangelogJSONEmptyCommits(t *testing.T) {
	result := GenerateChangelogJSON(nil, &Options{Version: "v1.0.0"})

	assert.Equal(t, "v1.0.0", result.Version)
	assert.Empty(t, result.Groups)
	assert.Empty(t, result.BreakingChanges)
	assert.Equal(t, 0, result.Stats["total"])
}
