package release

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestReleasePlanToJSON(t *testing.T) {
	plan := &ReleasePlan{
		GeneratedAt:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Repository:     "test/repo",
		CurrentVersion: "v1.0.0",
		NextVersion:    "v1.1.0",
		BumpType:       "minor",
		Commits: []ParsedCommit{
			{
				Hash:    "abc1234567890",
				Type:    "feat",
				Scope:   "api",
				Subject: "add new endpoint",
			},
		},
		ReleaseNeeded: true,
	}

	data, err := plan.ToJSON()
	require.NoError(t, err)

	// verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "test/repo", parsed["repository"])
	assert.Equal(t, "v1.0.0", parsed["current_version"])
	assert.Equal(t, "v1.1.0", parsed["next_version"])
	assert.Equal(t, "minor", parsed["bump_type"])
	assert.Equal(t, true, parsed["release_needed"])
}

func TestReleasePlanToYAML(t *testing.T) {
	plan := &ReleasePlan{
		GeneratedAt:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Repository:     "test/repo",
		CurrentVersion: "v1.0.0",
		NextVersion:    "v1.1.0",
		BumpType:       "minor",
		ReleaseNeeded:  true,
	}

	data, err := plan.ToYAML()
	require.NoError(t, err)

	// verify it's valid YAML
	var parsed map[string]interface{}
	err = yaml.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "test/repo", parsed["repository"])
	assert.Equal(t, "v1.0.0", parsed["current_version"])
}

func TestReleasePlanToTextNoRelease(t *testing.T) {
	plan := &ReleasePlan{
		ReleaseNeeded: false,
		Reason:        "no releasable commits found",
	}

	text := plan.ToText()
	assert.Contains(t, text, "No release needed")
	assert.Contains(t, text, "no releasable commits found")
}

func TestReleasePlanToTextWithRelease(t *testing.T) {
	plan := &ReleasePlan{
		GeneratedAt:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Repository:     "test/repo",
		CurrentVersion: "v1.0.0",
		NextVersion:    "v2.0.0",
		BumpType:       "major",
		Commits: []ParsedCommit{
			{
				Hash:     "abc1234567890",
				Type:     "feat",
				Scope:    "api",
				Subject:  "add new endpoint",
				Breaking: true,
			},
			{
				Hash:    "def1234567890",
				Type:    "fix",
				Subject: "fix bug",
			},
		},
		BreakingChanges: []string{"api: add new endpoint"},
		ReleaseNeeded:   true,
	}

	text := plan.ToText()
	assert.Contains(t, text, "Release Plan")
	assert.Contains(t, text, "test/repo")
	assert.Contains(t, text, "v1.0.0")
	assert.Contains(t, text, "v2.0.0")
	assert.Contains(t, text, "major")
	assert.Contains(t, text, "Breaking Changes")
	assert.Contains(t, text, "abc1234")
	assert.Contains(t, text, "feat(api)!")
	assert.Contains(t, text, "def1234")
}

func TestDefaultPlanOptions(t *testing.T) {
	opts := DefaultPlanOptions()

	assert.Equal(t, "", opts.FromRef)
	assert.Equal(t, "HEAD", opts.ToRef)
	assert.False(t, opts.FirstParent)
	assert.Equal(t, ".", opts.RepoPath)
	assert.Equal(t, "text", opts.OutputFormat)
}

func TestParsedCommitFields(t *testing.T) {
	commit := ParsedCommit{
		Hash:     "abc123",
		Type:     "feat",
		Scope:    "cli",
		Subject:  "add new command",
		Body:     "detailed description",
		Breaking: false,
		Raw:      "feat(cli): add new command\n\ndetailed description",
	}

	assert.Equal(t, "abc123", commit.Hash)
	assert.Equal(t, "feat", commit.Type)
	assert.Equal(t, "cli", commit.Scope)
	assert.Equal(t, "add new command", commit.Subject)
	assert.Equal(t, "detailed description", commit.Body)
	assert.False(t, commit.Breaking)
}

func TestFileMutationFields(t *testing.T) {
	mutation := FileMutation{
		Path:     "version.txt",
		Type:     "regex",
		Field:    "version",
		OldValue: "1.0.0",
		NewValue: "1.1.0",
	}

	assert.Equal(t, "version.txt", mutation.Path)
	assert.Equal(t, "regex", mutation.Type)
	assert.Equal(t, "1.0.0", mutation.OldValue)
	assert.Equal(t, "1.1.0", mutation.NewValue)
}
