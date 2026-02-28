package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConventionalCommit(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		message string
		want    *ParsedCommit
	}{
		{
			name:    "basic feat",
			hash:    "abc123",
			message: "feat: add login",
			want:    &ParsedCommit{Hash: "abc123", Type: "feat", Subject: "add login", Raw: "feat: add login"},
		},
		{
			name:    "fix with scope",
			hash:    "def456",
			message: "fix(auth): validate token",
			want:    &ParsedCommit{Hash: "def456", Type: "fix", Scope: "auth", Subject: "validate token", Raw: "fix(auth): validate token"},
		},
		{
			name:    "breaking change with bang",
			hash:    "ghi789",
			message: "feat!: redesign API",
			want:    &ParsedCommit{Hash: "ghi789", Type: "feat", Subject: "redesign API", Breaking: true, Raw: "feat!: redesign API"},
		},
		{
			name:    "breaking change with scope and bang",
			hash:    "jkl012",
			message: "feat(api)!: remove endpoint",
			want:    &ParsedCommit{Hash: "jkl012", Type: "feat", Scope: "api", Subject: "remove endpoint", Breaking: true, Raw: "feat(api)!: remove endpoint"},
		},
		{
			name:    "breaking change in body",
			hash:    "mno345",
			message: "feat: update\n\nBREAKING CHANGE: removed field",
			want:    &ParsedCommit{Hash: "mno345", Type: "feat", Subject: "update", Body: "BREAKING CHANGE: removed field", Breaking: true, Raw: "feat: update\n\nBREAKING CHANGE: removed field"},
		},
		{
			name:    "non-conventional returns nil",
			hash:    "pqr678",
			message: "Update README",
			want:    nil,
		},
		{
			name:    "type is lowercased",
			hash:    "stu901",
			message: "FEAT: uppercase type",
			want:    &ParsedCommit{Hash: "stu901", Type: "feat", Subject: "uppercase type", Raw: "FEAT: uppercase type"},
		},
		{
			name:    "multiline with body",
			hash:    "vwx234",
			message: "fix: handle nil\n\nAdded nil check to prevent panic.",
			want:    &ParsedCommit{Hash: "vwx234", Type: "fix", Subject: "handle nil", Body: "Added nil check to prevent panic.", Raw: "fix: handle nil\n\nAdded nil check to prevent panic."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseConventionalCommit(tt.hash, tt.message)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want.Hash, got.Hash)
			assert.Equal(t, tt.want.Type, got.Type)
			assert.Equal(t, tt.want.Scope, got.Scope)
			assert.Equal(t, tt.want.Subject, got.Subject)
			assert.Equal(t, tt.want.Breaking, got.Breaking)
			assert.Equal(t, tt.want.Body, got.Body)
		})
	}
}

func TestGetCommitTypeInfo(t *testing.T) {
	tests := []struct {
		commitType string
		wantName   string
		wantBump   BumpType
	}{
		{"feat", "Features", BumpMinor},
		{"fix", "Bug Fixes", BumpPatch},
		{"docs", "Documentation", BumpNone},
		{"perf", "Performance", BumpPatch},
		{"refactor", "Refactor", BumpNone},
		{"test", "Testing", BumpNone},
		{"build", "Build", BumpNone},
		{"ci", "CI", BumpNone},
		{"chore", "Chores", BumpNone},
		{"style", "Style", BumpNone},
		{"revert", "Reverts", BumpPatch},
		{"unknown", "Other", BumpNone},
	}

	for _, tt := range tests {
		t.Run(tt.commitType, func(t *testing.T) {
			info := GetCommitTypeInfo(tt.commitType)
			assert.Equal(t, tt.wantName, info.ChangelogName)
			assert.Equal(t, tt.wantBump, info.BumpType)
		})
	}
}

func TestFilterReleasableCommits(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "feat", Subject: "new feature"},
		{Type: "fix", Subject: "bug fix"},
		{Type: "docs", Subject: "update readme"},
		{Type: "chore", Subject: "update deps"},
		{Type: "perf", Subject: "optimize"},
		{Type: "test", Subject: "add tests"},
		{Type: "docs", Subject: "breaking docs", Breaking: true},
	}

	releasable := FilterReleasableCommits(commits)

	assert.Len(t, releasable, 4) // feat, fix, perf, breaking docs

	types := make(map[string]int)
	for _, c := range releasable {
		types[c.Type]++
	}
	assert.Equal(t, 1, types["feat"])
	assert.Equal(t, 1, types["fix"])
	assert.Equal(t, 1, types["perf"])
	assert.Equal(t, 1, types["docs"]) // only the breaking one
}

func TestExtractBreakingChanges(t *testing.T) {
	t.Run("basic breaking change", func(t *testing.T) {
		commits := []ParsedCommit{
			{Type: "feat", Subject: "remove field", Breaking: true},
		}
		changes := ExtractBreakingChanges(commits)
		assert.Equal(t, []string{"remove field"}, changes)
	})

	t.Run("breaking with scope", func(t *testing.T) {
		commits := []ParsedCommit{
			{Type: "feat", Scope: "api", Subject: "remove endpoint", Breaking: true},
		}
		changes := ExtractBreakingChanges(commits)
		assert.Equal(t, []string{"api: remove endpoint"}, changes)
	})

	t.Run("breaking with body detail", func(t *testing.T) {
		commits := []ParsedCommit{
			{Type: "feat", Subject: "change", Breaking: true, Body: "BREAKING CHANGE: detailed description"},
		}
		changes := ExtractBreakingChanges(commits)
		assert.Contains(t, changes, "change")
		assert.Contains(t, changes, "detailed description")
	})

	t.Run("no breaking changes", func(t *testing.T) {
		commits := []ParsedCommit{
			{Type: "feat", Subject: "normal feature"},
		}
		changes := ExtractBreakingChanges(commits)
		assert.Empty(t, changes)
	})
}

func TestGroupCommitsByType(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "feat", Subject: "feature 1"},
		{Type: "feat", Subject: "feature 2"},
		{Type: "fix", Subject: "fix 1"},
		{Type: "docs", Subject: "doc 1"},
	}

	groups := GroupCommitsByType(commits)

	assert.Len(t, groups["feat"], 2)
	assert.Len(t, groups["fix"], 1)
	assert.Len(t, groups["docs"], 1)
	assert.Empty(t, groups["chore"])
}
