package release

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConventionalCommit(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		message  string
		want     *ParsedCommit
		wantType string
	}{
		{
			name:    "simple feat",
			hash:    "abc123",
			message: "feat: add new feature",
			want: &ParsedCommit{
				Hash:     "abc123",
				Type:     "feat",
				Subject:  "add new feature",
				Breaking: false,
				Raw:      "feat: add new feature",
			},
		},
		{
			name:    "feat with scope",
			hash:    "def456",
			message: "feat(api): add new endpoint",
			want: &ParsedCommit{
				Hash:     "def456",
				Type:     "feat",
				Scope:    "api",
				Subject:  "add new endpoint",
				Breaking: false,
				Raw:      "feat(api): add new endpoint",
			},
		},
		{
			name:    "fix with scope",
			hash:    "ghi789",
			message: "fix(auth): handle edge case",
			want: &ParsedCommit{
				Hash:     "ghi789",
				Type:     "fix",
				Scope:    "auth",
				Subject:  "handle edge case",
				Breaking: false,
				Raw:      "fix(auth): handle edge case",
			},
		},
		{
			name:    "breaking change with bang",
			hash:    "jkl012",
			message: "feat(api)!: change response format",
			want: &ParsedCommit{
				Hash:     "jkl012",
				Type:     "feat",
				Scope:    "api",
				Subject:  "change response format",
				Breaking: true,
				Raw:      "feat(api)!: change response format",
			},
		},
		{
			name:    "breaking change without scope",
			hash:    "mno345",
			message: "feat!: major change",
			want: &ParsedCommit{
				Hash:     "mno345",
				Type:     "feat",
				Subject:  "major change",
				Breaking: true,
				Raw:      "feat!: major change",
			},
		},
		{
			name:    "breaking change in body",
			hash:    "pqr678",
			message: "feat: new api\n\nBREAKING CHANGE: old api removed",
			want: &ParsedCommit{
				Hash:     "pqr678",
				Type:     "feat",
				Subject:  "new api",
				Body:     "BREAKING CHANGE: old api removed",
				Breaking: true,
				Raw:      "feat: new api\n\nBREAKING CHANGE: old api removed",
			},
		},
		{
			name:    "commit with body",
			hash:    "stu901",
			message: "docs: update readme\n\nAdded installation instructions",
			want: &ParsedCommit{
				Hash:     "stu901",
				Type:     "docs",
				Subject:  "update readme",
				Body:     "Added installation instructions",
				Breaking: false,
				Raw:      "docs: update readme\n\nAdded installation instructions",
			},
		},
		{
			name:    "non-conventional commit",
			hash:    "vwx234",
			message: "updated some stuff",
			want:    nil,
		},
		{
			name:    "uppercase type normalized to lowercase",
			hash:    "yza567",
			message: "FEAT: uppercase type",
			want: &ParsedCommit{
				Hash:     "yza567",
				Type:     "feat",
				Subject:  "uppercase type",
				Breaking: false,
				Raw:      "FEAT: uppercase type",
			},
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
		name          string
		commitType    string
		wantBumpType  BumpType
		wantChangelog string
	}{
		{"feat", "feat", BumpMinor, "Features"},
		{"fix", "fix", BumpPatch, "Bug Fixes"},
		{"docs", "docs", BumpNone, "Documentation"},
		{"perf", "perf", BumpPatch, "Performance"},
		{"unknown", "unknown", BumpNone, "Other"},
		{"FEAT uppercase", "FEAT", BumpMinor, "Features"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := GetCommitTypeInfo(tt.commitType)
			assert.Equal(t, tt.wantBumpType, info.BumpType)
			assert.Equal(t, tt.wantChangelog, info.ChangelogName)
		})
	}
}

func TestFilterReleasableCommits(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "feat", Subject: "new feature"},
		{Type: "fix", Subject: "bug fix"},
		{Type: "docs", Subject: "update docs"},
		{Type: "chore", Subject: "update deps"},
		{Type: "perf", Subject: "optimize"},
		{Type: "docs", Subject: "more docs", Breaking: true},
	}

	releasable := FilterReleasableCommits(commits)

	assert.Len(t, releasable, 4) // feat, fix, perf, and the breaking docs commit

	types := make([]string, len(releasable))
	for i, c := range releasable {
		types[i] = c.Type
	}
	assert.Contains(t, types, "feat")
	assert.Contains(t, types, "fix")
	assert.Contains(t, types, "perf")
	assert.Contains(t, types, "docs") // the breaking one
}

func TestExtractBreakingChanges(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "feat", Subject: "normal feature", Breaking: false},
		{Type: "feat", Scope: "api", Subject: "breaking change", Breaking: true},
		{Type: "fix", Subject: "breaking fix", Breaking: true, Body: "BREAKING CHANGE: detailed description"},
	}

	breaking := ExtractBreakingChanges(commits)

	assert.Len(t, breaking, 3) // api: breaking change, breaking fix, detailed description
	assert.Contains(t, breaking, "api: breaking change")
	assert.Contains(t, breaking, "breaking fix")
	assert.Contains(t, breaking, "detailed description")
}

func TestGroupCommitsByType(t *testing.T) {
	commits := []ParsedCommit{
		{Type: "feat", Subject: "feature 1"},
		{Type: "feat", Subject: "feature 2"},
		{Type: "fix", Subject: "bug fix"},
		{Type: "docs", Subject: "update docs"},
	}

	groups := GroupCommitsByType(commits)

	assert.Len(t, groups["feat"], 2)
	assert.Len(t, groups["fix"], 1)
	assert.Len(t, groups["docs"], 1)
}
