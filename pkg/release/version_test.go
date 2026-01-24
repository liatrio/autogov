package release

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      *Version
		wantError bool
	}{
		{
			name:  "simple version with v prefix",
			input: "v1.2.3",
			want:  &Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "simple version without v prefix",
			input: "1.2.3",
			want:  &Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "version with prerelease",
			input: "v1.2.3-rc.1",
			want:  &Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1"},
		},
		{
			name:  "version with metadata",
			input: "v1.2.3+build.123",
			want:  &Version{Major: 1, Minor: 2, Patch: 3, Metadata: "build.123"},
		},
		{
			name:  "version with prerelease and metadata",
			input: "v1.2.3-beta.1+build.456",
			want:  &Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "beta.1", Metadata: "build.456"},
		},
		{
			name:  "zero version",
			input: "v0.0.0",
			want:  &Version{Major: 0, Minor: 0, Patch: 0},
		},
		{
			name:  "large version numbers",
			input: "v100.200.300",
			want:  &Version{Major: 100, Minor: 200, Patch: 300},
		},
		{
			name:      "invalid format - missing patch",
			input:     "v1.2",
			wantError: true,
		},
		{
			name:      "invalid format - non-numeric",
			input:     "v1.two.3",
			wantError: true,
		},
		{
			name:      "invalid format - empty",
			input:     "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Major, got.Major)
			assert.Equal(t, tt.want.Minor, got.Minor)
			assert.Equal(t, tt.want.Patch, got.Patch)
			assert.Equal(t, tt.want.Prerelease, got.Prerelease)
			assert.Equal(t, tt.want.Metadata, got.Metadata)
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version *Version
		want    string
	}{
		{
			name:    "simple version",
			version: &Version{Major: 1, Minor: 2, Patch: 3},
			want:    "v1.2.3",
		},
		{
			name:    "version with prerelease",
			version: &Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1"},
			want:    "v1.2.3-rc.1",
		},
		{
			name:    "version with metadata",
			version: &Version{Major: 1, Minor: 2, Patch: 3, Metadata: "build.123"},
			want:    "v1.2.3+build.123",
		},
		{
			name:    "version with both",
			version: &Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "beta.1", Metadata: "build.456"},
			want:    "v1.2.3-beta.1+build.456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.version.String())
		})
	}
}

func TestVersionStringWithoutV(t *testing.T) {
	v := &Version{Major: 1, Minor: 2, Patch: 3}
	assert.Equal(t, "1.2.3", v.StringWithoutV())
}

func TestVersionBump(t *testing.T) {
	tests := []struct {
		name    string
		version *Version
		bump    BumpType
		want    *Version
	}{
		{
			name:    "major bump resets minor and patch",
			version: &Version{Major: 1, Minor: 2, Patch: 3},
			bump:    BumpMajor,
			want:    &Version{Major: 2, Minor: 0, Patch: 0},
		},
		{
			name:    "minor bump resets patch",
			version: &Version{Major: 1, Minor: 2, Patch: 3},
			bump:    BumpMinor,
			want:    &Version{Major: 1, Minor: 3, Patch: 0},
		},
		{
			name:    "patch bump",
			version: &Version{Major: 1, Minor: 2, Patch: 3},
			bump:    BumpPatch,
			want:    &Version{Major: 1, Minor: 2, Patch: 4},
		},
		{
			name:    "no bump",
			version: &Version{Major: 1, Minor: 2, Patch: 3},
			bump:    BumpNone,
			want:    &Version{Major: 1, Minor: 2, Patch: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.version.Bump(tt.bump)
			assert.Equal(t, tt.want.Major, got.Major)
			assert.Equal(t, tt.want.Minor, got.Minor)
			assert.Equal(t, tt.want.Patch, got.Patch)
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		v1   *Version
		v2   *Version
		want int
	}{
		{
			name: "equal versions",
			v1:   &Version{Major: 1, Minor: 2, Patch: 3},
			v2:   &Version{Major: 1, Minor: 2, Patch: 3},
			want: 0,
		},
		{
			name: "v1 major less than v2",
			v1:   &Version{Major: 1, Minor: 2, Patch: 3},
			v2:   &Version{Major: 2, Minor: 0, Patch: 0},
			want: -1,
		},
		{
			name: "v1 major greater than v2",
			v1:   &Version{Major: 2, Minor: 0, Patch: 0},
			v2:   &Version{Major: 1, Minor: 2, Patch: 3},
			want: 1,
		},
		{
			name: "v1 minor less than v2",
			v1:   &Version{Major: 1, Minor: 1, Patch: 3},
			v2:   &Version{Major: 1, Minor: 2, Patch: 0},
			want: -1,
		},
		{
			name: "v1 patch less than v2",
			v1:   &Version{Major: 1, Minor: 2, Patch: 2},
			v2:   &Version{Major: 1, Minor: 2, Patch: 3},
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v1.Compare(tt.v2))
		})
	}
}

func TestVersionLessThan(t *testing.T) {
	v1 := &Version{Major: 1, Minor: 0, Patch: 0}
	v2 := &Version{Major: 2, Minor: 0, Patch: 0}

	assert.True(t, v1.LessThan(v2))
	assert.False(t, v2.LessThan(v1))
	assert.False(t, v1.LessThan(v1))
}

func TestZeroVersion(t *testing.T) {
	v := ZeroVersion()
	assert.Equal(t, 0, v.Major)
	assert.Equal(t, 0, v.Minor)
	assert.Equal(t, 0, v.Patch)
	assert.Equal(t, "v0.0.0", v.String())
}

func TestComputeNextVersion(t *testing.T) {
	tests := []struct {
		name         string
		current      *Version
		commits      []ParsedCommit
		wantVersion  *Version
		wantBumpType BumpType
	}{
		{
			name:         "no commits - no bump",
			current:      &Version{Major: 1, Minor: 0, Patch: 0},
			commits:      []ParsedCommit{},
			wantVersion:  &Version{Major: 1, Minor: 0, Patch: 0},
			wantBumpType: BumpNone,
		},
		{
			name:    "breaking change - major bump",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "feat", Breaking: true},
			},
			wantVersion:  &Version{Major: 2, Minor: 0, Patch: 0},
			wantBumpType: BumpMajor,
		},
		{
			name:    "feat - minor bump",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "feat"},
			},
			wantVersion:  &Version{Major: 1, Minor: 1, Patch: 0},
			wantBumpType: BumpMinor,
		},
		{
			name:    "fix - patch bump",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "fix"},
			},
			wantVersion:  &Version{Major: 1, Minor: 0, Patch: 1},
			wantBumpType: BumpPatch,
		},
		{
			name:    "perf - patch bump",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "perf"},
			},
			wantVersion:  &Version{Major: 1, Minor: 0, Patch: 1},
			wantBumpType: BumpPatch,
		},
		{
			name:    "docs only - no bump",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "docs"},
			},
			wantVersion:  &Version{Major: 1, Minor: 0, Patch: 0},
			wantBumpType: BumpNone,
		},
		{
			name:    "mixed commits - highest wins",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "fix"},
				{Type: "feat"},
				{Type: "docs"},
			},
			wantVersion:  &Version{Major: 1, Minor: 1, Patch: 0},
			wantBumpType: BumpMinor,
		},
		{
			name:    "breaking takes precedence",
			current: &Version{Major: 1, Minor: 0, Patch: 0},
			commits: []ParsedCommit{
				{Type: "feat"},
				{Type: "fix", Breaking: true},
			},
			wantVersion:  &Version{Major: 2, Minor: 0, Patch: 0},
			wantBumpType: BumpMajor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVersion, gotBump := ComputeNextVersion(tt.current, tt.commits)
			assert.Equal(t, tt.wantVersion.Major, gotVersion.Major)
			assert.Equal(t, tt.wantVersion.Minor, gotVersion.Minor)
			assert.Equal(t, tt.wantVersion.Patch, gotVersion.Patch)
			assert.Equal(t, tt.wantBumpType, gotBump)
		})
	}
}
