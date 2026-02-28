package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Version
		wantErr bool
	}{
		{
			name:  "basic version with v prefix",
			input: "v1.2.3",
			want:  &Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "basic version without v prefix",
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
			input: "v1.2.3-rc.1+build.123",
			want:  &Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1", Metadata: "build.123"},
		},
		{
			name:  "zero version",
			input: "v0.0.0",
			want:  &Version{Major: 0, Minor: 0, Patch: 0},
		},
		{
			name:    "invalid format missing patch",
			input:   "v1.2",
			wantErr: true,
		},
		{
			name:    "invalid format not a number",
			input:   "v1.2.abc",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if tt.wantErr {
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
		name string
		ver  Version
		want string
	}{
		{
			name: "basic version",
			ver:  Version{Major: 1, Minor: 2, Patch: 3},
			want: "v1.2.3",
		},
		{
			name: "with prerelease",
			ver:  Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			want: "v1.0.0-rc.1",
		},
		{
			name: "with metadata",
			ver:  Version{Major: 1, Minor: 0, Patch: 0, Metadata: "build.1"},
			want: "v1.0.0+build.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ver.String())
		})
	}
}

func TestVersionStringWithoutV(t *testing.T) {
	v := &Version{Major: 1, Minor: 2, Patch: 3}
	assert.Equal(t, "1.2.3", v.StringWithoutV())
}

func TestVersionBump(t *testing.T) {
	tests := []struct {
		name     string
		ver      Version
		bumpType BumpType
		want     string
	}{
		{
			name:     "major bump resets minor and patch",
			ver:      Version{Major: 1, Minor: 2, Patch: 3},
			bumpType: BumpMajor,
			want:     "v2.0.0",
		},
		{
			name:     "minor bump resets patch",
			ver:      Version{Major: 1, Minor: 2, Patch: 3},
			bumpType: BumpMinor,
			want:     "v1.3.0",
		},
		{
			name:     "patch bump",
			ver:      Version{Major: 1, Minor: 2, Patch: 3},
			bumpType: BumpPatch,
			want:     "v1.2.4",
		},
		{
			name:     "no bump returns same version",
			ver:      Version{Major: 1, Minor: 2, Patch: 3},
			bumpType: BumpNone,
			want:     "v1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ver.Bump(tt.bumpType)
			assert.Equal(t, tt.want, result.String())
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b Version
		want int
	}{
		{name: "equal", a: Version{1, 2, 3, "", ""}, b: Version{1, 2, 3, "", ""}, want: 0},
		{name: "major less", a: Version{1, 0, 0, "", ""}, b: Version{2, 0, 0, "", ""}, want: -1},
		{name: "major greater", a: Version{2, 0, 0, "", ""}, b: Version{1, 0, 0, "", ""}, want: 1},
		{name: "minor less", a: Version{1, 1, 0, "", ""}, b: Version{1, 2, 0, "", ""}, want: -1},
		{name: "minor greater", a: Version{1, 2, 0, "", ""}, b: Version{1, 1, 0, "", ""}, want: 1},
		{name: "patch less", a: Version{1, 1, 1, "", ""}, b: Version{1, 1, 2, "", ""}, want: -1},
		{name: "patch greater", a: Version{1, 1, 2, "", ""}, b: Version{1, 1, 1, "", ""}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.Compare(&tt.b))
		})
	}
}

func TestVersionLessThan(t *testing.T) {
	a := &Version{Major: 1, Minor: 0, Patch: 0}
	b := &Version{Major: 2, Minor: 0, Patch: 0}

	assert.True(t, a.LessThan(b))
	assert.False(t, b.LessThan(a))
	assert.False(t, a.LessThan(a))
}

func TestZeroVersion(t *testing.T) {
	v := ZeroVersion()
	assert.Equal(t, 0, v.Major)
	assert.Equal(t, 0, v.Minor)
	assert.Equal(t, 0, v.Patch)
	assert.Equal(t, "v0.0.0", v.String())
}

func TestComputeNextVersion(t *testing.T) {
	current := &Version{Major: 1, Minor: 0, Patch: 0}

	tests := []struct {
		name     string
		commits  []ParsedCommit
		wantVer  string
		wantBump BumpType
	}{
		{
			name:     "no commits",
			commits:  nil,
			wantVer:  "v1.0.0",
			wantBump: BumpNone,
		},
		{
			name:     "feat bumps minor",
			commits:  []ParsedCommit{{Type: "feat", Subject: "new feature"}},
			wantVer:  "v1.1.0",
			wantBump: BumpMinor,
		},
		{
			name:     "fix bumps patch",
			commits:  []ParsedCommit{{Type: "fix", Subject: "fix bug"}},
			wantVer:  "v1.0.1",
			wantBump: BumpPatch,
		},
		{
			name:     "perf bumps patch",
			commits:  []ParsedCommit{{Type: "perf", Subject: "faster"}},
			wantVer:  "v1.0.1",
			wantBump: BumpPatch,
		},
		{
			name:     "breaking change bumps major",
			commits:  []ParsedCommit{{Type: "feat", Subject: "break", Breaking: true}},
			wantVer:  "v2.0.0",
			wantBump: BumpMajor,
		},
		{
			name: "highest bump wins",
			commits: []ParsedCommit{
				{Type: "fix", Subject: "fix"},
				{Type: "feat", Subject: "feat"},
			},
			wantVer:  "v1.1.0",
			wantBump: BumpMinor,
		},
		{
			name:     "docs only no bump",
			commits:  []ParsedCommit{{Type: "docs", Subject: "update readme"}},
			wantVer:  "v1.0.0",
			wantBump: BumpNone,
		},
		{
			name:     "chore only no bump",
			commits:  []ParsedCommit{{Type: "chore", Subject: "update deps"}},
			wantVer:  "v1.0.0",
			wantBump: BumpNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, bump := ComputeNextVersion(current, tt.commits)
			assert.Equal(t, tt.wantVer, ver.String())
			assert.Equal(t, tt.wantBump, bump)
		})
	}
}
