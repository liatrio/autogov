package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireAtLeastOne(t *testing.T) {
	tests := []struct {
		name     string
		selector *ArtifactSelector
		wantErr  bool
	}{
		{
			name: "image digest provided",
			selector: &ArtifactSelector{
				ImageDigest: "sha256:abc123",
			},
			wantErr: false,
		},
		{
			name: "blob paths provided",
			selector: &ArtifactSelector{
				BlobPaths: []string{"file.txt"},
			},
			wantErr: false,
		},
		{
			name: "positional digest provided",
			selector: &ArtifactSelector{
				PositionalDigest: "sha256:def456",
			},
			wantErr: false,
		},
		{
			name:     "nothing provided",
			selector: &ArtifactSelector{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireAtLeastOne(tt.selector)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequireAtLeastOne() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequireRepoIf(t *testing.T) {
	tests := []struct {
		name     string
		selector *ArtifactSelector
		wantErr  bool
	}{
		{
			name: "image digest with repo",
			selector: &ArtifactSelector{
				ImageDigest: "sha256:abc123",
				Repo:        "owner/repo",
			},
			wantErr: false,
		},
		{
			name: "blob paths with repo",
			selector: &ArtifactSelector{
				BlobPaths: []string{"file.txt"},
				Repo:      "owner/repo",
			},
			wantErr: false,
		},
		{
			name: "image digest without repo",
			selector: &ArtifactSelector{
				ImageDigest: "sha256:abc123",
			},
			wantErr: true,
		},
		{
			name: "blob paths without repo",
			selector: &ArtifactSelector{
				BlobPaths: []string{"file.txt"},
			},
			wantErr: true,
		},
		{
			name:     "no artifact, no repo needed",
			selector: &ArtifactSelector{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// tests with requireRepo=true (online verification)
			err := RequireRepoIf(tt.selector, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequireRepoIf() error = %v, wantErr %v", err, tt.wantErr)
			}

			// tests with requireRepo=false (offline verification) / should never error
			err = RequireRepoIf(tt.selector, false)
			if err != nil {
				t.Errorf("RequireRepoIf() with requireRepo=false should never error, got %v", err)
			}
		})
	}
}

func TestBuildFullImageRef(t *testing.T) {
	tests := []struct {
		name   string
		repo   string
		digest string
		want   string
	}{
		{
			name:   "bare digest with repo",
			repo:   "owner/repo",
			digest: "sha256:abc123",
			want:   "ghcr.io/owner/repo@sha256:abc123",
		},
		{
			name:   "full ref already",
			repo:   "owner/repo",
			digest: "ghcr.io/owner/repo@sha256:abc123",
			want:   "ghcr.io/owner/repo@sha256:abc123",
		},
		{
			name:   "empty repo",
			repo:   "",
			digest: "sha256:abc123",
			want:   "sha256:abc123",
		},
		{
			name:   "empty digest",
			repo:   "owner/repo",
			digest: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFullImageRef(tt.repo, tt.digest)
			if got != tt.want {
				t.Errorf("BuildFullImageRef() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateDigestFormat(t *testing.T) {
	tests := []struct {
		name    string
		digest  string
		wantErr bool
	}{
		{
			name:    "valid digest",
			digest:  "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			wantErr: false,
		},
		{
			name:    "empty digest (valid)",
			digest:  "",
			wantErr: false,
		},
		{
			name:    "missing sha256 prefix",
			digest:  "abc123def456789012345678901234567890123456789012345678901234567890",
			wantErr: true,
		},
		{
			name:    "too short",
			digest:  "sha256:abc123",
			wantErr: true,
		},
		{
			name:    "invalid hex characters",
			digest:  "sha256:xyz123def456789012345678901234567890123456789012345678901234567890",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDigestFormat(tt.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDigestFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpandBlobPaths(t *testing.T) {
	// creates temporary dir with test files
	tempDir := t.TempDir()

	// creates test files
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")

	if err := os.WriteFile(file1, []byte("test1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte("test2"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		pathStr string
		wantLen int
		wantErr bool
	}{
		{
			name:    "empty path",
			pathStr: "",
			wantLen: 0,
			wantErr: false,
		},
		{
			name:    "single file",
			pathStr: file1,
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "directory",
			pathStr: tempDir,
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "comma-separated files",
			pathStr: file1 + "," + file2,
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "non-existent file",
			pathStr: "/non/existent/file.txt",
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandBlobPaths(tt.pathStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandBlobPaths() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("ExpandBlobPaths() len = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}
