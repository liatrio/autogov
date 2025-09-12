package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testFile1        = "file1.txt"
	testFile2        = "file2.txt"
	testFile3        = "file3.txt"
	testDigest       = "sha256:abc123"
	testRepo         = "org/repo"
	testFullImageRef = "ghcr.io/org/repo@sha256:abc123"
)

func TestExpandBlobPaths(t *testing.T) {
	tests := []struct {
		name    string
		pathStr string
		setup   func() string
		want    []string
		wantErr bool
		cleanup func(string)
	}{
		{
			name:    "empty path",
			pathStr: "",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "single file",
			pathStr: "file.txt",
			want:    []string{"file.txt"},
			wantErr: false,
		},
		{
			name:    "comma-separated files",
			pathStr: testFile1 + ", " + testFile2 + ", " + testFile3,
			want:    []string{testFile1, testFile2, testFile3},
			wantErr: false,
		},
		{
			name:    "comma-separated with extra spaces",
			pathStr: "  " + testFile1 + "  ,  " + testFile2 + "  ,  " + testFile3 + "  ",
			want:    []string{testFile1, testFile2, testFile3},
			wantErr: false,
		},
		{
			name: "directory with files",
			setup: func() string {
				tmpDir, _ := os.MkdirTemp("", "test-expand-*")
				_ = os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
				_ = os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644)
				_ = os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755)
				_ = os.WriteFile(filepath.Join(tmpDir, "subdir", "file3.txt"), []byte("content3"), 0644)
				return tmpDir
			},
			cleanup: func(dir string) {
				_ = os.RemoveAll(dir)
			},
			wantErr: false,
		},
		{
			name: "empty directory",
			setup: func() string {
				tmpDir, _ := os.MkdirTemp("", "test-empty-*")
				return tmpDir
			},
			cleanup: func(dir string) {
				_ = os.RemoveAll(dir)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testPath string
			if tt.setup != nil {
				testPath = tt.setup()
				if tt.cleanup != nil {
					defer tt.cleanup(testPath)
				}
			} else {
				testPath = tt.pathStr
			}

			got, err := ExpandBlobPaths(testPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandBlobPaths() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.name == "directory with files" && !tt.wantErr {
				// for directory test, just check we got 2 files (not subdirs)
				if len(got) != 2 {
					t.Errorf("ExpandBlobPaths() got %d files, want 2", len(got))
				}
				// check files are from the right directory
				for _, file := range got {
					if !strings.HasPrefix(file, testPath) {
						t.Errorf("ExpandBlobPaths() file %s not in directory %s", file, testPath)
					}
				}
			} else if !tt.wantErr {
				// for non-directory tests, check exact match
				if len(got) != len(tt.want) {
					t.Errorf("ExpandBlobPaths() got = %v, want %v", got, tt.want)
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("ExpandBlobPaths() got[%d] = %v, want %v", i, got[i], tt.want[i])
					}
				}
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
			name:   "empty repo and digest",
			repo:   "",
			digest: "",
			want:   "",
		},
		{
			name:   "empty repo",
			repo:   "",
			digest: testDigest,
			want:   testDigest,
		},
		{
			name:   "empty digest",
			repo:   testRepo,
			digest: "",
			want:   "",
		},
		{
			name:   "digest already contains registry",
			repo:   testRepo,
			digest: testFullImageRef,
			want:   testFullImageRef,
		},
		{
			name:   "simple digest",
			repo:   testRepo,
			digest: testDigest,
			want:   testFullImageRef,
		},
		{
			name:   "digest with slash (already has path)",
			repo:   testRepo,
			digest: "some/path@" + testDigest,
			want:   "some/path@" + testDigest,
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
		errMsg  string
	}{
		{
			name:    "empty digest",
			digest:  "",
			wantErr: false,
		},
		{
			name:    "valid digest",
			digest:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: false,
		},
		{
			name:    "missing sha256 prefix",
			digest:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: true,
			errMsg:  "must start with 'sha256:' prefix",
		},
		{
			name:    "wrong prefix",
			digest:  "sha512:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: true,
			errMsg:  "must start with 'sha256:' prefix",
		},
		{
			name:    "too short",
			digest:  "sha256:abc123",
			wantErr: true,
			errMsg:  "must be 64 hex characters",
		},
		{
			name:    "too long",
			digest:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855abc",
			wantErr: true,
			errMsg:  "must be 64 hex characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDigestFormat(tt.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDigestFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateDigestFormat() error = %v, want error containing %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestCalculateFileDigest(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantHash string
		wantErr  bool
	}{
		{
			name:     "empty file",
			content:  "",
			wantHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:  false,
		},
		{
			name:     "simple content",
			content:  "hello world",
			wantHash: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErr:  false,
		},
		{
			name:     "multi-line content",
			content:  "line1\nline2\nline3",
			wantHash: "6bb6a5ad9b9c43a7cb535e636578716b64ac42edea814a4cad102ba404946837",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create temp file
			tmpFile, err := os.CreateTemp("", "test-digest-*")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer func() {
				_ = os.Remove(tmpFile.Name())
			}()

			// write content
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("Failed to write to temp file: %v", err)
			}
			_ = tmpFile.Close()

			// calculate digest
			got, err := CalculateFileDigest(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateFileDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantHash {
				t.Errorf("CalculateFileDigest() = %v, want %v", got, tt.wantHash)
			}
		})
	}

	// test non-existent file
	t.Run("non-existent file", func(t *testing.T) {
		_, err := CalculateFileDigest("/non/existent/file")
		if err == nil {
			t.Error("CalculateFileDigest() expected error for non-existent file")
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && contains(s[1:], substr)
}
