package predicate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateDigest(t *testing.T) {
	tempDir := t.TempDir()

	// create test files
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("test content 1"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "file2.txt"), []byte("test content 2"), 0600))

	t.Run("single file", func(t *testing.T) {
		digest, err := CalculateDigest(filepath.Join(tempDir, "file1.txt"))
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
		assert.Contains(t, digest, "sha256:")
	})

	t.Run("directory", func(t *testing.T) {
		digest, err := CalculateDigest(tempDir)
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
		assert.Contains(t, digest, "sha256:")
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := CalculateDigest("non-existent-file")
		assert.Error(t, err)
	})
}

func TestCalculateDigestForDirectory(t *testing.T) {
	tempDir := t.TempDir()

	// create nested test files
	testFiles := map[string]string{
		"file1.txt":          "test content 1",
		"dir1/file2.txt":     "test content 2",
		"dir1/dir2/file.txt": "test content 3",
	}

	for fileName, content := range testFiles {
		filePath := filepath.Join(tempDir, fileName)
		require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0700))
		require.NoError(t, os.WriteFile(filePath, []byte(content), 0600))
	}

	t.Run("list all files", func(t *testing.T) {
		foundFiles, err := listFiles(tempDir)
		require.NoError(t, err)
		assert.Len(t, foundFiles, len(testFiles))
	})

	t.Run("non-existent directory", func(t *testing.T) {
		_, err := listFiles("non-existent-dir")
		assert.Error(t, err)
	})
}
