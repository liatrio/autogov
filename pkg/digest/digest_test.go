package digest

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateFile(t *testing.T) {
	// create a temp file with known content
	tmpFile, err := os.CreateTemp("", "test-digest-*.txt")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	testContent := "Hello, World!"
	_, err = tmpFile.WriteString(testContent)
	require.NoError(t, err)
	_ = tmpFile.Close()

	// calculate digest
	digest, err := CalculateFile(tmpFile.Name())
	assert.NoError(t, err)
	assert.Equal(t, "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", digest)

	// test with non-existent file
	_, err = CalculateFile("/nonexistent/file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestCalculateString(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "hello world",
			content:  "Hello, World!",
			expected: "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "empty string",
			content:  "",
			expected: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "with newline",
			content:  "test\n",
			expected: "sha256:f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateString(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateBytes(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "hello bytes",
			data:     []byte("Hello, World!"),
			expected: "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "empty bytes",
			data:     []byte{},
			expected: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "binary data",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: "sha256:054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateBytes(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateReader(t *testing.T) {
	tests := []struct {
		name      string
		reader    io.Reader
		expected  string
		wantError bool
	}{
		{
			name:     "valid reader",
			reader:   strings.NewReader("Hello, World!"),
			expected: "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "empty reader",
			reader:   strings.NewReader(""),
			expected: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "bytes reader",
			reader:   bytes.NewReader([]byte("test")),
			expected: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CalculateReader(tt.reader)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCalculateDirectory(t *testing.T) {
	// create a temp directory with test files
	tmpDir, err := os.MkdirTemp("", "test-digest-dir-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// create test files
	files := map[string]string{
		"file1.txt":  "content1",
		"file2.go":   "content2",
		"file3.json": "content3",
		"file4.yaml": "content4",
	}

	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
	}

	// test with no filter
	digest1, err := CalculateDirectory(tmpDir, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, digest1)

	// test with extension filter
	digest2, err := CalculateDirectory(tmpDir, []string{".go", ".json"})
	assert.NoError(t, err)
	assert.NotEmpty(t, digest2)
	assert.NotEqual(t, digest1, digest2) // should be different due to filtering

	// test with single extension
	digest3, err := CalculateDirectory(tmpDir, []string{".txt"})
	assert.NoError(t, err)
	assert.NotEmpty(t, digest3)

	// test with non-existent directory
	_, err = CalculateDirectory("/nonexistent/dir", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to hash directory")
}

func TestFormat(t *testing.T) {
	tests := []struct {
		algorithm string
		hexDigest string
		expected  string
	}{
		{
			algorithm: "sha256",
			hexDigest: "abc123",
			expected:  "sha256:abc123",
		},
		{
			algorithm: "sha1",
			hexDigest: "def456",
			expected:  "sha1:def456",
		},
		{
			algorithm: "md5",
			hexDigest: "789ghi",
			expected:  "md5:789ghi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			result := Format(tt.algorithm, tt.hexDigest)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		digest    string
		wantAlgo  string
		wantHex   string
		wantError bool
	}{
		{
			name:      "valid sha256",
			digest:    "sha256:abc123",
			wantAlgo:  "sha256",
			wantHex:   "abc123",
			wantError: false,
		},
		{
			name:      "valid sha1",
			digest:    "sha1:def456",
			wantAlgo:  "sha1",
			wantHex:   "def456",
			wantError: false,
		},
		{
			name:      "no colon",
			digest:    "abc123",
			wantError: true,
		},
		{
			name:      "empty string",
			digest:    "",
			wantError: true,
		},
		{
			name:      "multiple colons",
			digest:    "sha256:abc:123",
			wantAlgo:  "sha256",
			wantHex:   "abc:123",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, hex, err := Parse(tt.digest)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantAlgo, algo)
				assert.Equal(t, tt.wantHex, hex)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		digest   string
		expected string
	}{
		{
			name:     "already normalized",
			digest:   "sha256:abc123",
			expected: "sha256:abc123",
		},
		{
			name:     "missing algorithm",
			digest:   "abc123",
			expected: "sha256:abc123",
		},
		{
			name:     "sha1 digest",
			digest:   "sha1:def456",
			expected: "sha1:def456",
		},
		{
			name:     "empty string",
			digest:   "",
			expected: "sha256:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Normalize(tt.digest)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		hexDigest string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid sha256",
			algorithm: "sha256",
			hexDigest: strings.Repeat("a", 64),
			wantError: false,
		},
		{
			name:      "invalid sha256 length",
			algorithm: "sha256",
			hexDigest: "abc123",
			wantError: true,
			errorMsg:  "invalid SHA256 digest length",
		},
		{
			name:      "valid sha1",
			algorithm: "sha1",
			hexDigest: strings.Repeat("b", 40),
			wantError: false,
		},
		{
			name:      "invalid sha1 length",
			algorithm: "sha1",
			hexDigest: "abc",
			wantError: true,
			errorMsg:  "invalid SHA1 digest length",
		},
		{
			name:      "valid sha512",
			algorithm: "sha512",
			hexDigest: strings.Repeat("c", 128),
			wantError: false,
		},
		{
			name:      "invalid sha512 length",
			algorithm: "sha512",
			hexDigest: "abc",
			wantError: true,
			errorMsg:  "invalid SHA512 digest length",
		},
		{
			name:      "valid md5",
			algorithm: "md5",
			hexDigest: strings.Repeat("d", 32),
			wantError: false,
		},
		{
			name:      "invalid md5 length",
			algorithm: "md5",
			hexDigest: "abc",
			wantError: true,
			errorMsg:  "invalid MD5 digest length",
		},
		{
			name:      "empty digest",
			algorithm: "sha256",
			hexDigest: "",
			wantError: true,
			errorMsg:  "empty digest value",
		},
		{
			name:      "non-hex characters",
			algorithm: "sha256",
			hexDigest: strings.Repeat("g", 64),
			wantError: true,
			errorMsg:  "digest contains non-hexadecimal characters",
		},
		{
			name:      "mixed case hex",
			algorithm: "sha256",
			hexDigest: strings.Repeat("aB", 32),
			wantError: false,
		},
		{
			name:      "unknown algorithm",
			algorithm: "unknown",
			hexDigest: "abc123",
			wantError: false, // no validation for unknown algorithms
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFormat(tt.algorithm, tt.hexDigest)
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid lowercase hex",
			input:    "abc123def456",
			expected: true,
		},
		{
			name:     "valid uppercase hex",
			input:    "ABC123DEF456",
			expected: true,
		},
		{
			name:     "valid mixed case hex",
			input:    "aBc123DeF456",
			expected: true,
		},
		{
			name:     "invalid characters",
			input:    "xyz123",
			expected: false,
		},
		{
			name:     "special characters",
			input:    "abc-123",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHexString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateTempDir(t *testing.T) {
	// test successful creation
	dir, cleanup, err := CreateTempDir("test-prefix-")
	assert.NoError(t, err)
	assert.NotEmpty(t, dir)
	assert.NotNil(t, cleanup)
	assert.True(t, strings.HasPrefix(filepath.Base(dir), "test-prefix-"))

	// verify directory exists
	_, err = os.Stat(dir)
	assert.NoError(t, err)

	// cleanup
	cleanup()

	// verify directory is removed
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err))
}

func TestCleanupTempDir(t *testing.T) {
	// create a temp directory
	tmpDir, err := os.MkdirTemp("", "test-cleanup-*")
	require.NoError(t, err)

	// cleanup should work for temp directory
	err = CleanupTempDir(tmpDir)
	assert.NoError(t, err)

	// verify directory is removed
	_, err = os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(err))

	// cleanup should not work for non-temp directory
	err = CleanupTempDir("/usr/local/bin")
	assert.NoError(t, err) // returns nil but doesn't delete

	// verify non-temp directory still exists
	_, err = os.Stat("/usr/local/bin")
	assert.NoError(t, err)
}
