// Package digest provides common digest calculation utilities
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CalculateFile calculates the SHA256 digest of a file
func CalculateFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}

	return Format("sha256", hex.EncodeToString(h.Sum(nil))), nil
}

// CalculateString calculates the SHA256 digest of a string
func CalculateString(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return Format("sha256", hex.EncodeToString(h.Sum(nil)))
}

// CalculateBytes calculates the SHA256 digest of bytes
func CalculateBytes(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return Format("sha256", hex.EncodeToString(h.Sum(nil)))
}

// CalculateReader calculates the SHA256 digest from a reader
func CalculateReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}
	return Format("sha256", hex.EncodeToString(h.Sum(nil))), nil
}

// CalculateDirectory calculates a combined hash of all files in a directory
func CalculateDirectory(dirPath string, extensions []string) (string, error) {
	h := sha256.New()
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// skip directories
		if info.IsDir() {
			return nil
		}
		
		// check if file matches extensions filter
		if len(extensions) > 0 {
			matched := false
			for _, ext := range extensions {
				if strings.HasSuffix(path, ext) {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}
		
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		
		// include relative path in hash for uniqueness
		relPath, _ := filepath.Rel(dirPath, path)
		h.Write([]byte(relPath))
		
		_, err = io.Copy(h, file)
		return err
	})
	
	if err != nil {
		return "", fmt.Errorf("failed to hash directory: %w", err)
	}
	
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Format formats a digest with its algorithm prefix
func Format(algorithm, hexDigest string) string {
	return fmt.Sprintf("%s:%s", algorithm, hexDigest)
}

// Parse parses a digest string into algorithm and hex parts
func Parse(digest string) (algorithm, hexDigest string, err error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid digest format: %s (expected <algorithm>:<digest>)", digest)
	}
	return parts[0], parts[1], nil
}

// Normalize ensures a digest has the algorithm prefix
func Normalize(digest string) string {
	if !strings.Contains(digest, ":") {
		return Format("sha256", digest)
	}
	return digest
}

// ValidateFormat validates digest format based on algorithm
func ValidateFormat(algorithm, hexDigest string) error {
	if hexDigest == "" {
		return fmt.Errorf("empty digest value")
	}

	// validate hex characters
	if !isHexString(hexDigest) {
		return fmt.Errorf("digest contains non-hexadecimal characters")
	}

	// validate length based on algorithm
	switch algorithm {
	case "sha256":
		if len(hexDigest) != 64 {
			return fmt.Errorf("invalid SHA256 digest length: expected 64 characters, got %d", len(hexDigest))
		}
	case "sha1":
		if len(hexDigest) != 40 {
			return fmt.Errorf("invalid SHA1 digest length: expected 40 characters, got %d", len(hexDigest))
		}
	case "sha512":
		if len(hexDigest) != 128 {
			return fmt.Errorf("invalid SHA512 digest length: expected 128 characters, got %d", len(hexDigest))
		}
	case "md5":
		if len(hexDigest) != 32 {
			return fmt.Errorf("invalid MD5 digest length: expected 32 characters, got %d", len(hexDigest))
		}
	}

	return nil
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// CreateTempDir creates a temp dir and returns its path along with cleanup func
func CreateTempDir(prefix string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), prefix)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	cleanup := func() {
		if err := CleanupTempDir(tmpDir); err != nil {
			// log error, but don't fail since this is cleanup
			fmt.Printf("Warning: failed to cleanup temp directory %s: %v\n", tmpDir, err)
		}
	}
	return tmpDir, cleanup, nil
}

// CleanupTempDir removes temp dir if it's under os.TempDir()
func CleanupTempDir(dirPath string) error {
	if strings.HasPrefix(dirPath, os.TempDir()) {
		return os.RemoveAll(dirPath)
	}
	return nil
}
