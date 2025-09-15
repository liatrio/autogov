package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// takes a path string (which could be a single file, comma-separated files, or a directory)
// and returns a slice of individual file paths
func ExpandBlobPaths(pathStr string) ([]string, error) {
	if pathStr == "" {
		return nil, nil
	}

	// check if dir
	fileInfo, err := os.Stat(pathStr)
	if err == nil && fileInfo.IsDir() {
		// if dir, get all files in it
		entries, err := os.ReadDir(pathStr)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s: %w", pathStr, err)
		}

		var files []string
		for _, entry := range entries {
			if !entry.IsDir() {
				files = append(files, filepath.Join(pathStr, entry.Name()))
			}
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("no files found in directory %s", pathStr)
		}
		return files, nil
	}

	// otherwise it's either a single file or comma-separated list
	if strings.Contains(pathStr, ",") {
		// multiple files separated by commas
		parts := strings.Split(pathStr, ",")
		var files []string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				files = append(files, part)
			}
		}
		return files, nil
	}

	// single file
	return []string{pathStr}, nil
}

// constructs a full image reference from repo and digest
func BuildFullImageRef(repo, digest string) string {
	if repo == "" || digest == "" {
		return digest
	}

	// if digest already contains a registry/repo, return as-is
	if strings.Contains(digest, "/") {
		return digest
	}

	return fmt.Sprintf("ghcr.io/%s@%s", repo, digest)
}

// validates that a digest string is in the correct format
func ValidateDigestFormat(digest string) error {
	if digest == "" {
		return nil
	}

	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("digest must start with 'sha256:' prefix")
	}

	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("digest must be 64 hex characters after 'sha256:' prefix")
	}

	return nil
}

// calculates the SHA256 digest of a file
func CalculateFileDigest(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
