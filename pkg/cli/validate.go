package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ensures that at least one artifact selector is provided
func RequireAtLeastOne(selector *ArtifactSelector) error {
	if selector.ImageDigest == "" && len(selector.BlobPaths) == 0 && selector.PositionalDigest == "" {
		return fmt.Errorf("either --image-digest, --blob-path, or a positional argument must be provided")
	}
	return nil
}

// ensures repo is provided when required for online verification
// offline verification doesn't require repo since it uses pre-downloaded attestations
func RequireRepoIf(selector *ArtifactSelector, requireRepo bool) error {
	if requireRepo && (selector.ImageDigest != "" || len(selector.BlobPaths) > 0) && selector.Repo == "" {
		return fmt.Errorf("--repo is required for blob and image verification")
	}
	return nil
}

// takes a path string (which could be a single file, comma-separated files, or a directory), returns a slice of individual file paths
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

	// if no dir, treat as comma-separated paths
	paths := strings.Split(pathStr, ",")
	var result []string
	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			// verify the file exists
			if _, err := os.Stat(trimmed); err != nil {
				return nil, fmt.Errorf("file not found: %s", trimmed)
			}
			result = append(result, trimmed)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid paths found in: %s", pathStr)
	}

	return result, nil
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

	// construct full reference with ghcr.io registry
	return fmt.Sprintf("ghcr.io/%s@%s", repo, digest)
}

// validates that a digest has the correct format
func ValidateDigestFormat(digest string) error {
	if digest == "" {
		return nil // empty is valid (optional)
	}

	// check for sha256: prefix
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("digest must start with 'sha256:'")
	}

	// check hex length (64 characters after sha256:)
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("invalid digest format, expected 'sha256:<64-char-hex>', got %s", digest)
	}

	// check if hex is valid
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return fmt.Errorf("invalid digest format, contains non-hex characters: %s", digest)
		}
	}

	return nil
}
