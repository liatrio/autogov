package predicate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// CalculateDigest calculates the sha256 digest of a file or directory.
func CalculateDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		// get all files in dir
		files, err := listFiles(path)
		if err != nil {
			return "", err
		}

		// get combined digest of all files
		h := sha256.New()
		for _, file := range files {
			if err := hashFileInto(h, file); err != nil {
				return "", err
			}
		}
		return fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil))), nil
	}

	// handle single file
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}

	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil))), nil
}

// hashFileInto opens a file and copies its contents into the provided hash.
func hashFileInto(h hash.Hash, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to calculate digest for %s: %w", path, err)
	}
	return nil
}

// listFiles lists all files in a directory recursively, sorted.
func listFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}
	sort.Strings(files)
	return files, nil
}
