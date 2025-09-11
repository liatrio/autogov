// provides functionality for offline attestation verification
// using pre-downloaded Sigstore bundles and trusted roots.
package offline

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"path/filepath"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// loads sigstore bundles from a JSON/JSONL file or directory
func LoadBundles(bundlePath string) ([]*bundle.Bundle, error) {
	// check if dir
	fileInfo, err := os.Stat(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	// if dir, load all .json and .jsonl files
	if fileInfo.IsDir() {
		return loadBundlesFromDirectory(bundlePath)
	}

	// otherwise load as a single file
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file: %w", err)
	}

	// parse as single bundle JSON first
	singleBundle := &bundle.Bundle{}
	if err := singleBundle.UnmarshalJSON(data); err == nil {
		return []*bundle.Bundle{singleBundle}, nil
	}

	// parse as JSON array
	var jsonBundles []json.RawMessage
	if err := json.Unmarshal(data, &jsonBundles); err == nil {
		bundles := make([]*bundle.Bundle, 0, len(jsonBundles))
		for i, raw := range jsonBundles {
			b := &bundle.Bundle{}
			if err := b.UnmarshalJSON(raw); err != nil {
				return nil, fmt.Errorf("failed to parse bundle %d: %w", i, err)
			}
			bundles = append(bundles, b)
		}
		return bundles, nil
	}

	// parse as JSONL
	bundles := make([]*bundle.Bundle, 0)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// buffer size to handle large attestations (up to 10MB per line)
	const maxScanTokenSize = 10 * 1024 * 1024
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// single bundle
		b := &bundle.Bundle{}
		if err := b.UnmarshalJSON(line); err == nil {
			bundles = append(bundles, b)
			continue
		}

		// array of bundles (some files have arrays on each line)
		var arrayBundles []json.RawMessage
		if err := json.Unmarshal(line, &arrayBundles); err == nil {
			for _, raw := range arrayBundles {
				b := &bundle.Bundle{}
				if err := b.UnmarshalJSON(raw); err != nil {
					return nil, fmt.Errorf("failed to parse bundle in array: %w", err)
				}
				bundles = append(bundles, b)
			}
			continue
		}

		return nil, fmt.Errorf("failed to parse bundle line")
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan bundle file: %w", err)
	}

	if len(bundles) == 0 {
		return nil, fmt.Errorf("no bundles found in file")
	}

	return bundles, nil
}

// loads bundles from all JSON/JSONL files in a directory
func loadBundlesFromDirectory(dirPath string) ([]*bundle.Bundle, error) {
	var allBundles []*bundle.Bundle

	// read all files in dir
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// process .json and .jsonl files only
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jsonl") {
			continue
		}

		// loads bundles from file
		filePath := filepath.Join(dirPath, name)
		bundles, err := LoadBundles(filePath)
		if err != nil {
			// skip files that can't be parsed as bundles
			continue
		}

		allBundles = append(allBundles, bundles...)
	}

	if len(allBundles) == 0 {
		return nil, fmt.Errorf("no valid attestation bundles found in directory %s", dirPath)
	}

	return allBundles, nil
}

// writes sigstore bundles to a file in the specified format
func WriteBundles(bundles []*bundle.Bundle, path, format string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = file.Close() }()

	switch format {
	case "json":
		// JSON array
		jsonBundles := make([]json.RawMessage, 0, len(bundles))
		for _, b := range bundles {
			data, err := b.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal bundle: %w", err)
			}
			jsonBundles = append(jsonBundles, data)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(jsonBundles); err != nil {
			return fmt.Errorf("failed to write bundles as JSON: %w", err)
		}
	case "jsonl":
		// JSONL (one bundle per line)
		for _, b := range bundles {
			data, err := b.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal bundle: %w", err)
			}
			if _, err := file.Write(data); err != nil {
				return fmt.Errorf("failed to write bundle: %w", err)
			}
			if _, err := file.WriteString("\n"); err != nil {
				return fmt.Errorf("failed to write newline: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}
