package release

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// AssetSource describes a local directory whose releasable files are collected recursively.
type AssetSource struct {
	ID  string
	Dir string
}

// ResolvedAsset is a local file paired with the name it will have on the release.
type ResolvedAsset struct {
	Path string
	Name string
}

// ResolveAssets validates explicit assets and recursively resolves source directories into
// deterministic release upload entries. Explicit assets retain their base filenames; VSA
// files discovered from a source are namespaced by that source's sanitized ID.
func ResolveAssets(assets []string, sources []AssetSource) ([]ResolvedAsset, error) {
	resolved := make([]ResolvedAsset, 0, len(assets))
	for _, path := range assets {
		if err := validateAssetFile(path); err != nil {
			return nil, err
		}
		resolved = append(resolved, ResolvedAsset{Path: path, Name: filepath.Base(path)})
	}

	type normalizedSource struct {
		AssetSource
		sanitizedID string
	}
	normalized := make([]normalizedSource, 0, len(sources))
	seenIDs := make(map[string]AssetSource, len(sources))
	for _, source := range sources {
		if source.ID == "" || source.Dir == "" {
			return nil, fmt.Errorf("asset source must have non-empty ID and directory")
		}
		sanitizedID := sanitizeAssetSourceID(source.ID)
		if sanitizedID == "" {
			return nil, fmt.Errorf("invalid asset source ID %q", source.ID)
		}
		if previous, duplicate := seenIDs[sanitizedID]; duplicate {
			return nil, fmt.Errorf("ambiguous asset source IDs %q and %q both sanitize to %q", previous.ID, source.ID, sanitizedID)
		}
		seenIDs[sanitizedID] = source
		normalized = append(normalized, normalizedSource{AssetSource: source, sanitizedID: sanitizedID})
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].sanitizedID < normalized[j].sanitizedID
	})

	for _, source := range normalized {
		entries, err := resolveAssetSource(source.AssetSource, source.sanitizedID)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, entries...)
	}
	if err := validateResolvedAssetNames(resolved, len(sources) == 0); err != nil {
		return nil, err
	}
	return resolved, nil
}

func resolveAssetSource(source AssetSource, sanitizedID string) ([]ResolvedAsset, error) {
	root, err := filepath.EvalSymlinks(source.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve asset source %q (%s): %w", source.ID, source.Dir, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("asset source not found: %s: %w", source.Dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("asset source is not a directory: %s", source.Dir)
	}

	entries := make([]ResolvedAsset, 0)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() == 0 {
			return nil
		}
		name := entry.Name()
		if isVSAFilename(name) {
			name = "vsa-" + sanitizedID + "-" + strings.TrimPrefix(name, "vsa-")
		}
		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries = append(entries, ResolvedAsset{Path: filepath.Join(source.Dir, relativePath), Name: name})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read asset source %q (%s): %w", source.ID, source.Dir, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("asset source %q contains no releasable files: %s", source.ID, source.Dir)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})
	return entries, nil
}

func validateAssetFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("asset not found: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("asset is not a regular file: %s", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("asset is empty (0 bytes): %s", path)
	}
	return nil
}

func validateResolvedAssetNames(assets []ResolvedAsset, explicitOnly bool) error {
	pathsByName := make(map[string][]string, len(assets))
	for _, asset := range assets {
		pathsByName[asset.Name] = append(pathsByName[asset.Name], asset.Path)
	}
	for _, asset := range assets {
		paths := pathsByName[asset.Name]
		if len(paths) > 1 {
			if explicitOnly {
				return fmt.Errorf("multiple assets resolve to the same name %q; release asset names must be unique", asset.Name)
			}
			return fmt.Errorf("multiple assets resolve to the same name %q: %s", asset.Name, strings.Join(paths, ", "))
		}
	}
	return nil
}

func isVSAFilename(name string) bool {
	return strings.HasPrefix(name, "vsa-") && strings.HasSuffix(name, ".json")
}

func sanitizeAssetSourceID(id string) string {
	var builder strings.Builder
	lastWasSeparator := true
	for _, char := range strings.ToLower(id) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			builder.WriteRune(char)
			lastWasSeparator = false
			continue
		}
		if !lastWasSeparator {
			builder.WriteByte('-')
			lastWasSeparator = true
		}
	}
	return strings.Trim(builder.String(), "-")
}
