package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAssets(t *testing.T) {
	t.Run("recursively resolves deterministic names", func(t *testing.T) {
		root := t.TempDir()
		imageDir := filepath.Join(root, "image")
		blobDir := filepath.Join(root, "blob")
		writeAsset(t, filepath.Join(imageDir, "nested", "vsa-PASSED.json"), "{}")
		writeAsset(t, filepath.Join(imageDir, "release.tar.gz"), "image")
		writeAsset(t, filepath.Join(blobDir, "vsa-PASSED.json"), "{}")

		assets, err := ResolveAssets(nil, []AssetSource{{ID: "image", Dir: imageDir}, {ID: "blob", Dir: blobDir}})
		require.NoError(t, err)
		assert.Equal(t, []string{"vsa-blob-PASSED.json", "release.tar.gz", "vsa-image-PASSED.json"}, resolvedNames(assets))

		reversed, err := ResolveAssets(nil, []AssetSource{{ID: "blob", Dir: blobDir}, {ID: "image", Dir: imageDir}})
		require.NoError(t, err)
		assert.Equal(t, assets, reversed)
	})

	t.Run("always namespaces an already prefixed VSA name", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "vsa-image-PASSED.json")
		writeAsset(t, path, "{}")

		assets, err := ResolveAssets(nil, []AssetSource{{ID: "image", Dir: dir}})
		require.NoError(t, err)
		assert.Equal(t, []ResolvedAsset{{Path: path, Name: "vsa-image-image-PASSED.json"}}, assets)
	})

	t.Run("preserves explicit asset basenames and input order", func(t *testing.T) {
		dir := t.TempDir()
		first := filepath.Join(dir, "z-last")
		second := filepath.Join(dir, "a-first")
		writeAsset(t, first, "first")
		writeAsset(t, second, "second")
		assets, err := ResolveAssets([]string{first, second}, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"z-last", "a-first"}, resolvedNames(assets))
	})

	t.Run("skips empty files when a source has releasable files", func(t *testing.T) {
		dir := t.TempDir()
		writeAsset(t, filepath.Join(dir, "empty.txt"), "")
		nonEmpty := filepath.Join(dir, "non-empty.txt")
		writeAsset(t, nonEmpty, "contents")

		assets, err := ResolveAssets(nil, []AssetSource{{ID: "source", Dir: dir}})
		require.NoError(t, err)
		assert.Equal(t, []ResolvedAsset{{Path: nonEmpty, Name: "non-empty.txt"}}, assets)
	})

	t.Run("follows a symlinked source root", func(t *testing.T) {
		target := t.TempDir()
		writeAsset(t, filepath.Join(target, "vsa-PASSED.json"), "{}")
		link := filepath.Join(t.TempDir(), "source-link")
		require.NoError(t, os.Symlink(target, link))

		assets, err := ResolveAssets(nil, []AssetSource{{ID: "image", Dir: link}})
		require.NoError(t, err)
		assert.Equal(t, []ResolvedAsset{{Path: filepath.Join(link, "vsa-PASSED.json"), Name: "vsa-image-PASSED.json"}}, assets)
	})

	t.Run("rejects empty sources and collisions with all paths", func(t *testing.T) {
		empty := t.TempDir()
		_, err := ResolveAssets(nil, []AssetSource{{ID: "empty", Dir: empty}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no releasable files")

		first := filepath.Join(t.TempDir(), "one", "artifact.txt")
		sourceDir := filepath.Join(t.TempDir(), "two")
		second := filepath.Join(sourceDir, "artifact.txt")
		writeAsset(t, first, "one")
		writeAsset(t, second, "two")
		_, err = ResolveAssets([]string{first}, []AssetSource{{ID: "source", Dir: sourceDir}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "artifact.txt")
		assert.Contains(t, err.Error(), first)
		assert.Contains(t, err.Error(), second)
	})

	t.Run("rejects ambiguous sanitized source IDs", func(t *testing.T) {
		dir := t.TempDir()
		writeAsset(t, filepath.Join(dir, "asset"), "x")
		_, err := ResolveAssets(nil, []AssetSource{{ID: "release image", Dir: dir}, {ID: "release-image", Dir: dir}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ambiguous asset source IDs")
	})
}

func writeAsset(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func resolvedNames(assets []ResolvedAsset) []string {
	names := make([]string, len(assets))
	for index, asset := range assets {
		names[index] = asset.Name
	}
	return names
}
