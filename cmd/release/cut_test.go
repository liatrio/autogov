package release

import (
	"testing"

	"github.com/liatrio/autogov/pkg/release"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAssetLabels(t *testing.T) {
	t.Run("nil for empty input", func(t *testing.T) {
		labels, err := parseAssetLabels(nil)
		require.NoError(t, err)
		assert.Nil(t, labels)
	})
	t.Run("parses name=label pairs", func(t *testing.T) {
		labels, err := parseAssetLabels([]string{"bin=Linux x86_64", "vsa.json=VSA"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"bin": "Linux x86_64", "vsa.json": "VSA"}, labels)
	})
	t.Run("keeps = inside the label value (split on first =)", func(t *testing.T) {
		labels, err := parseAssetLabels([]string{"key=a=b"})
		require.NoError(t, err)
		assert.Equal(t, "a=b", labels["key"])
	})
	t.Run("rejects a pair without =", func(t *testing.T) {
		_, err := parseAssetLabels([]string{"nokey"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected name=label")
	})
	t.Run("rejects an empty name", func(t *testing.T) {
		_, err := parseAssetLabels([]string{"=label"})
		require.Error(t, err)
	})
	t.Run("rejects an empty label value", func(t *testing.T) {
		_, err := parseAssetLabels([]string{"name="})
		require.Error(t, err)
	})
	t.Run("rejects duplicate keys", func(t *testing.T) {
		_, err := parseAssetLabels([]string{"bin=A", "bin=B"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate")
	})
}

func TestParseAssetSources(t *testing.T) {
	t.Run("nil for empty input", func(t *testing.T) {
		sources, err := parseAssetSources(nil)
		require.NoError(t, err)
		assert.Nil(t, sources)
	})
	t.Run("parses repeated ID directory pairs", func(t *testing.T) {
		sources, err := parseAssetSources([]string{"image=dist/image", "blob=dist/blob"})
		require.NoError(t, err)
		assert.Equal(t, []release.AssetSource{{ID: "image", Dir: "dist/image"}, {ID: "blob", Dir: "dist/blob"}}, sources)
	})
	for _, value := range []string{"image", "=dist/image", "image="} {
		t.Run("rejects malformed pair "+value, func(t *testing.T) {
			_, err := parseAssetSources([]string{value})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "expected ID=DIR")
		})
	}
}

func TestCutOptionsFromFlagsPassesRepeatedAssetSources(t *testing.T) {
	cmd := &cobra.Command{}
	registerCutFlags(cmd)
	flags := cmd.Flags()
	require.NoError(t, flags.Set("asset-source", "image=dist/image"))
	require.NoError(t, flags.Set("asset-source", "blob=dist/blob"))

	opts, err := cutOptionsFromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, []release.AssetSource{{ID: "image", Dir: "dist/image"}, {ID: "blob", Dir: "dist/blob"}}, opts.AssetSources)
}
