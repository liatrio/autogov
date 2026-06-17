package release

import (
	"testing"

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
}
