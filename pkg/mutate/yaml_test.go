package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestYAMLPathMutatorSimpleField(t *testing.T) {
	content := []byte(`name: my-chart
version: 1.0.0
appVersion: 1.0.0
`)

	m := &yamlPathMutator{}
	updated, result, err := m.Apply(content, "version", "2.0.0", MutationRule{Path: "Chart.yaml", Type: "yamlPath", Field: "version"})

	require.NoError(t, err)
	assert.Equal(t, "1.0.0", result.OldValue)
	assert.Equal(t, "2.0.0", result.NewValue)
	assert.True(t, result.Applied)
	assert.Contains(t, string(updated), "version: 2.0.0")
}

func TestYAMLPathMutatorNestedField(t *testing.T) {
	content := []byte(`image:
  repository: my-repo
  tag: v1.0.0
`)

	m := &yamlPathMutator{}
	updated, result, err := m.Apply(content, "image.tag", "v2.0.0", MutationRule{Path: "values.yaml", Type: "yamlPath", Field: "image.tag"})

	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", result.OldValue)
	assert.Contains(t, string(updated), "tag: v2.0.0")
}

func TestYAMLPathMutatorCommentPreservation(t *testing.T) {
	content := []byte(`# chart metadata
name: my-chart  # chart name
# the version field
version: 1.0.0  # current version
appVersion: 1.0.0
`)

	m := &yamlPathMutator{}
	updated, result, err := m.Apply(content, "version", "2.0.0", MutationRule{Path: "Chart.yaml", Type: "yamlPath", Field: "version"})

	require.NoError(t, err)
	assert.Equal(t, "1.0.0", result.OldValue)
	// comments should be preserved
	assert.Contains(t, string(updated), "# chart metadata")
	assert.Contains(t, string(updated), "# chart name")
	assert.Contains(t, string(updated), "# the version field")
	assert.Contains(t, string(updated), "# current version")
}

func TestYAMLPathMutatorFourSpaceIndent(t *testing.T) {
	// H1 regression: 4-space indentation must be preserved, not normalized to 2-space
	content := []byte(`global:
    image:
        repository: my-repo
        tag: v1.0.0
`)

	m := &yamlPathMutator{}
	updated, result, err := m.Apply(content, "global.image.tag", "v2.0.0", MutationRule{Path: "values.yaml", Type: "yamlPath", Field: "global.image.tag"})

	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", result.OldValue)
	// verify 4-space indentation is preserved
	assert.Contains(t, string(updated), "        tag: v2.0.0")
	assert.Contains(t, string(updated), "        repository: my-repo")
}

func TestYAMLPathMutatorTrailingNewlinePreserved(t *testing.T) {
	// H2 regression: files without trailing newline must not gain one
	content := []byte("name: my-chart\nversion: 1.0.0")

	m := &yamlPathMutator{}
	updated, _, err := m.Apply(content, "version", "2.0.0", MutationRule{Path: "Chart.yaml", Type: "yamlPath", Field: "version"})

	require.NoError(t, err)
	// should NOT add trailing newline
	assert.Equal(t, "name: my-chart\nversion: 2.0.0", string(updated))
}

func TestYAMLPathMutatorInlineCommentPreserved(t *testing.T) {
	content := []byte("version: 1.0.0  # current version\nname: test\n")

	m := &yamlPathMutator{}
	updated, _, err := m.Apply(content, "version", "2.0.0", MutationRule{Path: "Chart.yaml", Type: "yamlPath", Field: "version"})

	require.NoError(t, err)
	assert.Contains(t, string(updated), "version: 2.0.0  # current version")
}

func TestYAMLPathMutatorMissingField(t *testing.T) {
	content := []byte(`name: test
`)

	m := &yamlPathMutator{}
	_, _, err := m.Apply(content, "version", "1.0.0", MutationRule{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestYAMLPathMutatorInvalidYAML(t *testing.T) {
	content := []byte(`[invalid: yaml: {`)

	m := &yamlPathMutator{}
	_, _, err := m.Apply(content, "version", "1.0.0", MutationRule{})

	require.Error(t, err)
}

func TestYAMLPathMutatorDeeplyNested(t *testing.T) {
	content := []byte(`global:
  image:
    tag: v0.1.0
`)

	m := &yamlPathMutator{}
	updated, result, err := m.Apply(content, "global.image.tag", "v1.0.0", MutationRule{Path: "values.yaml", Type: "yamlPath", Field: "global.image.tag"})

	require.NoError(t, err)
	assert.Equal(t, "v0.1.0", result.OldValue)
	assert.Contains(t, string(updated), "tag: v1.0.0")
}
