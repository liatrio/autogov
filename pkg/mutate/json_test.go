package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONPathMutatorSimpleField(t *testing.T) {
	content := []byte(`{
  "name": "my-app",
  "version": "1.0.0",
  "description": "test"
}`)

	m := &jsonPathMutator{}
	updated, result, err := m.Apply(content, "version", "2.0.0", MutationRule{Path: "package.json", Type: "jsonPath", Field: "version"})

	require.NoError(t, err)
	assert.Equal(t, "1.0.0", result.OldValue)
	assert.Equal(t, "2.0.0", result.NewValue)
	assert.True(t, result.Applied)
	assert.Contains(t, string(updated), `"version": "2.0.0"`)
	// verify formatting preserved (name and description unchanged)
	assert.Contains(t, string(updated), `"name": "my-app"`)
	assert.Contains(t, string(updated), `"description": "test"`)
}

func TestJSONPathMutatorNestedField(t *testing.T) {
	content := []byte(`{
  "package": {
    "version": "0.5.0",
    "name": "nested"
  }
}`)

	m := &jsonPathMutator{}
	updated, result, err := m.Apply(content, "package.version", "1.0.0", MutationRule{Path: "pkg.json", Type: "jsonPath", Field: "package.version"})

	require.NoError(t, err)
	assert.Equal(t, "0.5.0", result.OldValue)
	assert.Contains(t, string(updated), `"version": "1.0.0"`)
}

func TestJSONPathMutatorMissingField(t *testing.T) {
	content := []byte(`{"name": "test"}`)

	m := &jsonPathMutator{}
	_, _, err := m.Apply(content, "version", "1.0.0", MutationRule{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestJSONPathMutatorInvalidJSON(t *testing.T) {
	content := []byte(`{not valid json}`)

	m := &jsonPathMutator{}
	_, _, err := m.Apply(content, "version", "1.0.0", MutationRule{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestJSONPathMutatorNumericValue(t *testing.T) {
	content := []byte(`{
  "name": "app",
  "build": 42
}`)

	m := &jsonPathMutator{}
	updated, result, err := m.Apply(content, "build", "43", MutationRule{Path: "config.json", Type: "jsonPath", Field: "build"})

	require.NoError(t, err)
	assert.Equal(t, "42", result.OldValue)
	assert.Contains(t, string(updated), "43")
}

func TestJSONPathMutatorDuplicateKeyCollision(t *testing.T) {
	// C1 regression: same key+value at different nesting levels
	// only the targeted path should be replaced
	content := []byte(`{
  "dependencies": { "version": "1.0.0", "name": "dep-a" },
  "devDependencies": { "version": "1.0.0", "name": "dep-b" }
}`)

	m := &jsonPathMutator{}
	updated, result, err := m.Apply(content, "dependencies.version", "2.0.0", MutationRule{Path: "package.json", Type: "jsonPath", Field: "dependencies.version"})

	require.NoError(t, err)
	assert.Equal(t, "1.0.0", result.OldValue)
	assert.Equal(t, "2.0.0", result.NewValue)
	// only dependencies.version should change
	assert.Contains(t, string(updated), `"dependencies": { "version": "2.0.0"`)
	// devDependencies.version must remain untouched
	assert.Contains(t, string(updated), `"devDependencies": { "version": "1.0.0"`)
}

func TestJSONPathMutatorPreservesFormatting(t *testing.T) {
	// verify indentation and key order are preserved
	content := []byte(`{
    "name": "my-package",
    "version": "1.2.3",
    "private": true
}`)

	m := &jsonPathMutator{}
	updated, _, err := m.Apply(content, "version", "1.3.0", MutationRule{Path: "package.json", Type: "jsonPath", Field: "version"})

	require.NoError(t, err)
	// should preserve 4-space indentation
	assert.Contains(t, string(updated), `    "version": "1.3.0"`)
	assert.Contains(t, string(updated), `    "name": "my-package"`)
}
