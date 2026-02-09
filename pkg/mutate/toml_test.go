package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOMLKeyMutatorTopLevel(t *testing.T) {
	content := []byte(`name = "my-crate"
version = "0.1.0"
edition = "2021"
`)

	m := &tomlKeyMutator{}
	updated, result, err := m.Apply(content, "version", "1.0.0", MutationRule{Path: "Cargo.toml", Type: "tomlKey", Field: "version"})

	require.NoError(t, err)
	assert.Equal(t, "0.1.0", result.OldValue)
	assert.Equal(t, "1.0.0", result.NewValue)
	assert.True(t, result.Applied)
	assert.Contains(t, string(updated), `version = "1.0.0"`)
	// preserve other lines
	assert.Contains(t, string(updated), `name = "my-crate"`)
	assert.Contains(t, string(updated), `edition = "2021"`)
}

func TestTOMLKeyMutatorSectionKey(t *testing.T) {
	content := []byte(`[package]
name = "my-crate"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
`)

	m := &tomlKeyMutator{}
	updated, result, err := m.Apply(content, "package.version", "2.0.0", MutationRule{Path: "Cargo.toml", Type: "tomlKey", Field: "package.version"})

	require.NoError(t, err)
	assert.Equal(t, "0.1.0", result.OldValue)
	assert.Contains(t, string(updated), `version = "2.0.0"`)
	// should not modify dependencies section
	assert.Contains(t, string(updated), `serde = "1.0"`)
}

func TestTOMLKeyMutatorUnquotedValue(t *testing.T) {
	content := []byte(`port = 8080
host = "localhost"
`)

	m := &tomlKeyMutator{}
	updated, result, err := m.Apply(content, "port", "9090", MutationRule{Path: "config.toml", Type: "tomlKey", Field: "port"})

	require.NoError(t, err)
	assert.Equal(t, "8080", result.OldValue)
	assert.Contains(t, string(updated), "port = 9090")
}

func TestTOMLKeyMutatorDottedKey(t *testing.T) {
	// H3 regression: dotted key syntax without section headers
	content := []byte(`package.name = "my-crate"
package.version = "0.1.0"
package.edition = "2021"
`)

	m := &tomlKeyMutator{}
	updated, result, err := m.Apply(content, "package.version", "1.0.0", MutationRule{Path: "Cargo.toml", Type: "tomlKey", Field: "package.version"})

	require.NoError(t, err)
	assert.Equal(t, "0.1.0", result.OldValue)
	assert.Contains(t, string(updated), `package.version = "1.0.0"`)
	// other dotted keys must remain untouched
	assert.Contains(t, string(updated), `package.name = "my-crate"`)
	assert.Contains(t, string(updated), `package.edition = "2021"`)
}

func TestTOMLKeyMutatorMissingKey(t *testing.T) {
	content := []byte(`name = "test"
`)

	m := &tomlKeyMutator{}
	_, _, err := m.Apply(content, "version", "1.0.0", MutationRule{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTOMLKeyMutatorPreservesComments(t *testing.T) {
	content := []byte(`# project config
[package]
name = "my-crate"  # crate name
# version of the package
version = "0.1.0"
edition = "2021"
`)

	m := &tomlKeyMutator{}
	updated, _, err := m.Apply(content, "package.version", "1.0.0", MutationRule{Path: "Cargo.toml", Type: "tomlKey", Field: "package.version"})

	require.NoError(t, err)
	assert.Contains(t, string(updated), "# project config")
	assert.Contains(t, string(updated), "# crate name")
	assert.Contains(t, string(updated), "# version of the package")
}
