package mutate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyMutationsJSON(t *testing.T) {
	dir := t.TempDir()

	// create test JSON file
	jsonContent := `{
  "name": "my-app",
  "version": "1.0.0"
}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(jsonContent), 0o644))

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "package.json", Type: "jsonPath", Field: "version"},
		},
	}

	results, err := ApplyMutations(dir, config, "2.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Applied)
	assert.Equal(t, "1.0.0", results[0].OldValue)
	assert.Equal(t, "2.0.0", results[0].NewValue)

	// verify file was actually written
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `"version": "2.0.0"`)
}

func TestApplyMutationsYAML(t *testing.T) {
	dir := t.TempDir()

	yamlContent := `name: my-chart
version: 1.0.0
appVersion: 1.0.0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte(yamlContent), 0o644))

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "Chart.yaml", Type: "yamlPath", Field: "version"},
			{Path: "Chart.yaml", Type: "yamlPath", Field: "appVersion"},
		},
	}

	results, err := ApplyMutations(dir, config, "2.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 2)

	// verify file
	data, err := os.ReadFile(filepath.Join(dir, "Chart.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "2.0.0")
}

func TestDryRunMutations(t *testing.T) {
	dir := t.TempDir()

	jsonContent := `{"version": "1.0.0"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(jsonContent), 0o644))

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "package.json", Type: "jsonPath", Field: "version"},
		},
	}

	results, err := DryRunMutations(dir, config, "2.0.0")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Applied) // dry run should not apply
	assert.Equal(t, "1.0.0", results[0].OldValue)
	assert.NotEmpty(t, results[0].Diff)

	// verify file was NOT modified
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `"version": "1.0.0"`)
}

func TestApplyMutationsFileNotFound(t *testing.T) {
	dir := t.TempDir()

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "nonexistent.json", Type: "jsonPath", Field: "version"},
		},
	}

	results, err := ApplyMutations(dir, config, "1.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].Error)
	assert.Contains(t, results[0].Error, "failed to read file")
}

func TestApplyMutationsMultiFile(t *testing.T) {
	dir := t.TempDir()

	// create multiple test files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"version": "1.0.0"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("version: 1.0.0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Makefile"), []byte("VERSION := 1.0.0\n"), 0o644))

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "package.json", Type: "jsonPath", Field: "version"},
			{Path: "Chart.yaml", Type: "yamlPath", Field: "version"},
			{Path: "Makefile", Type: "regexReplace", Field: `VERSION\s*:=\s*(\S+)`, Replace: "VERSION := ${version}"},
		},
	}

	results, err := ApplyMutations(dir, config, "2.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 3)

	for _, r := range results {
		assert.True(t, r.Applied, "rule for %s should be applied", r.Rule.Path)
		assert.Empty(t, r.Error, "rule for %s should have no error", r.Rule.Path)
	}

	// verify all files updated
	data, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	assert.Contains(t, string(data), `"version": "2.0.0"`)

	data, _ = os.ReadFile(filepath.Join(dir, "Chart.yaml"))
	assert.Contains(t, string(data), "2.0.0")

	data, _ = os.ReadFile(filepath.Join(dir, "Makefile"))
	assert.Contains(t, string(data), "VERSION := 2.0.0")
}

func TestApplyMutationsPathEscape(t *testing.T) {
	dir := t.TempDir()

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "../../../etc/passwd", Type: "jsonPath", Field: "version"},
		},
	}

	results, err := ApplyMutations(dir, config, "1.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].Error)
	assert.Contains(t, results[0].Error, "path escapes repository root")
}

func TestApplyMutationsRuleErrorInMultiRule(t *testing.T) {
	// verify that a failed rule doesn't stop other rules from being processed
	dir := t.TempDir()

	// create one valid file, one missing
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"version": "1.0.0"}`), 0o644))

	config := &MutationConfig{
		Rules: []MutationRule{
			{Path: "nonexistent.json", Type: "jsonPath", Field: "version"},
			{Path: "package.json", Type: "jsonPath", Field: "version"},
		},
	}

	results, err := ApplyMutations(dir, config, "2.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 2)

	// first rule should have an error
	assert.NotEmpty(t, results[0].Error)
	assert.False(t, results[0].Applied)

	// second rule should succeed despite first failing
	assert.Empty(t, results[1].Error)
	assert.True(t, results[1].Applied)
}

func TestAtomicWritePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o755))

	require.NoError(t, atomicWrite(path, []byte("updated")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "updated", string(data))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}
