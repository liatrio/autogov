package mutate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecMutatorBasic(t *testing.T) {
	dir := t.TempDir()

	// create a target file
	targetPath := filepath.Join(dir, "version.txt")
	require.NoError(t, os.WriteFile(targetPath, []byte("old content"), 0o644))

	// create a script that writes the version to the file
	scriptPath := filepath.Join(dir, "update.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(`#!/bin/sh
echo "version=$1" > version.txt
`), 0o755))

	rule := MutationRule{
		Path:     "version.txt",
		Type:     "exec",
		Field:    "./update.sh ${version}",
		RepoRoot: dir,
	}

	m := &execMutator{}
	updated, result, err := m.Apply([]byte("old content"), rule.Field, "1.2.3", rule)

	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.Contains(t, string(updated), "version=1.2.3")
}

func TestExecMutatorVersionSubstitution(t *testing.T) {
	dir := t.TempDir()

	targetPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(targetPath, []byte(""), 0o644))

	rule := MutationRule{
		Path:     "out.txt",
		Type:     "exec",
		Field:    `echo "v${version}" > out.txt`,
		RepoRoot: dir,
	}

	m := &execMutator{}
	updated, _, err := m.Apply([]byte(""), rule.Field, "3.0.0", rule)

	require.NoError(t, err)
	assert.Contains(t, string(updated), "v3.0.0")
}

func TestExecMutatorEnvironmentVariable(t *testing.T) {
	dir := t.TempDir()

	targetPath := filepath.Join(dir, "env.txt")
	require.NoError(t, os.WriteFile(targetPath, []byte(""), 0o644))

	rule := MutationRule{
		Path:     "env.txt",
		Type:     "exec",
		Field:    `echo "$VERSION" > env.txt`,
		RepoRoot: dir,
	}

	m := &execMutator{}
	updated, _, err := m.Apply([]byte(""), rule.Field, "2.5.0", rule)

	require.NoError(t, err)
	assert.Contains(t, string(updated), "2.5.0")
}

func TestExecMutatorInvalidVersion(t *testing.T) {
	dir := t.TempDir()

	rule := MutationRule{
		Path:     "file.txt",
		Type:     "exec",
		Field:    "echo ${version}",
		RepoRoot: dir,
	}

	m := &execMutator{}

	tests := []struct {
		name    string
		version string
	}{
		{"semicolon injection", "1.0.0; rm -rf /"},
		{"backtick injection", "1.0.0`whoami`"},
		{"pipe injection", "1.0.0 | cat /etc/passwd"},
		{"subshell injection", "$(whoami)"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := m.Apply([]byte(""), rule.Field, tt.version, rule)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid characters")
		})
	}
}

func TestExecMutatorCommandFails(t *testing.T) {
	dir := t.TempDir()

	targetPath := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(targetPath, []byte("content"), 0o644))

	rule := MutationRule{
		Path:     "file.txt",
		Type:     "exec",
		Field:    "exit 1",
		RepoRoot: dir,
	}

	m := &execMutator{}
	_, _, err := m.Apply([]byte("content"), rule.Field, "1.0.0", rule)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec command failed")
}

func TestExecMutatorNoRepoRoot(t *testing.T) {
	rule := MutationRule{
		Path:  "file.txt",
		Type:  "exec",
		Field: "echo hi",
	}

	m := &execMutator{}
	_, _, err := m.Apply([]byte(""), rule.Field, "1.0.0", rule)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires repo root")
}

func TestExecMutatorDryRunSkipped(t *testing.T) {
	dir := t.TempDir()

	targetPath := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(targetPath, []byte("original"), 0o644))

	config := &MutationConfig{
		Rules: []MutationRule{
			{
				Path:  "file.txt",
				Type:  "exec",
				Field: `echo "modified" > file.txt`,
			},
		},
	}

	results, err := ApplyMutations(dir, config, "1.0.0", true)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Applied)
	assert.Contains(t, results[0].Diff, "not simulated in dry-run")

	// verify file was NOT modified
	content, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	assert.Equal(t, "original", string(content))
}

func TestExecMutatorIntegration(t *testing.T) {
	dir := t.TempDir()

	// create a JSON file and a script that updates it
	jsonPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"version": "0.0.0"}`), 0o644))

	scriptPath := filepath.Join(dir, "update.sh")
	script := `#!/bin/sh
VERSION="$1"
cat > config.json << EOF
{"version": "${VERSION}"}
EOF
`
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o755))

	config := &MutationConfig{
		Rules: []MutationRule{
			{
				Path:  "config.json",
				Type:  "exec",
				Field: "./update.sh ${version}",
			},
		},
	}

	results, err := ApplyMutations(dir, config, "2.0.0", false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Applied)

	// verify file was updated
	content, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), `"version": "2.0.0"`)
}
