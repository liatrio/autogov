package mutate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mutations.yaml")

	yamlContent := `mutations:
  - path: package.json
    type: jsonPath
    field: version
  - path: Chart.yaml
    type: yamlPath
    field: appVersion
`
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0o644))

	config, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Len(t, config.Rules, 2)
	assert.Equal(t, "package.json", config.Rules[0].Path)
	assert.Equal(t, "jsonPath", config.Rules[0].Type)
	assert.Equal(t, "version", config.Rules[0].Field)
}

func TestLoadConfigJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mutations.json")

	jsonContent := `{"mutations": [{"path": "package.json", "type": "jsonPath", "field": "version"}]}`
	require.NoError(t, os.WriteFile(configPath, []byte(jsonContent), 0o644))

	config, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Len(t, config.Rules, 1)
}

func TestLoadConfigUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mutations.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(""), 0o644))

	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mutation config format")
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/mutations.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

func TestLoadConfigEmptyRules(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mutations.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("mutations: []\n"), 0o644))

	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no mutation rules")
}

func TestLoadConfigMissingFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
		errMsg  string
	}{
		{
			name:    "missing path",
			content: "mutations:\n  - type: jsonPath\n    field: version\n",
			errMsg:  "path is required",
		},
		{
			name:    "missing type",
			content: "mutations:\n  - path: foo.json\n    field: version\n",
			errMsg:  "type is required",
		},
		{
			name:    "missing field",
			content: "mutations:\n  - path: foo.json\n    type: jsonPath\n",
			errMsg:  "field is required",
		},
		{
			name:    "invalid type",
			content: "mutations:\n  - path: foo.json\n    type: badType\n    field: version\n",
			errMsg:  "unknown mutation type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "mutations.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte(tt.content), 0o644))

			_, err := LoadConfig(configPath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestLoadConfigInvalidRegexPattern(t *testing.T) {
	// M2 regression: invalid regex patterns should fail at config load time
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mutations.yaml")
	content := "mutations:\n  - path: file.txt\n    type: regexReplace\n    field: \"[invalid\"\n"
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o644))

	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestLoadConfigPathTraversal(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mutations.yaml")
	content := "mutations:\n  - path: ../../../etc/passwd\n    type: jsonPath\n    field: version\n"
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o644))

	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be relative and within repository root")
}
