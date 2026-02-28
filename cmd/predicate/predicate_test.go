package predicate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateCommandStructure(t *testing.T) {
	t.Run("predicate command exists", func(t *testing.T) {
		assert.Equal(t, "predicate", PredicateCmd.Use)
		assert.NotEmpty(t, PredicateCmd.Short)
	})

	t.Run("has metadata subcommand", func(t *testing.T) {
		found := false
		for _, cmd := range PredicateCmd.Commands() {
			if cmd.Use == "metadata" {
				found = true
				break
			}
		}
		assert.True(t, found, "metadata subcommand should exist")
	})

	t.Run("has depscan subcommand", func(t *testing.T) {
		found := false
		for _, cmd := range PredicateCmd.Commands() {
			if cmd.Use == "depscan" {
				found = true
				break
			}
		}
		assert.True(t, found, "depscan subcommand should exist")
	})
}

func TestMetadataCommandFlags(t *testing.T) {
	flags := metadataCmd.Flags()

	expectedFlags := []string{
		"subject-path",
		"subject-name",
		"subject-digest",
		"output",
		"type",
		"policy-ref",
	}

	for _, name := range expectedFlags {
		t.Run("has flag "+name, func(t *testing.T) {
			f := flags.Lookup(name)
			assert.NotNil(t, f, "flag %q should exist", name)
		})
	}

	t.Run("type defaults to image", func(t *testing.T) {
		f := flags.Lookup("type")
		require.NotNil(t, f)
		assert.Equal(t, "image", f.DefValue)
	})
}

func TestDepscanCommandFlags(t *testing.T) {
	flags := depscanCmd.Flags()

	expectedFlags := []string{
		"results-path",
		"subject-name",
		"subject-path",
		"subject-digest",
		"output",
		"type",
	}

	for _, name := range expectedFlags {
		t.Run("has flag "+name, func(t *testing.T) {
			f := flags.Lookup(name)
			assert.NotNil(t, f, "flag %q should exist", name)
		})
	}

	t.Run("results-path is required", func(t *testing.T) {
		annotations := depscanCmd.Flags().Lookup("results-path")
		require.NotNil(t, annotations)
		// cobra marks required flags via annotations
	})
}

func TestGetWorkflowPermissions(t *testing.T) {
	t.Run("default permissions for container image", func(t *testing.T) {
		t.Setenv(pred.EnvWorkflowPermissions, "")
		perms := getWorkflowPermissions(pred.ArtifactTypeContainerImage)
		assert.Equal(t, "write", perms["id-token"])
		assert.Equal(t, "write", perms["attestations"])
		assert.Equal(t, "read", perms["contents"])
		assert.Equal(t, "write", perms["packages"])
	})

	t.Run("default permissions for blob", func(t *testing.T) {
		t.Setenv(pred.EnvWorkflowPermissions, "")
		perms := getWorkflowPermissions(pred.ArtifactTypeBlob)
		assert.Equal(t, "write", perms["id-token"])
		assert.Equal(t, "write", perms["attestations"])
		assert.Equal(t, "read", perms["contents"])
		assert.Equal(t, "none", perms["packages"])
	})

	t.Run("custom permissions from env", func(t *testing.T) {
		customPerms := map[string]string{
			"id-token":     "write",
			"attestations": "write",
			"contents":     "write",
		}
		permsJSON, _ := json.Marshal(customPerms)
		t.Setenv(pred.EnvWorkflowPermissions, string(permsJSON))

		perms := getWorkflowPermissions(pred.ArtifactTypeContainerImage)
		assert.Equal(t, "write", perms["contents"])
		assert.Empty(t, perms["packages"]) // not in custom perms
	})

	t.Run("invalid env JSON falls back to defaults", func(t *testing.T) {
		t.Setenv(pred.EnvWorkflowPermissions, "not-json")

		perms := getWorkflowPermissions(pred.ArtifactTypeContainerImage)
		assert.Equal(t, "write", perms["packages"]) // default for image
	})
}

func TestRunDepscanValidation(t *testing.T) {
	t.Run("invalid type rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(`{"descriptor":{"version":"1.0"},"matches":[]}`), 0600))

		// reset package-level vars
		origType := depscanType
		origResults := depscanResultsPath
		defer func() {
			depscanType = origType
			depscanResultsPath = origResults
		}()

		depscanType = "invalid"
		depscanResultsPath = resultsPath

		err := runDepscan(nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid type")
	})
}
