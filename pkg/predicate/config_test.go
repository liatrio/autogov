package predicate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Run("loads default config", func(t *testing.T) {
		t.Setenv("POLICY_REPO_OWNER", "")
		t.Setenv("POLICY_REPO_NAME", "")
		t.Setenv("POLICY_VERSION", "")
		t.Setenv("SCHEMAS_PATH", "")

		cfg, err := LoadConfig()
		assert.NoError(t, err)
		assert.Equal(t, "liatrio", cfg.PolicyRepo.Owner)
		assert.Equal(t, "demo-gh-autogov-policy-library", cfg.PolicyRepo.Name)
		assert.Equal(t, "main", cfg.PolicyRepo.Ref)
		assert.Equal(t, "schemas/", cfg.SchemasPath)
	})

	t.Run("loads custom config", func(t *testing.T) {
		t.Setenv("POLICY_REPO_OWNER", "custom-owner")
		t.Setenv("POLICY_REPO_NAME", "custom-repo")
		t.Setenv("POLICY_VERSION", "v1.0.0")
		t.Setenv("SCHEMAS_PATH", "custom/schemas/")

		cfg, err := LoadConfig()
		assert.NoError(t, err)
		assert.Equal(t, "custom-owner", cfg.PolicyRepo.Owner)
		assert.Equal(t, "custom-repo", cfg.PolicyRepo.Name)
		assert.Equal(t, "v1.0.0", cfg.PolicyRepo.Ref)
		assert.Equal(t, "custom/schemas/", cfg.SchemasPath)
	})
}

func TestValidateMetadata(t *testing.T) {
	t.Run("validates valid metadata", func(t *testing.T) {
		validMetadata := []byte(`{
			"artifact": {
				"version": "1.0.0",
				"created": "2024-01-27T19:48:49Z",
				"type": "container-image",
				"registry": "ghcr.io",
				"fullName": "ghcr.io/test-org/test-repo@sha256:test",
				"digest": "sha256:test"
			},
			"repositoryData": {
				"repository": "test-org/test-repo",
				"repositoryId": "123",
				"githubServerURL": "https://github.com"
			},
			"ownerData": {
				"owner": "test-org",
				"ownerId": "456"
			},
			"runnerData": {
				"os": "linux",
				"arch": "amd64",
				"environment": "github-hosted"
			},
			"workflowData": {
				"workflowRefPath": "test-workflow",
				"inputs": {"test-input": "test-value"},
				"branch": "main",
				"event": "push"
			},
			"jobData": {
				"runNumber": "1",
				"runId": "123",
				"status": "success",
				"triggeredBy": "test-user",
				"startedAt": "2024-01-27T19:48:49Z",
				"completedAt": "2024-01-27T19:48:50Z"
			},
			"commitData": {
				"sha": "abc123",
				"timestamp": "2024-01-27T19:48:49Z"
			},
			"organization": {
				"name": "test-org"
			},
			"compliance": {
				"policyRef": "https://github.com/test-org/test-policy",
				"controlIds": ["test-control"]
			},
			"security": {
				"permissions": {
					"id-token": "write",
					"attestations": "write",
					"contents": "read",
					"packages": "write"
				}
			}
		}`)

		err := ValidateMetadata(validMetadata)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid metadata", func(t *testing.T) {
		invalidMetadata := []byte(`{
			"artifact": {
				"version": "1.0.0",
				"type": "invalid-type"
			}
		}`)

		err := ValidateMetadata(invalidMetadata)
		require.Error(t, err)
	})
}

func TestValidateDepscan(t *testing.T) {
	t.Run("validates valid depscan", func(t *testing.T) {
		validDepscan := []byte(`{
			"scanner": {
				"name": "grype",
				"uri": "https://github.com/anchore/grype/releases/tag/v0.74.7",
				"version": "0.74.7",
				"db": {
					"uri": "https://toolbox-data.anchore.io/grype/databases/listing.json",
					"version": "1.5",
					"lastUpdate": "2024-01-27T19:48:49Z"
				},
				"result": [
					{
						"id": "CVE-2024-1234",
						"severity": [
							{"method": "CVSSv3", "score": "7.5"}
						]
					}
				]
			}
		}`)

		err := ValidateDepscan(validDepscan)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid depscan", func(t *testing.T) {
		invalidDepscan := []byte(`{
			"scanner": {
				"uri": "https://github.com/anchore/grype/releases/tag/v0.74.7",
				"version": "0.74.7",
				"db": {
					"uri": "https://toolbox-data.anchore.io/grype/databases/listing.json",
					"version": "1.5",
					"lastUpdate": "2024-01-27T19:48:49Z"
				},
				"result": []
			}
		}`)

		err := ValidateDepscan(invalidDepscan)
		require.Error(t, err)
	})
}
