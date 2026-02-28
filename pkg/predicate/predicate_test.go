package predicate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestOptions() Options {
	now := time.Now().UTC()
	return Options{
		Type:            ArtifactTypeContainerImage,
		Registry:        "ghcr.io",
		Repository:      "test-org/test-repo",
		FullName:        "ghcr.io/test-org/test-repo@sha256:test",
		Digest:          "sha256:test",
		Version:         "test-sha-test-run-number",
		Created:         now,
		GitHubServerURL: "https://github.com",
		Owner:           "test-org",
		OwnerID:         "test-owner-id",
		RepositoryID:    "test-repo-id",
		OS:              "test-os",
		Arch:            "test-arch",
		Environment:     "test-env",
		WorkflowRefPath: "test-workflow-ref",
		Branch:          "main",
		Event:           "push",
		RunNumber:       "1",
		RunID:           "123",
		Status:          "success",
		TriggeredBy:     "test-user",
		StartedAt:       now,
		CompletedAt:     now,
		SHA:             "test-sha",
		Timestamp:       now,
		OrgName:         "test-org",
		PolicyRef:       "https://github.com/test-org/test-policy",
		ControlIds:      []string{"test-control"},
		Permissions: map[string]string{
			"id-token":     "write",
			"attestations": "write",
			"contents":     "read",
			"packages":     "write",
		},
		Inputs: map[string]any{
			"test-input": "test-value",
		},
	}
}

func TestGenerateMetadata(t *testing.T) {
	t.Run("valid_container_image_metadata", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "metadata.json")

		opts := createTestOptions()

		err := GenerateMetadata(opts, outputPath)
		require.NoError(t, err)

		// verify output file exists
		_, err = os.Stat(outputPath)
		require.NoError(t, err)

		// read and parse output
		data, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var predicate map[string]any
		err = json.Unmarshal(data, &predicate)
		require.NoError(t, err)

		// verify all top-level fields
		assert.NotNil(t, predicate["artifact"])
		assert.NotNil(t, predicate["repositoryData"])
		assert.NotNil(t, predicate["ownerData"])
		assert.NotNil(t, predicate["runnerData"])
		assert.NotNil(t, predicate["workflowData"])
		assert.NotNil(t, predicate["jobData"])
		assert.NotNil(t, predicate["commitData"])
		assert.NotNil(t, predicate["organization"])
		assert.NotNil(t, predicate["compliance"])
		assert.NotNil(t, predicate["security"])

		// verify artifact fields
		artifact := predicate["artifact"].(map[string]any)
		assert.Equal(t, "container-image", artifact["type"])
		assert.Equal(t, "ghcr.io/test-org/test-repo@sha256:test", artifact["fullName"])
		assert.Equal(t, "sha256:test", artifact["digest"])
		assert.Equal(t, "ghcr.io", artifact["registry"])
	})

	t.Run("valid_blob_metadata", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "metadata.json")

		// create a test blob file
		blobPath := filepath.Join(tmpDir, "test-blob.tar.gz")
		require.NoError(t, os.WriteFile(blobPath, []byte("test blob content"), 0600))

		opts := createTestOptions()
		opts.Type = ArtifactTypeBlob
		opts.SubjectPath = blobPath
		opts.Registry = ""
		opts.FullName = ""
		opts.Digest = "sha256:test"

		err := GenerateMetadata(opts, outputPath)
		require.NoError(t, err)

		data, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var predicate map[string]any
		require.NoError(t, json.Unmarshal(data, &predicate))

		artifact := predicate["artifact"].(map[string]any)
		assert.Equal(t, "blob", artifact["type"])
		assert.Equal(t, blobPath, artifact["path"])
	})

	t.Run("invalid_artifact_type", func(t *testing.T) {
		opts := createTestOptions()
		opts.Type = "invalid"

		err := GenerateMetadata(opts, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid artifact type")
	})

	t.Run("container_image_missing_fields", func(t *testing.T) {
		opts := createTestOptions()
		opts.Type = ArtifactTypeContainerImage
		opts.Registry = ""
		opts.FullName = ""
		opts.Digest = ""

		err := GenerateMetadata(opts, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "container-image requires")
	})

	t.Run("blob_missing_subject_path", func(t *testing.T) {
		opts := createTestOptions()
		opts.Type = ArtifactTypeBlob
		opts.SubjectPath = ""

		err := GenerateMetadata(opts, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "blob requires subjectPath")
	})

	t.Run("stdout_output", func(t *testing.T) {
		opts := createTestOptions()
		err := GenerateMetadata(opts, "")
		require.NoError(t, err)
	})
}

func TestGenerateDepscan(t *testing.T) {
	t.Run("valid_depscan", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "depscan.json")
		resultsPath := filepath.Join(tmpDir, "results.json")

		testData := []byte(`{
			"descriptor": {
				"name": "grype",
				"version": "0.87.0",
				"timestamp": "2025-01-24T00:18:00Z",
				"db": {
					"status": {
						"schemaVersion": "5",
						"from": "https://toolbox-data.anchore.io/grype/databases/listing.json",
						"built": "2025-01-23T01:31:43Z"
					}
				}
			},
			"matches": [
				{
					"vulnerability": {
						"id": "CVE-2024-1234",
						"severity": "Medium",
						"cvss": [{"metrics": {"baseScore": 7.5}}]
					}
				}
			]
		}`)

		require.NoError(t, os.WriteFile(resultsPath, testData, 0600))

		opts := DependencyScanOptions{
			Type:        ArtifactTypeContainerImage,
			SubjectName: "test-image",
			Digest:      "sha256:test",
			ResultsPath: resultsPath,
		}

		err := GenerateDepscan(opts, outputPath)
		require.NoError(t, err)

		data, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var result map[string]any
		require.NoError(t, json.Unmarshal(data, &result))

		assert.Contains(t, result, "scanner")
		assert.Contains(t, result, "metadata")

		// verify scanner details
		scanner := result["scanner"].(map[string]any)
		assert.Equal(t, "grype", scanner["name"])
		assert.Equal(t, "0.87.0", scanner["version"])

		// verify results
		results := scanner["result"].([]any)
		assert.Len(t, results, 1)

		vuln := results[0].(map[string]any)
		assert.Equal(t, "CVE-2024-1234", vuln["id"])
	})

	t.Run("depscan_with_new_status_format", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "depscan.json")
		resultsPath := filepath.Join(tmpDir, "results.json")

		testData := []byte(`{
			"descriptor": {
				"name": "grype",
				"version": "0.97.2",
				"timestamp": "2025-08-12T17:13:00Z",
				"db": {
					"status": {
						"schemaVersion": "v6.0.3",
						"from": "https://grype.anchore.io/databases/v6/db.tar.zst",
						"built": "2025-08-12T04:13:42Z"
					}
				}
			},
			"matches": [
				{
					"vulnerability": {
						"id": "CVE-2024-5678",
						"severity": "High",
						"cvss": [{"metrics": {"baseScore": 8.5}}]
					}
				}
			]
		}`)

		require.NoError(t, os.WriteFile(resultsPath, testData, 0600))

		opts := DependencyScanOptions{
			Type:        ArtifactTypeContainerImage,
			SubjectName: "test-image",
			Digest:      "sha256:test",
			ResultsPath: resultsPath,
		}

		err := GenerateDepscan(opts, outputPath)
		require.NoError(t, err)

		data, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var result map[string]any
		require.NoError(t, json.Unmarshal(data, &result))

		scanner := result["scanner"].(map[string]any)
		db := scanner["db"].(map[string]any)
		assert.Equal(t, "https://grype.anchore.io/databases/v6/db.tar.zst", db["uri"])
		assert.Equal(t, "v6.0.3", db["version"])
		assert.Equal(t, "2025-08-12T04:13:42Z", db["lastUpdate"])
	})

	t.Run("invalid_results_path", func(t *testing.T) {
		opts := DependencyScanOptions{
			Type:        ArtifactTypeContainerImage,
			SubjectName: "test-image",
			Digest:      "sha256:test",
			ResultsPath: "/nonexistent/path.json",
		}

		err := GenerateDepscan(opts, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read results file")
	})

	t.Run("invalid_results_json", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte("not json"), 0600))

		opts := DependencyScanOptions{
			Type:        ArtifactTypeContainerImage,
			SubjectName: "test-image",
			Digest:      "sha256:test",
			ResultsPath: resultsPath,
		}

		err := GenerateDepscan(opts, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse results")
	})
}
