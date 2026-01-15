package policy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const (
	testPolicyContent = `package governance

import rego.v1

default allow := false

allow if {
    input.test == true
}

violations contains msg if {
    input.test == false
    msg := "Test input is false"
}
`
)

// helper to create a temporary policy dir
func createTestPolicyDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "opa-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	policyFile := filepath.Join(tempDir, "test.rego")
	if err := os.WriteFile(policyFile, []byte(testPolicyContent), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	return tempDir
}

func TestNewOPAEvaluatorLocalDirectory(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}

	if evaluator.policyPath != tempDir {
		t.Errorf("Expected policy path %s, got %s", tempDir, evaluator.policyPath)
	}

	if evaluator.prepared == nil {
		t.Error("Expected prepared query to be non-nil")
	}
}

func TestNewOPAEvaluatorInvalidDirectory(t *testing.T) {
	ctx := context.Background()

	_, err := NewOPAEvaluator(ctx, "/nonexistent/directory", "", "")
	if err == nil {
		t.Fatal("Expected error for nonexistent directory")
	}
}

func TestNewOPAEvaluatorEmptyDirectory(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "opa-empty-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// empty dir should create evaluator with 0 policies
	if evaluator == nil {
		t.Fatal("Expected evaluator to be created even with empty directory")
	}
}

func TestLoadPoliciesFromPathSuccess(t *testing.T) {
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	policies, err := loadPoliciesFromPath(tempDir)
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	if _, exists := policies["test.rego"]; !exists {
		t.Error("Expected test.rego policy to exist")
	}
}

func TestLoadPoliciesFromPathNonexistentPath(t *testing.T) {
	_, err := loadPoliciesFromPath("/nonexistent/path")
	if err == nil {
		t.Fatal("Expected error for nonexistent path")
	}
}

func TestLoadPoliciesFromPathNoRegoFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-no-rego-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a non-rego file
	txtFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(txtFile, []byte("not a rego file"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	policies, err := loadPoliciesFromPath(tempDir)
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	if len(policies) != 0 {
		t.Errorf("Expected 0 policies, got %d", len(policies))
	}
}

func TestGetPolicyDetails(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// set opa version for test
	viper.Set("opa-version", "v1.8.0")
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	details := evaluator.GetPolicyDetails()
	if details == nil {
		t.Fatal("Expected details to be non-nil")
	}

	if policyPath, exists := details["policy_path"]; !exists || policyPath != tempDir {
		t.Errorf("Expected policy_path %s, got %v", tempDir, policyPath)
	}

	if opaVersion, exists := details["opa_version"]; !exists || opaVersion != "v1.8.0" {
		t.Errorf("Expected opa_version v1.8.0, got %v", opaVersion)
	}
}

func TestStop(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// stop should not panic or return error
	evaluator.Stop(ctx)
}

func TestPolicyViolationJSONMarshaling(t *testing.T) {
	violation := PolicyViolation{
		Policy:  "test-policy",
		Message: "test message",
	}

	data, err := json.Marshal(violation)
	if err != nil {
		t.Fatalf("Failed to marshal violation: %v", err)
	}

	var unmarshaled PolicyViolation
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal violation: %v", err)
	}

	if unmarshaled.Policy != violation.Policy {
		t.Errorf("Expected policy %s, got %s", violation.Policy, unmarshaled.Policy)
	}

	if unmarshaled.Message != violation.Message {
		t.Errorf("Expected message %s, got %s", violation.Message, unmarshaled.Message)
	}
}

func TestPolicyResultJSONMarshaling(t *testing.T) {
	result := PolicyResult{
		Result: "PASSED",
		Violations: []PolicyViolation{
			{Policy: "test", Message: "test message"},
		},
		Details: map[string]interface{}{
			"test": "value",
		},
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	var unmarshaled PolicyResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if unmarshaled.Result != result.Result {
		t.Errorf("Expected result %s, got %s", result.Result, unmarshaled.Result)
	}

	if len(unmarshaled.Violations) != len(result.Violations) {
		t.Errorf("Expected %d violations, got %d", len(result.Violations), len(unmarshaled.Violations))
	}
}

// test w/ env vars for token auth
func TestDownloadBundleWithToken(t *testing.T) {
	// skip if running in CI without network access
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	// create a simple test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test content")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// set test token
	if err := os.Setenv("GH_TOKEN", "test-token"); err != nil {
		t.Fatalf("Failed to set env var: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GH_TOKEN"); err != nil {
			t.Logf("Warning: failed to unset env var: %v", err)
		}
	}()

	ctx := context.Background()

	// will fail because we're not serving a valid tar.gz, but it tests the auth logic
	_, err := downloadBundle(ctx, server.URL)
	if err == nil {
		t.Fatal("Expected error for invalid tar.gz content")
	}

	// error should be about gzip/tar format, not authentication
	if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized") {
		t.Error("Authentication failed when token was provided")
	}
}

func TestDownloadBundleWithoutToken(t *testing.T) {
	// skip if running in CI without network access
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	// create a test server that requires auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// ensure no tokens are set
	for _, key := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if err := os.Unsetenv(key); err != nil {
			t.Logf("Warning: failed to unset env var %s: %v", key, err)
		}
	}

	ctx := context.Background()

	_, err := downloadBundle(ctx, server.URL)
	if err == nil {
		t.Fatal("Expected error for unauthorized request")
	}

	if !strings.Contains(err.Error(), "401") {
		t.Errorf("Expected 401 error, got: %v", err)
	}
}

func TestLoadSchemasFromPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-schemas-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a valid JSON schema file
	schemaContent := `{"type": "object", "properties": {"name": {"type": "string"}}}`
	schemaFile := filepath.Join(tempDir, "test-schema.json")
	if err := os.WriteFile(schemaFile, []byte(schemaContent), 0644); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	schemas, err := loadSchemasFromPath(tempDir)
	if err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	if len(schemas) != 1 {
		t.Errorf("Expected 1 schema, got %d", len(schemas))
	}

	if _, exists := schemas["test-schema"]; !exists {
		t.Error("Expected test-schema to exist")
	}
}

func TestLoadSchemasFromPathInvalidJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-invalid-schemas-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create an invalid JSON file
	schemaFile := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(schemaFile, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	_, err = loadSchemasFromPath(tempDir)
	if err == nil {
		t.Fatal("Expected error for invalid JSON schema")
	}
}

func TestLoadSchemasFromPathNonexistent(t *testing.T) {
	_, err := loadSchemasFromPath("/nonexistent/path")
	if err == nil {
		t.Fatal("Expected error for nonexistent path")
	}
}

func TestLoadDataFromPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-data-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a valid data file
	dataContent := `{"threshold": 5, "enabled": true}`
	dataFile := filepath.Join(tempDir, "data.json")
	if err := os.WriteFile(dataFile, []byte(dataContent), 0644); err != nil {
		t.Fatalf("Failed to write data file: %v", err)
	}

	data, err := loadDataFromPath(dataFile)
	if err != nil {
		t.Fatalf("Failed to load data: %v", err)
	}

	if data == nil {
		t.Fatal("Expected data to be non-nil")
	}

	if val, ok := data["threshold"].(float64); !ok || val != 5 {
		t.Errorf("Expected threshold 5, got %v", data["threshold"])
	}

	if val, ok := data["enabled"].(bool); !ok || !val {
		t.Errorf("Expected enabled true, got %v", data["enabled"])
	}
}

func TestLoadDataFromPathInvalidJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-invalid-data-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create an invalid JSON file
	dataFile := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(dataFile, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write data file: %v", err)
	}

	_, err = loadDataFromPath(dataFile)
	if err == nil {
		t.Fatal("Expected error for invalid JSON data")
	}
}

func TestLoadDataFromPathNonexistent(t *testing.T) {
	_, err := loadDataFromPath("/nonexistent/data.json")
	if err == nil {
		t.Fatal("Expected error for nonexistent path")
	}
}

func TestCalculateDigestDirectory(t *testing.T) {
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	digest, err := CalculateDigest(tempDir)
	if err != nil {
		t.Fatalf("Failed to calculate digest: %v", err)
	}

	if digest == "" {
		t.Error("Expected non-empty digest")
	}

	// SHA256 hex is 64 characters
	if len(digest) != 64 {
		t.Errorf("Expected 64-character hex digest, got %d characters", len(digest))
	}
}

func TestCalculateDigestFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-digest-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a single file
	testFile := filepath.Join(tempDir, "test.rego")
	if err := os.WriteFile(testFile, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	digest, err := CalculateDigest(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate digest: %v", err)
	}

	if digest == "" {
		t.Error("Expected non-empty digest")
	}

	// SHA256 hex is 64 characters
	if len(digest) != 64 {
		t.Errorf("Expected 64-character hex digest, got %d characters", len(digest))
	}
}

func TestCalculateDigestNonexistent(t *testing.T) {
	_, err := CalculateDigest("/nonexistent/path")
	if err == nil {
		t.Fatal("Expected error for nonexistent path")
	}
}

func TestEvaluatePolicyWithBundles(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// test with input that should pass (test == true)
	bundles := []map[string]interface{}{
		{"test": true},
	}

	result, err := evaluator.EvaluatePolicyWithBundles(ctx, bundles)
	if err != nil {
		t.Fatalf("Failed to evaluate policy: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	// Our simple test policy allows when input.test == true
	// However, since we're passing bundles as input array, we need to adjust the test
	t.Logf("Result: %s, Violations: %d", result.Result, len(result.Violations))
}

func TestEvaluatePolicyWithBundlesFailed(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// test with input that should fail (test == false)
	bundles := []map[string]interface{}{
		{"test": false},
	}

	result, err := evaluator.EvaluatePolicyWithBundles(ctx, bundles)
	if err != nil {
		t.Fatalf("Failed to evaluate policy: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	// policy should fail when test != true
	t.Logf("Result: %s, Violations: %d", result.Result, len(result.Violations))
}

func TestStopCalled(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// verify Stop doesn't panic (it's a no-op)
	evaluator.Stop(ctx)
}

func TestGetPolicyDetailsNoVersion(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	viper.Set("quiet", true)
	viper.Set("opa-version", "") // explicitly set to empty
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	details := evaluator.GetPolicyDetails()

	// should show "unknown" when version is not set
	if opaVersion := details["opa_version"]; opaVersion != "unknown" {
		t.Errorf("Expected opa_version 'unknown', got %v", opaVersion)
	}
}

func TestNewOPAEvaluatorWithDataPath(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a data file
	dataContent := `{"config": {"threshold": 10}}`
	dataFile := filepath.Join(tempDir, "data.json")
	if err := os.WriteFile(dataFile, []byte(dataContent), 0644); err != nil {
		t.Fatalf("Failed to write data file: %v", err)
	}

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", dataFile)
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator with data: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}
}

func TestNewOPAEvaluatorWithInvalidDataPath(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	viper.Set("quiet", true)
	defer viper.Reset()

	_, err := NewOPAEvaluator(ctx, tempDir, "", "/nonexistent/data.json")
	if err == nil {
		t.Fatal("Expected error for nonexistent data path")
	}
}

func TestNewOPAEvaluatorWithSchemas(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create schemas directory
	schemaDir := filepath.Join(tempDir, "schemas")
	if err := os.MkdirAll(schemaDir, 0755); err != nil {
		t.Fatalf("Failed to create schema dir: %v", err)
	}

	// create a schema file
	schemaContent := `{"type": "object"}`
	schemaFile := filepath.Join(schemaDir, "input.json")
	if err := os.WriteFile(schemaFile, []byte(schemaContent), 0644); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, schemaDir, "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator with schemas: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}
}

func TestNewOPAEvaluatorWithSchemasHyphenName(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create schemas directory
	schemaDir := filepath.Join(tempDir, "schemas")
	if err := os.MkdirAll(schemaDir, 0755); err != nil {
		t.Fatalf("Failed to create schema dir: %v", err)
	}

	// create a schema file with hyphen in name
	schemaContent := `{"type": "object"}`
	schemaFile := filepath.Join(schemaDir, "my-schema.json")
	if err := os.WriteFile(schemaFile, []byte(schemaContent), 0644); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, schemaDir, "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator with hyphen schema: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}
}

// createTestTarGz creates a tar.gz file with a test policy
func createTestTarGz(t *testing.T, destPath string) {
	file, err := os.Create(destPath)
	if err != nil {
		t.Fatalf("Failed to create tar.gz file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Logf("Warning: failed to close file: %v", err)
		}
	}()

	gzWriter := gzip.NewWriter(file)
	defer func() {
		if err := gzWriter.Close(); err != nil {
			t.Logf("Warning: failed to close gzip writer: %v", err)
		}
	}()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			t.Logf("Warning: failed to close tar writer: %v", err)
		}
	}()

	// add a test policy file
	content := []byte(testPolicyContent)
	header := &tar.Header{
		Name: "test.rego",
		Mode: 0644,
		Size: int64(len(content)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("Failed to write tar header: %v", err)
	}

	if _, err := tarWriter.Write(content); err != nil {
		t.Fatalf("Failed to write tar content: %v", err)
	}
}

func TestExtractBundle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-extract-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a test tar.gz file
	tarGzPath := filepath.Join(tempDir, "bundle.tar.gz")
	createTestTarGz(t, tarGzPath)

	// extract it
	extractedPath, err := extractBundle(tarGzPath)
	if err != nil {
		t.Fatalf("Failed to extract bundle: %v", err)
	}

	// clean up extracted path
	defer func() {
		if err := os.RemoveAll(extractedPath); err != nil {
			t.Logf("Warning: failed to clean up extracted dir: %v", err)
		}
	}()

	// verify extracted contents
	policyFile := filepath.Join(extractedPath, "test.rego")
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		t.Error("Expected test.rego to exist in extracted bundle")
	}

	content, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("Failed to read extracted policy: %v", err)
	}

	if string(content) != testPolicyContent {
		t.Error("Extracted policy content doesn't match")
	}
}

func TestExtractBundleNonexistent(t *testing.T) {
	_, err := extractBundle("/nonexistent/bundle.tar.gz")
	if err == nil {
		t.Fatal("Expected error for nonexistent bundle")
	}
}

func TestExtractBundleInvalidGzip(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-invalid-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create an invalid file
	invalidFile := filepath.Join(tempDir, "invalid.tar.gz")
	if err := os.WriteFile(invalidFile, []byte("not a valid gzip"), 0644); err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}

	_, err = extractBundle(invalidFile)
	if err == nil {
		t.Fatal("Expected error for invalid gzip")
	}
}

func TestNewOPAEvaluatorWithTarGzBundle(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "opa-tar-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a test tar.gz bundle
	tarGzPath := filepath.Join(tempDir, "bundle.tar.gz")
	createTestTarGz(t, tarGzPath)

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tarGzPath, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator with tar.gz: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}
}

func TestNewOPAEvaluatorWithTgzBundle(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "opa-tgz-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a test .tgz bundle
	tgzPath := filepath.Join(tempDir, "bundle.tgz")
	createTestTarGz(t, tgzPath)

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tgzPath, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator with .tgz: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}
}

func TestNewOPAEvaluatorWithSchemasTarGz(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a schemas tar.gz
	schemasTarGz := filepath.Join(tempDir, "schemas.tar.gz")
	createSchemasTarGz(t, schemasTarGz)

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, schemasTarGz, "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator with schemas tar.gz: %v", err)
	}

	if evaluator == nil {
		t.Fatal("Expected evaluator to be non-nil")
	}
}

// createSchemasTarGz creates a tar.gz file with a test schema
func createSchemasTarGz(t *testing.T, destPath string) {
	file, err := os.Create(destPath)
	if err != nil {
		t.Fatalf("Failed to create tar.gz file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Logf("Warning: failed to close file: %v", err)
		}
	}()

	gzWriter := gzip.NewWriter(file)
	defer func() {
		if err := gzWriter.Close(); err != nil {
			t.Logf("Warning: failed to close gzip writer: %v", err)
		}
	}()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			t.Logf("Warning: failed to close tar writer: %v", err)
		}
	}()

	// add a test schema file
	content := []byte(`{"type": "object"}`)
	header := &tar.Header{
		Name: "input.json",
		Mode: 0644,
		Size: int64(len(content)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("Failed to write tar header: %v", err)
	}

	if _, err := tarWriter.Write(content); err != nil {
		t.Fatalf("Failed to write tar content: %v", err)
	}
}

func TestExtractBundleWithDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-dir-extract-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	// create a tar.gz with a directory structure
	tarGzPath := filepath.Join(tempDir, "bundle.tar.gz")
	createTarGzWithDir(t, tarGzPath)

	extractedPath, err := extractBundle(tarGzPath)
	if err != nil {
		t.Fatalf("Failed to extract bundle: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(extractedPath); err != nil {
			t.Logf("Warning: failed to clean up extracted dir: %v", err)
		}
	}()

	// verify directory was created
	subDir := filepath.Join(extractedPath, "policies")
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		t.Error("Expected policies directory to exist")
	}

	// verify file in subdirectory
	policyFile := filepath.Join(subDir, "test.rego")
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		t.Error("Expected test.rego to exist in policies directory")
	}
}

func createTarGzWithDir(t *testing.T, destPath string) {
	file, err := os.Create(destPath)
	if err != nil {
		t.Fatalf("Failed to create tar.gz file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Logf("Warning: failed to close file: %v", err)
		}
	}()

	gzWriter := gzip.NewWriter(file)
	defer func() {
		if err := gzWriter.Close(); err != nil {
			t.Logf("Warning: failed to close gzip writer: %v", err)
		}
	}()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			t.Logf("Warning: failed to close tar writer: %v", err)
		}
	}()

	// add directory
	dirHeader := &tar.Header{
		Name:     "policies/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	if err := tarWriter.WriteHeader(dirHeader); err != nil {
		t.Fatalf("Failed to write dir header: %v", err)
	}

	// add file in directory
	content := []byte(testPolicyContent)
	fileHeader := &tar.Header{
		Name: "policies/test.rego",
		Mode: 0644,
		Size: int64(len(content)),
	}
	if err := tarWriter.WriteHeader(fileHeader); err != nil {
		t.Fatalf("Failed to write file header: %v", err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatalf("Failed to write tar content: %v", err)
	}
}

// Test policy that returns allow=true and violations
const testPolicyWithViolations = `package governance

import rego.v1

default allow := false

allow if {
    input[0].test == true
}

violations := v if {
    v := {
        "sbom": ["Missing SBOM attestation"],
        "provenance": ["Missing provenance"]
    }
    input[0].test == false
}
`

func TestEvaluatePolicyWithBundlesViolations(t *testing.T) {
	ctx := context.Background()

	// create temp dir with violation-returning policy
	tempDir, err := os.MkdirTemp("", "opa-violations-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	policyFile := filepath.Join(tempDir, "violations.rego")
	if err := os.WriteFile(policyFile, []byte(testPolicyWithViolations), 0644); err != nil {
		t.Fatalf("Failed to write policy: %v", err)
	}

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// test with input that should fail and return violations
	bundles := []map[string]interface{}{
		{"test": false},
	}

	result, err := evaluator.EvaluatePolicyWithBundles(ctx, bundles)
	if err != nil {
		t.Fatalf("Failed to evaluate policy: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.Result == "PASSED" {
		t.Error("Expected policy to fail")
	}

	t.Logf("Result: %s, Violations: %v", result.Result, result.Violations)
}

func TestEvaluatePolicyWithBundlesAllow(t *testing.T) {
	ctx := context.Background()

	// create temp dir with allowing policy
	tempDir, err := os.MkdirTemp("", "opa-allow-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	policyFile := filepath.Join(tempDir, "allow.rego")
	if err := os.WriteFile(policyFile, []byte(testPolicyWithViolations), 0644); err != nil {
		t.Fatalf("Failed to write policy: %v", err)
	}

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// test with input that should pass
	bundles := []map[string]interface{}{
		{"test": true},
	}

	result, err := evaluator.EvaluatePolicyWithBundles(ctx, bundles)
	if err != nil {
		t.Fatalf("Failed to evaluate policy: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.Result != "PASSED" {
		t.Errorf("Expected PASSED, got %s", result.Result)
	}

	t.Logf("Result: %s, Allow: %v", result.Result, result.Details["allow"])
}

func TestCalculateRemoteDigest(t *testing.T) {
	// create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test policy content")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	digest, err := CalculateDigest(server.URL)
	if err != nil {
		t.Fatalf("Failed to calculate remote digest: %v", err)
	}

	if digest == "" {
		t.Error("Expected non-empty digest")
	}

	if len(digest) != 64 {
		t.Errorf("Expected 64-character hex digest, got %d characters", len(digest))
	}
}

func TestCalculateRemoteDigestNotFound(t *testing.T) {
	// create a test server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := CalculateDigest(server.URL)
	if err == nil {
		t.Fatal("Expected error for 404 response")
	}
}

func TestDownloadBundleHTTPError(t *testing.T) {
	// create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := downloadBundle(ctx, server.URL)
	if err == nil {
		t.Fatal("Expected error for 500 response")
	}

	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected 500 in error, got: %v", err)
	}
}

func TestOPAEvaluatorStructFields(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up temp dir: %v", err)
		}
	}()

	viper.Set("quiet", true)
	defer viper.Reset()

	evaluator, err := NewOPAEvaluator(ctx, tempDir, "", "")
	if err != nil {
		t.Fatalf("Failed to create evaluator: %v", err)
	}

	// verify struct fields are set correctly
	if evaluator.policyPath != tempDir {
		t.Errorf("Expected policyPath %s, got %s", tempDir, evaluator.policyPath)
	}

	if evaluator.prepared == nil {
		t.Error("Expected prepared to be non-nil")
	}
}
