package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test constants
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

// Test helper to create a temporary policy directory
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

func TestNewOPAEvaluator_LocalDirectory(t *testing.T) {
	ctx := context.Background()
	tempDir := createTestPolicyDir(t)
	defer os.RemoveAll(tempDir)

	evaluator, err := NewOPAEvaluator(ctx, tempDir)
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

func TestNewOPAEvaluator_InvalidDirectory(t *testing.T) {
	ctx := context.Background()
	
	_, err := NewOPAEvaluator(ctx, "/nonexistent/directory")
	if err == nil {
		t.Fatal("Expected error for nonexistent directory")
	}
}

func TestNewOPAEvaluator_EmptyDirectory(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "opa-empty-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	evaluator, err := NewOPAEvaluator(ctx, tempDir)
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// Empty directory should create evaluator with 0 policies
	if evaluator == nil {
		t.Fatal("Expected evaluator to be created even with empty directory")
	}
}

func TestLoadPoliciesFromPath_Success(t *testing.T) {
	tempDir := createTestPolicyDir(t)
	defer os.RemoveAll(tempDir)

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

func TestLoadPoliciesFromPath_NonexistentPath(t *testing.T) {
	_, err := loadPoliciesFromPath("/nonexistent/path")
	if err == nil {
		t.Fatal("Expected error for nonexistent path")
	}
}

func TestLoadPoliciesFromPath_NoRegoFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "opa-no-rego-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a non-rego file
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
	defer os.RemoveAll(tempDir)

	evaluator, err := NewOPAEvaluator(ctx, tempDir)
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
	defer os.RemoveAll(tempDir)

	evaluator, err := NewOPAEvaluator(ctx, tempDir)
	if err != nil {
		t.Fatalf("Failed to create OPA evaluator: %v", err)
	}

	// Stop should not panic or return error
	evaluator.Stop(ctx)
}

func TestPolicyViolation_JSONMarshaling(t *testing.T) {
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

func TestPolicyResult_JSONMarshaling(t *testing.T) {
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

// Test with environment variables for token authentication
func TestDownloadBundle_WithToken(t *testing.T) {
	// Skip if running in CI without network access
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	// Create a simple test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test content"))
	}))
	defer server.Close()

	// Set test token
	os.Setenv("GH_TOKEN", "test-token")
	defer os.Unsetenv("GH_TOKEN")

	ctx := context.Background()
	
	// This will fail because we're not serving a valid tar.gz, but it tests the auth logic
	_, err := downloadBundle(ctx, server.URL)
	if err == nil {
		t.Fatal("Expected error for invalid tar.gz content")
	}

	// The error should be about gzip/tar format, not authentication
	if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized") {
		t.Error("Authentication failed when token was provided")
	}
}

func TestDownloadBundle_WithoutToken(t *testing.T) {
	// Skip if running in CI without network access
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	// Create a test server that requires auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Ensure no tokens are set
	for _, key := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_AUTH_TOKEN"} {
		os.Unsetenv(key)
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
