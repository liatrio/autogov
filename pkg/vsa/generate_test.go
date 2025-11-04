package vsa

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerate_PolicyFailure_FlagEnabled tests that when policy fails and flag is true,
// Generate() returns an error but VSA is still created
func TestGenerate_PolicyFailure_FlagEnabled(t *testing.T) {
	// create temp dir for VSA output
	tempDir := t.TempDir()
	vsaOutput := filepath.Join(tempDir, "test-vsa.json")

	// create test policy bundle with failing policy
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "test.rego")
	policyContent := `package governance

allow := false

violations := {"test": "Policy intentionally fails for testing"}`

	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err, "Failed to write test policy file")

	// set flag to true (opt-in strict mode)
	viper.Set("fail-on-policy-error", true)
	defer viper.Set("fail-on-policy-error", nil)

	// test options
	opts := GenerateOptions{
		ArtifactDigest:   "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		VSASubjects:      []VSASubject{{URI: "test://artifact", Digest: map[string]string{"sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}}},
		AttestationTypes: []string{"test"},
		PolicyURI:        "https://example.com/policy",
		VSAOutput:        vsaOutput,
		PolicyBundlePath: policyDir,
		Quiet:            true,
	}

	// sets offline attestations for testing
	viper.Set("offline-attestations", []map[string]interface{}{
		{
			"dsseEnvelope": map[string]interface{}{
				"payload":     "eyJ0ZXN0IjoidGVzdCJ9", // base64 encoded test data
				"payloadType": "application/vnd.in-toto+json",
			},
		},
	})
	defer viper.Set("offline-attestations", nil)

	ctx := context.Background()

	err = Generate(ctx, opts)

	// policy failures cause exit code 1
	assert.Error(t, err, "Expected error when policy fails with flag=true")
	assert.Contains(t, err.Error(), "policy evaluation failed", "Error message should indicate policy failure")
	assert.Contains(t, err.Error(), "violations", "Error message should include violation count")

	// VSA file created regardless of policy result
	assert.FileExists(t, vsaOutput, "VSA file should exist even when policy fails")

	// verifies VSA contains policy failure metadata
	vsaBytes, err := os.ReadFile(vsaOutput)
	require.NoError(t, err, "Should be able to read generated VSA")
	assert.NotEmpty(t, vsaBytes, "VSA file should not be empty")
}

// TestGenerate_PolicyFailure_FlagDisabled tests that when policy fails and flag is false (default),
// Generate() returns nil (exit 0) and VSA is created
func TestGenerate_PolicyFailure_FlagDisabled(t *testing.T) {
	// create temp dir for VSA output
	tempDir := t.TempDir()
	vsaOutput := filepath.Join(tempDir, "test-vsa.json")

	// create test policy bundle with failing policy
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "test.rego")
	policyContent := `package governance

allow := false

violations := {"test": "Policy intentionally fails for testing"}`

	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err, "Failed to write test policy file")

	// sets flag to false (default behavior - permissive mode)
	viper.Set("fail-on-policy-error", false)
	defer viper.Set("fail-on-policy-error", nil)

	// test options
	opts := GenerateOptions{
		ArtifactDigest:   "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		VSASubjects:      []VSASubject{{URI: "test://artifact2", Digest: map[string]string{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}}},
		AttestationTypes: []string{"test"},
		PolicyURI:        "https://example.com/policy",
		VSAOutput:        vsaOutput,
		PolicyBundlePath: policyDir,
		Quiet:            true, // Quiet mode to avoid checking stdout
	}

	// sets offline attestations for testing
	viper.Set("offline-attestations", []map[string]interface{}{
		{
			"dsseEnvelope": map[string]interface{}{
				"payload":     "eyJ0ZXN0IjoidGVzdCJ9",
				"payloadType": "application/vnd.in-toto+json",
			},
		},
	})
	defer viper.Set("offline-attestations", nil)

	ctx := context.Background()

	err = Generate(ctx, opts)

	// app exits with code 0 (success)
	assert.NoError(t, err, "Expected no error when policy fails with flag=false")

	// VSA file created
	assert.FileExists(t, vsaOutput, "VSA file should exist when policy fails with flag=false")

	// verifies VSA contains policy failure in metadata
	vsaBytes, err := os.ReadFile(vsaOutput)
	require.NoError(t, err, "Should be able to read generated VSA")
	assert.NotEmpty(t, vsaBytes, "VSA file should not be empty")

	// verifies VSA contains FAILED status
	vsa, err := ValidateVSA(vsaBytes)
	require.NoError(t, err, "VSA should be valid")

	// checks policy metadata
	if vsa.Metadata != nil {
		if policyEval, ok := vsa.Metadata["autogov.policy.evaluation"]; ok {
			evalMap, ok := policyEval.(map[string]interface{})
			assert.True(t, ok, "Policy evaluation metadata should be a map")
			assert.Equal(t, "FAILED", evalMap["result"], "Policy result should be FAILED in metadata")
		}
	}
}

// TestGenerate_PolicyPass_FlagDisabled tests that when policy passes with flag disabled,
// no warnings are logged and Generate() returns nil
func TestGenerate_PolicyPass_FlagDisabled(t *testing.T) {
	// create temp dir for VSA output
	tempDir := t.TempDir()
	vsaOutput := filepath.Join(tempDir, "test-vsa.json")

	// create test policy bundle w/ passing policy
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "test.rego")
	policyContent := `package governance

allow := true

violations := {}`

	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err, "Failed to write test policy file")

	// set flag to false
	viper.Set("fail-on-policy-error", false)
	defer viper.Set("fail-on-policy-error", nil)

	// setup test options
	opts := GenerateOptions{
		ArtifactDigest:   "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
		VSASubjects:      []VSASubject{{URI: "test://artifact3", Digest: map[string]string{"sha256": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"}}},
		AttestationTypes: []string{"test"},
		PolicyURI:        "https://example.com/policy",
		VSAOutput:        vsaOutput,
		PolicyBundlePath: policyDir,
		Quiet:            true,
	}

	// set offline attestations for testing
	viper.Set("offline-attestations", []map[string]interface{}{
		{
			"dsseEnvelope": map[string]interface{}{
				"payload":     "eyJ0ZXN0IjoidGVzdCJ9",
				"payloadType": "application/vnd.in-toto+json",
			},
		},
	})
	defer viper.Set("offline-attestations", nil)

	ctx := context.Background()

	err = Generate(ctx, opts)

	// asserts policy passed, no errors regardless of flag
	assert.NoError(t, err, "Expected no error when policy passes")

	// VSA file should exist
	assert.FileExists(t, vsaOutput, "VSA file should exist when policy passes")

	// verifies VSA contains PASSED status
	vsaBytes, err := os.ReadFile(vsaOutput)
	require.NoError(t, err, "Should be able to read generated VSA")

	vsa, err := ValidateVSA(vsaBytes)
	require.NoError(t, err, "VSA should be valid")

	// checks policy metadata shows PASSED
	if vsa.Metadata != nil {
		if policyEval, ok := vsa.Metadata["autogov.policy.evaluation"]; ok {
			evalMap, ok := policyEval.(map[string]interface{})
			assert.True(t, ok, "Policy evaluation metadata should be a map")
			assert.Equal(t, "PASSED", evalMap["result"], "Policy result should be PASSED in metadata")
		}
	}
}

// TestGenerate_PolicyFailure_FlagUnset verifies default behavior when flag is not set
// When flag is unset: viper.GetBool returns false, policy fails → exit code 0, VSA created
func TestGenerate_PolicyFailure_FlagUnset(t *testing.T) {
	// create temp dir for VSA output
	tempDir := t.TempDir()
	vsaOutput := filepath.Join(tempDir, "test-vsa.json")

	// create test policy bundle with failing policy
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "test.rego")
	policyContent := `package governance

allow := false

violations := {"flag_unset_test": "Policy fails with unset flag"}`

	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err, "Failed to write test policy file")

	// DO NOT set the flag - test default behavior (should be false)
	// Note: viper.GetBool returns false for unset values, which matches our default

	// test options
	opts := GenerateOptions{
		ArtifactDigest:   "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		VSASubjects:      []VSASubject{{URI: "test://compat", Digest: map[string]string{"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}},
		AttestationTypes: []string{"test"},
		PolicyURI:        "https://example.com/policy",
		VSAOutput:        vsaOutput,
		PolicyBundlePath: policyDir,
		Quiet:            true,
	}

	// sets offline attestations for testing
	viper.Set("offline-attestations", []map[string]interface{}{
		{
			"dsseEnvelope": map[string]interface{}{
				"payload":     "eyJ0ZXN0IjoidGVzdCJ9",
				"payloadType": "application/vnd.in-toto+json",
			},
		},
	})
	defer viper.Set("offline-attestations", nil)

	ctx := context.Background()

	err = Generate(ctx, opts)

	// assert default behavior (unset flag) should NOT fail on policy error
	assert.NoError(t, err, "Expected no error when flag is unset (defaults to false)")

	// VSA should be created with default behavior
	assert.FileExists(t, vsaOutput, "VSA file should exist when flag is unset")
}
