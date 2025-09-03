package vsa

import (
	"strings"
	"testing"
	"time"
)

// Test constants to reduce duplication
const (
	testImageRef = "ghcr.io/liatrio/test-image:v1.0.0@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	testImageRef2 = "ghcr.io/test/image:v1.0.0@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	testImageDigest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	testPolicyURI = "https://github.com/liatrio/liatrio-rego-policy-library/policies/test-policy"
	testExamplePolicyURI = "https://example.com/policy"
	testAutoGovVersion = "v1.1.0"
	testVerifierID = "autogov-verify"
	testGenerateVSAError = "GenerateVSAWithOptions failed: %v"
	testGenerateVSAError2 = "GenerateVSA failed: %v"
)

// TestGenerateVSAWithOptions tests the enhanced VSA generation with v1.1 features
func TestGenerateVSAWithOptions(t *testing.T) {
	imageRef := testImageRef
	policyURI := testPolicyURI
	verificationResults := map[string]bool{
		"slsa_build":    true,
		"attestation":   true,
		"vulnerability": true,
	}

	opts := VSAOptions{
		InputAttestations: []ResourceDescriptor{
			{
				URI: "https://example.com/attestation1",
				Digest: map[string]string{
					"sha256": "abc123def456",
				},
			},
			{
				URI: "https://example.com/attestation2",
				Digest: map[string]string{
					"sha256": "def456ghi789",
				},
			},
		},
		AutoGovVersion: testAutoGovVersion,
		PolicyDigest: map[string]string{
			"sha256": "policy123hash456",
		},
		Dependencies: []Dependency{
			{
				Name: "test-dependency-1",
				Digest: map[string]string{
					"sha256": "dep1hash123",
				},
				URI:           "https://example.com/dep1",
				VerifiedLevel: "SLSA_BUILD_LEVEL_2",
			},
			{
				Name: "test-dependency-2",
				Digest: map[string]string{
					"sha256": "dep2hash456",
				},
				URI:           "https://example.com/dep2",
				VerifiedLevel: "SLSA_BUILD_LEVEL_3",
			},
		},
		AdditionalVerifiers: map[string]string{
			"opa": "v0.58.0",
		},
	}

	vsa, err := GenerateVSAWithOptions(imageRef, policyURI, verificationResults, opts)
	if err != nil {
		t.Fatalf(testGenerateVSAError, err)
	}

	// Validate v1.1 compliance
	if vsa.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Expected Type to be v1, got %s", vsa.Type)
	}

	if vsa.PredicateType != "https://slsa.dev/verification_summary/v1" {
		t.Errorf("Expected PredicateType to be verification_summary/v1, got %s", vsa.PredicateType)
	}

	if vsa.Predicate.SlsaVersion != "1.1" {
		t.Errorf("Expected SlsaVersion to be 1.1, got %s", vsa.Predicate.SlsaVersion)
	}

	// Validate verifier version map
	if len(vsa.Predicate.Verifier.Version) == 0 {
		t.Error("Expected verifier versions to be populated")
	}

	if vsa.Predicate.Verifier.Version[testVerifierID] != testAutoGovVersion {
		t.Errorf("Expected autogov-verify version to be %s, got %s", testAutoGovVersion, vsa.Predicate.Verifier.Version[testVerifierID])
	}

	if vsa.Predicate.Verifier.Version["opa"] != "v0.58.0" {
		t.Errorf("Expected opa version to be v0.58.0, got %s", vsa.Predicate.Verifier.Version["opa"])
	}

	// Validate input attestations
	if len(vsa.Predicate.InputAttestations) != 2 {
		t.Errorf("Expected 2 input attestations, got %d", len(vsa.Predicate.InputAttestations))
	}

	// Validate policy ResourceDescriptor
	if vsa.Predicate.Policy.URI != policyURI {
		t.Errorf("Expected policy URI to be %s, got %s", policyURI, vsa.Predicate.Policy.URI)
	}

	if vsa.Predicate.Policy.Digest["sha256"] != "policy123hash456" {
		t.Errorf("Expected policy digest to be policy123hash456, got %s", vsa.Predicate.Policy.Digest["sha256"])
	}

	// Validate TimeVerified is set as string
	if vsa.Predicate.TimeVerified == "" {
		t.Error("Expected TimeVerified to be set")
	}

	// Validate verification result
	if vsa.Predicate.VerificationResult != "PASSED" {
		t.Errorf("Expected VerificationResult to be PASSED, got %s", vsa.Predicate.VerificationResult)
	}
}

// TestSLSALevelParsing tests the SLSA level parsing utilities
func TestSLSALevelParsing(t *testing.T) {
	testCases := []struct {
		name           string
		trackLevels    []string
		expectedLevels map[string]int
		expectError    bool
	}{
		{
			name:        "Valid SLSA levels",
			trackLevels: []string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_1", "SLSA_BUILD_LEVEL_3"},
			expectedLevels: map[string]int{
				"BUILD":  3, // Should take the highest level
				"SOURCE": 1,
			},
			expectError: false,
		},
		{
			name:        "Mixed SLSA and custom levels",
			trackLevels: []string{"SLSA_BUILD_LEVEL_2", "CUSTOM_LEVEL", "AUTOGOV_ATTESTATION_REQUIRED"},
			expectedLevels: map[string]int{
				"BUILD": 2,
			},
			expectError: false,
		},
		{
			name:        "Invalid SLSA level format",
			trackLevels: []string{"SLSA_BUILD_INVALID"},
			expectError: true,
		},
		{
			name:        "Invalid SLSA level number",
			trackLevels: []string{"SLSA_BUILD_LEVEL_ABC"},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			levels, err := ExtractSLSATrackLevels(tc.trackLevels)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(levels) != len(tc.expectedLevels) {
				t.Errorf("Expected %d levels, got %d", len(tc.expectedLevels), len(levels))
			}

			for track, expectedLevel := range tc.expectedLevels {
				if levels[track] != expectedLevel {
					t.Errorf("Expected level %d for track %s, got %d", expectedLevel, track, levels[track])
				}
			}
		})
	}
}

// TestIsSLSATrackLevel tests the SLSA track level detection
func TestIsSLSATrackLevel(t *testing.T) {
	testCases := []struct {
		level    string
		expected bool
	}{
		{"SLSA_BUILD_LEVEL_2", true},
		{"SLSA_SOURCE_LEVEL_1", true},
		{"CUSTOM_LEVEL", false},
		{"AUTOGOV_ATTESTATION_REQUIRED", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.level, func(t *testing.T) {
			result := IsSLSATrackLevel(tc.level)
			if result != tc.expected {
				t.Errorf("Expected %v for level %s, got %v", tc.expected, tc.level, result)
			}
		})
	}
}

// TestResourceDescriptorValidation tests ResourceDescriptor functionality
func TestResourceDescriptorValidation(t *testing.T) {
	// Test with policy ResourceDescriptor
	policyURI := testExamplePolicyURI
	policyDigest := map[string]string{
		"sha256": "abc123def456",
	}

	opts := VSAOptions{
		PolicyDigest: policyDigest,
	}

	vsa, err := GenerateVSAWithOptions(
		testImageRef2,
		policyURI,
		map[string]bool{"test": true},
		opts,
	)
	if err != nil {
		t.Fatalf(testGenerateVSAError, err)
	}

	// Validate policy ResourceDescriptor
	if vsa.Predicate.Policy.URI != policyURI {
		t.Errorf("Expected policy URI %s, got %s", policyURI, vsa.Predicate.Policy.URI)
	}

	if vsa.Predicate.Policy.Digest["sha256"] != "abc123def456" {
		t.Errorf("Expected policy digest abc123def456, got %s", vsa.Predicate.Policy.Digest["sha256"])
	}
}

// TestBackwardCompatibility tests that the original GenerateVSA function still works
func TestBackwardCompatibility(t *testing.T) {
	imageRef := testImageRef
	policyURI := testExamplePolicyURI
	verificationResults := map[string]bool{
		"slsa_build":  true,
		"attestation": true,
	}

	// Test original function
	vsa, err := GenerateVSA(imageRef, policyURI, verificationResults)
	if err != nil {
		t.Fatalf(testGenerateVSAError2, err)
	}

	// Should still generate v1.1 compliant VSA
	if vsa.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Expected Type to be v1, got %s", vsa.Type)
	}

	if vsa.Predicate.SlsaVersion != "1.1" {
		t.Errorf("Expected SlsaVersion to be 1.1, got %s", vsa.Predicate.SlsaVersion)
	}

	// Should have default verifier version
	if vsa.Predicate.Verifier.Version[testVerifierID] != "v1.0.0" {
		t.Errorf("Expected default autogov-verify version to be v1.0.0, got %s", vsa.Predicate.Verifier.Version[testVerifierID])
	}

	// Should work with existing validation
	if !vsa.IsVerificationPassed() {
		t.Error("Expected verification to be passed")
	}
}

// TestVSAValidation tests the enhanced VSA validation
func TestVSAValidation(t *testing.T) {
	// Generate a test VSA
	imageRef := testImageRef
	policyURI := testExamplePolicyURI
	verificationResults := map[string]bool{"test": true}

	vsa, err := GenerateVSA(imageRef, policyURI, verificationResults)
	if err != nil {
		t.Fatalf(testGenerateVSAError2, err)
	}

	// Serialize VSA
	vsaBytes, err := vsa.SerializeVSA()
	if err != nil {
		t.Fatalf("SerializeVSA failed: %v", err)
	}

	// Validate VSA
	validatedVSA, err := ValidateVSA(vsaBytes)
	if err != nil {
		t.Fatalf("ValidateVSA failed: %v", err)
	}

	// Check that validation preserves all fields
	if validatedVSA.Type != vsa.Type {
		t.Errorf("Type mismatch after validation: expected %s, got %s", vsa.Type, validatedVSA.Type)
	}

	if validatedVSA.PredicateType != vsa.PredicateType {
		t.Errorf("PredicateType mismatch after validation: expected %s, got %s", vsa.PredicateType, validatedVSA.PredicateType)
	}

	if validatedVSA.Predicate.VerificationResult != vsa.Predicate.VerificationResult {
		t.Errorf("VerificationResult mismatch after validation: expected %s, got %s", vsa.Predicate.VerificationResult, validatedVSA.Predicate.VerificationResult)
	}
}

// TestVSAValidationErrors tests VSA validation error cases
func TestVSAValidationErrors(t *testing.T) {
	testCases := []struct {
		name        string
		vsaModifier func(*VSA)
		expectError string
	}{
		{
			name: "Missing verifier ID",
			vsaModifier: func(vsa *VSA) {
				vsa.Predicate.Verifier.ID = ""
			},
			expectError: "verifier ID is required",
		},
		{
			name: "Missing resource URI",
			vsaModifier: func(vsa *VSA) {
				vsa.Predicate.ResourceURI = ""
			},
			expectError: "resourceURI is required",
		},
		{
			name: "Invalid verification result",
			vsaModifier: func(vsa *VSA) {
				vsa.Predicate.VerificationResult = "INVALID"
			},
			expectError: "invalid verificationResult",
		},
		{
			name: "Invalid VSA type",
			vsaModifier: func(vsa *VSA) {
				vsa.Type = "invalid-type"
			},
			expectError: "invalid statement type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a valid VSA
			vsa, err := GenerateVSA(
				testImageRef2,
				testExamplePolicyURI,
				map[string]bool{"test": true},
			)
			if err != nil {
				t.Fatalf(testGenerateVSAError2, err)
			}

			// Apply modification to make it invalid
			tc.vsaModifier(vsa)

			// Serialize modified VSA
			vsaBytes, err := vsa.SerializeVSA()
			if err != nil {
				t.Fatalf("SerializeVSA failed: %v", err)
			}

			// Validation should fail
			_, err = ValidateVSA(vsaBytes)
			if err == nil {
				t.Error("Expected validation to fail but it passed")
			}

			if !strings.Contains(err.Error(), tc.expectError) {
				t.Errorf("Expected error to contain '%s', got '%s'", tc.expectError, err.Error())
			}
		})
	}
}

// TestVSATimestampHandling tests optional timestamp handling
func TestVSATimestampHandling(t *testing.T) {
	opts := VSAOptions{
		AutoGovVersion: testAutoGovVersion,
	}

	vsa, err := GenerateVSAWithOptions(
		testImageRef2,
		testExamplePolicyURI,
		map[string]bool{"test": true},
		opts,
	)
	if err != nil {
		t.Fatalf(testGenerateVSAError, err)
	}

	// TimeVerified should be set
	if vsa.Predicate.TimeVerified == "" {
		t.Error("Expected TimeVerified to be set")
	}

	// Validate timestamp format (should be RFC3339)
	if _, err := time.Parse(time.RFC3339, vsa.Predicate.TimeVerified); err != nil {
		t.Errorf("TimeVerified should be valid RFC3339 format: %v", err)
	}
}

// TestVSAMetadata tests VSA metadata handling
func TestVSAMetadata(t *testing.T) {
	verificationResults := map[string]bool{
		"attestation.slsa_build": true,
		"policy.security_check":  true,
	}

	vsa, err := GenerateVSA(
		testImageRef2,
		testExamplePolicyURI,
		verificationResults,
	)
	if err != nil {
		t.Fatalf(testGenerateVSAError2, err)
	}

	// Check metadata
	if vsa.Metadata == nil {
		t.Error("Expected metadata to be set")
	}

	if details, ok := vsa.Metadata["autogov.verification.details"]; !ok {
		t.Error("Expected verification details in metadata")
	} else {
		detailsMap, ok := details.(map[string]bool)
		if !ok {
			t.Error("Expected verification details to be map[string]bool")
		} else {
			if !detailsMap["attestation.slsa_build"] {
				t.Error("Expected attestation.slsa_build to be true in metadata")
			}
		}
	}
}
