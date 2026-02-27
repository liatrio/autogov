package vsa

import (
	"strings"
	"testing"
	"time"

	"github.com/liatrio/autogov/pkg/attestations"
)

const (
	testImageRef          = "ghcr.io/liatrio/test-image:v1.0.0@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	testImageRef2         = "ghcr.io/test/image:v1.0.0@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	testPolicyURI         = "https://github.com/liatrio/liatrio-rego-policy-library/policies/test-policy"
	testExamplePolicyURI  = "https://example.com/policy"
	testGenerateVSAError  = "GenerateVSAWithOptions failed: %v"
	testGenerateVSAError2 = "GenerateVSA failed: %v"
)

// tests the enhanced VSA generation with v1.1 features
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
		PolicyDigest: map[string]string{
			"sha256": "abc123",
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

	// validates v1.1 compliance
	if vsa.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Expected Type to be v1, got %s", vsa.Type)
	}

	if vsa.PredicateType != attestations.PredicateTypeVSA {
		t.Errorf("Expected PredicateType to be verification_summary/v1, got %s", vsa.PredicateType)
	}

	if vsa.Predicate.SlsaVersion != "1.1" {
		t.Errorf("Expected SlsaVersion to be 1.1, got %s", vsa.Predicate.SlsaVersion)
	}

	// validates verifier version map - should only have OPA
	if vsa.Predicate.Verifier.Version["opa"] != "v0.58.0" {
		t.Errorf("Expected opa version to be v0.58.0, got %s", vsa.Predicate.Verifier.Version["opa"])
	}

	// validates input attestations
	if len(vsa.Predicate.InputAttestations) != 2 {
		t.Errorf("Expected 2 input attestations, got %d", len(vsa.Predicate.InputAttestations))
	}

	// validates policy ResourceDescriptor
	if vsa.Predicate.Policy.URI != policyURI {
		t.Errorf("Expected policy URI to be %s, got %s", policyURI, vsa.Predicate.Policy.URI)
	}

	if vsa.Predicate.Policy.Digest["sha256"] != "abc123" {
		t.Errorf("Expected policy digest to be abc123, got %s", vsa.Predicate.Policy.Digest["sha256"])
	}

	// validates TimeVerified is set as string
	if vsa.Predicate.TimeVerified == "" {
		t.Error("Expected TimeVerified to be set")
	}

	// validates verification result
	if vsa.Predicate.VerificationResult != "PASSED" {
		t.Errorf("Expected VerificationResult to be PASSED, got %s", vsa.Predicate.VerificationResult)
	}
}

// tests ResourceDescriptor functionality
func TestResourceDescriptorValidation(t *testing.T) {
	// tests w/ policy ResourceDescriptor
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

	// validates policy ResourceDescriptor
	if vsa.Predicate.Policy.URI != policyURI {
		t.Errorf("Expected policy URI %s, got %s", policyURI, vsa.Predicate.Policy.URI)
	}

	if vsa.Predicate.Policy.Digest["sha256"] != "abc123def456" {
		t.Errorf("Expected policy digest abc123def456, got %s", vsa.Predicate.Policy.Digest["sha256"])
	}
}

// tests that the original GenerateVSA function still works
func TestBackwardCompatibility(t *testing.T) {
	imageRef := testImageRef
	policyURI := testExamplePolicyURI
	verificationResults := map[string]bool{
		"slsa_build":  true,
		"attestation": true,
	}

	// original function
	vsa, err := GenerateVSA(imageRef, policyURI, verificationResults)
	if err != nil {
		t.Fatalf(testGenerateVSAError2, err)
	}

	// should still generate v1.1 compliant VSA
	if vsa.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Expected Type to be v1, got %s", vsa.Type)
	}

	if vsa.Predicate.SlsaVersion != "1.1" {
		t.Errorf("Expected SlsaVersion to be 1.1, got %s", vsa.Predicate.SlsaVersion)
	}

	// should have empty verifier version map (no additional verifiers)
	if len(vsa.Predicate.Verifier.Version) != 0 {
		t.Errorf("Expected empty verifier version map, got %v", vsa.Predicate.Verifier.Version)
	}

	// should work with existing validation
	if !vsa.IsVerificationPassed() {
		t.Error("Expected verification to be passed")
	}
}

// tests the enhanced VSA validation
func TestVSAValidation(t *testing.T) {
	// generates a test VSA
	imageRef := testImageRef
	policyURI := testExamplePolicyURI
	verificationResults := map[string]bool{"test": true}

	vsa, err := GenerateVSA(imageRef, policyURI, verificationResults)
	if err != nil {
		t.Fatalf(testGenerateVSAError2, err)
	}

	// serializes VSA
	vsaBytes, err := vsa.SerializeVSA()
	if err != nil {
		t.Fatalf("SerializeVSA failed: %v", err)
	}

	// validates VSA
	validatedVSA, err := ValidateVSA(vsaBytes)
	if err != nil {
		t.Fatalf("ValidateVSA failed: %v", err)
	}

	// checks that validation preserves all fields
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

// tests VSA validation error cases
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
			// generate a valid VSA
			vsa, err := GenerateVSA(
				testImageRef2,
				testExamplePolicyURI,
				map[string]bool{"test": true},
			)
			if err != nil {
				t.Fatalf(testGenerateVSAError2, err)
			}

			// apply modification to make it invalid
			tc.vsaModifier(vsa)

			// serialize modified VSA
			vsaBytes, err := vsa.SerializeVSA()
			if err != nil {
				t.Fatalf("SerializeVSA failed: %v", err)
			}

			// validation should fail
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

// tests optional timestamp handling
func TestVSATimestampHandling(t *testing.T) {
	opts := VSAOptions{}

	vsa, err := GenerateVSAWithOptions(
		testImageRef2,
		testExamplePolicyURI,
		map[string]bool{"test": true},
		opts,
	)
	if err != nil {
		t.Fatalf(testGenerateVSAError, err)
	}

	// should be set
	if vsa.Predicate.TimeVerified == "" {
		t.Error("Expected TimeVerified to be set")
	}

	// validate timestamp format (should be RFC3339)
	if _, err := time.Parse(time.RFC3339, vsa.Predicate.TimeVerified); err != nil {
		t.Errorf("TimeVerified should be valid RFC3339 format: %v", err)
	}
}

// tests VSA metadata handling
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

	// check metadata
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

// tests the SLSA level parsing utilities
func TestSLSALevelParsing(t *testing.T) {
	testCases := []struct {
		name               string
		trackLevels        []string
		expectedBuildTrack int
		expectedDepTrack   int
		expectError        bool
	}{
		{
			name:               "Valid build levels only",
			trackLevels:        []string{"SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_3"},
			expectedBuildTrack: 3, // should take the highest level
			expectedDepTrack:   0,
			expectError:        false,
		},
		{
			name:               "Valid dependency levels only",
			trackLevels:        []string{"SLSA_DEPENDENCY_LEVEL_1", "SLSA_DEPENDENCY_LEVEL_2"},
			expectedBuildTrack: 0,
			expectedDepTrack:   2, // should take the highest level
			expectError:        false,
		},
		{
			name:               "Mixed build and dependency levels",
			trackLevels:        []string{"SLSA_BUILD_LEVEL_2", "SLSA_DEPENDENCY_LEVEL_1", "SLSA_BUILD_LEVEL_3"},
			expectedBuildTrack: 3,
			expectedDepTrack:   1,
			expectError:        false,
		},
		{
			name:               "Mixed SLSA and custom levels",
			trackLevels:        []string{"SLSA_BUILD_LEVEL_2", "CUSTOM_LEVEL", "AUTOGOV_ATTESTATION_REQUIRED"},
			expectedBuildTrack: 2,
			expectedDepTrack:   0,
			expectError:        false,
		},
		{
			name:               "Invalid SLSA level format",
			trackLevels:        []string{"SLSA_BUILD_INVALID"},
			expectedBuildTrack: 0, // invalid format is ignored
			expectedDepTrack:   0,
			expectError:        false,
		},
		{
			name:               "Invalid SLSA level number",
			trackLevels:        []string{"SLSA_BUILD_LEVEL_ABC"},
			expectedBuildTrack: 0, // invalid number is ignored
			expectedDepTrack:   0,
			expectError:        false,
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

			if levels.BuildTrack != tc.expectedBuildTrack {
				t.Errorf("Expected BuildTrack=%d, got %d", tc.expectedBuildTrack, levels.BuildTrack)
			}

			if levels.DependencyTrack != tc.expectedDepTrack {
				t.Errorf("Expected DependencyTrack=%d, got %d", tc.expectedDepTrack, levels.DependencyTrack)
			}
		})
	}
}

// tests the SLSA track level detection
func TestIsSLSATrackLevel(t *testing.T) {
	testCases := []struct {
		name     string
		level    string
		expected bool
	}{
		{"valid build level 0", "SLSA_BUILD_LEVEL_0", true},
		{"valid build level 1", "SLSA_BUILD_LEVEL_1", true},
		{"valid build level 2", "SLSA_BUILD_LEVEL_2", true},
		{"valid build level 3", "SLSA_BUILD_LEVEL_3", true},
		{"valid dependency level 0", "SLSA_DEPENDENCY_LEVEL_0", true},
		{"valid dependency level 1", "SLSA_DEPENDENCY_LEVEL_1", true},
		{"valid dependency level 2", "SLSA_DEPENDENCY_LEVEL_2", true},
		{"valid dependency level 3", "SLSA_DEPENDENCY_LEVEL_3", true},
		{"invalid - higher level number", "SLSA_BUILD_LEVEL_4", false},
		{"invalid - source level", "SLSA_SOURCE_LEVEL_1", false},
		{"invalid - custom level", "CUSTOM_LEVEL", false},
		{"invalid - wrong format", "SLSA_INVALID_LEVEL", false},
		{"invalid - empty string", "", false},
		{"invalid - autogov level", "AUTOGOV_LEVEL_1", false},
		{"invalid - partial match", "SLSA_BUILD", false},
		{"invalid - case sensitivity", "slsa_build_level_1", false},
		{"invalid - autogov attestation", "AUTOGOV_ATTESTATION_REQUIRED", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsSLSATrackLevel(tc.level)
			if result != tc.expected {
				t.Errorf("IsSLSATrackLevel(%q) = %v, want %v", tc.level, result, tc.expected)
			}
		})
	}
}

// tests the SLSA level extraction
func TestExtractSLSALevels(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "only valid SLSA levels",
			input:    []string{"SLSA_BUILD_LEVEL_2", "SLSA_DEPENDENCY_LEVEL_1"},
			expected: []string{"SLSA_BUILD_LEVEL_2", "SLSA_DEPENDENCY_LEVEL_1"},
		},
		{
			name:     "mixed valid and invalid levels",
			input:    []string{"SLSA_BUILD_LEVEL_2", "CUSTOM_LEVEL", "SLSA_DEPENDENCY_LEVEL_1"},
			expected: []string{"SLSA_BUILD_LEVEL_2", "SLSA_DEPENDENCY_LEVEL_1"},
		},
		{
			name:     "no valid SLSA levels",
			input:    []string{"CUSTOM_LEVEL", "AUTOGOV_ATTESTATION_REQUIRED"},
			expected: []string{},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "duplicates",
			input:    []string{"SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_2"},
			expected: []string{"SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractSLSALevels(tc.input)

			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d levels, got %d", len(tc.expected), len(result))
				return
			}

			for i, expected := range tc.expected {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected level %d to be %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}
