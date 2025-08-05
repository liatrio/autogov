package vsa

import (
	"encoding/json"
	"fmt"
	"time"
)

// VSA represents a Verification Summary Attestation
// Based on the in-toto VSA specification
type VSA struct {
	Type          string                 `json:"_type"`
	PredicateType string                 `json:"predicateType"`
	Subject       []VSASubject           `json:"subject"`
	Predicate     VSAPredicate           `json:"predicate"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type VSASubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ResourceDescriptor represents a resource with URI and digest (SLSA v1.1)
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type VSAPredicate struct {
	Verifier           VSAVerifier          `json:"verifier"`
	TimeVerified       *time.Time           `json:"timeVerified,omitempty"` // Optional in v1.1
	ResourceURI        string               `json:"resourceUri"`
	Policy             ResourceDescriptor   `json:"policy"`                      // Updated to ResourceDescriptor
	InputAttestations  []ResourceDescriptor `json:"inputAttestations,omitempty"` // NEW in v1.1
	VerificationResult string               `json:"verificationResult"`          // Simplified to string
	VerifiedLevels     []string             `json:"verifiedLevels,omitempty"`
	DependencyLevels   map[string]int       `json:"dependencyLevels,omitempty"` // NEW in v1.1: count of deps at each level
	SlsaVersion        string               `json:"slsaVersion,omitempty"`      // NEW in v1.1
}

type VSAVerifier struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"` // Updated to map for multiple tool versions
}

// VSAVerificationResult is deprecated in favor of string field
// Keeping for backward compatibility during transition
type VSAVerificationResult struct {
	Result string `json:"result"` // "PASSED", "FAILED", "WARNING"
}

// VSAPolicy is deprecated in favor of ResourceDescriptor
// Keeping for backward compatibility during transition
type VSAPolicy struct {
	URI    string `json:"uri,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// GenerateVSA creates a VSA for successful AutoGov validation (SLSA v1.1 compliant)
func GenerateVSA(imageRef string, policyURI string, verificationResults map[string]bool) (*VSA, error) {
	// Parse image reference to extract digest
	digest, err := extractDigestFromImageRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to extract digest: %w", err)
	}

	// Determine overall result
	result := "PASSED"
	for _, passed := range verificationResults {
		if !passed {
			result = "FAILED"
			break
		}
	}

	// Create timestamp pointer for v1.1 compliance
	now := time.Now().UTC()

	vsa := &VSA{
		Type:          "https://in-toto.io/Statement/v1", // Updated to v1
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Subject: []VSASubject{
			{
				Name: imageRef,
				Digest: map[string]string{
					"sha256": digest,
				},
			},
		},
		Predicate: VSAPredicate{
			Verifier: VSAVerifier{
				ID: "https://github.com/liatrio/autogov-verify",
				Version: map[string]string{
					"autogov-verify": "v1.0.0", // Updated to map format
				},
			},
			TimeVerified: &now, // Updated to pointer
			ResourceURI:  imageRef,
			Policy: ResourceDescriptor{ // Updated to ResourceDescriptor
				URI: policyURI,
			},
			VerificationResult: result, // Updated to string
			VerifiedLevels: []string{
				"SLSA_BUILD_LEVEL_3",
				"AUTOGOV_ATTESTATION_REQUIRED",
				"AUTOGOV_SECURITY_CONTEXT",
			},
			SlsaVersion: "1.1", // NEW: SLSA version
		},
		Metadata: map[string]interface{}{
			"autogov.verification.details": verificationResults,
			"autogov.policy.version":       "v1",
		},
	}

	return vsa, nil
}

// ValidateVSA validates an existing VSA (SLSA v1.1 compliant)
func ValidateVSA(vsaBytes []byte) (*VSA, error) {
	var vsa VSA
	if err := json.Unmarshal(vsaBytes, &vsa); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VSA: %w", err)
	}

	// Basic validation - support both v0.1 and v1 for backward compatibility
	if vsa.Type != "https://in-toto.io/Statement/v1" && vsa.Type != "https://in-toto.io/Statement/v0.1" {
		return nil, fmt.Errorf("invalid VSA type: %s", vsa.Type)
	}

	if vsa.PredicateType != "https://slsa.dev/verification_summary/v1" {
		return nil, fmt.Errorf("invalid predicate type: %s", vsa.PredicateType)
	}

	// Validate required fields
	if vsa.Predicate.Verifier.ID == "" {
		return nil, fmt.Errorf("verifier ID is required")
	}

	if vsa.Predicate.ResourceURI == "" {
		return nil, fmt.Errorf("resourceURI is required")
	}

	if vsa.Predicate.VerificationResult == "" {
		return nil, fmt.Errorf("verificationResult is required")
	}

	// Validate verification result values
	if vsa.Predicate.VerificationResult != "PASSED" && vsa.Predicate.VerificationResult != "FAILED" {
		return nil, fmt.Errorf("invalid verificationResult: %s (must be PASSED or FAILED)", vsa.Predicate.VerificationResult)
	}

	return &vsa, nil
}

// extractDigestFromImageRef extracts SHA256 digest from image reference
func extractDigestFromImageRef(imageRef string) (string, error) {
	// This is a simplified implementation
	// In practice, you'd use proper OCI image parsing
	if len(imageRef) > 7 && imageRef[len(imageRef)-71:len(imageRef)-64] == "@sha256:" {
		return imageRef[len(imageRef)-64:], nil
	}
	return "", fmt.Errorf("no SHA256 digest found in image reference")
}

// SerializeVSA converts VSA to JSON bytes
func (v *VSA) SerializeVSA() ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// IsVerificationPassed checks if the VSA indicates successful verification
func (v *VSA) IsVerificationPassed() bool {
	return v.Predicate.VerificationResult == "PASSED"
}
