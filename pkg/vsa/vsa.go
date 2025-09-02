package vsa

import (
	"encoding/json"
	"fmt"
	"strings"
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

// VSAOptions provides configuration for enhanced VSA generation (SLSA v1.1)
type VSAOptions struct {
	InputAttestations   []ResourceDescriptor `json:"inputAttestations,omitempty"`
	AutoGovVersion      string               `json:"autogovVersion,omitempty"`
	PolicyDigest        map[string]string    `json:"policyDigest,omitempty"`
	Dependencies        []Dependency         `json:"dependencies,omitempty"`
	AdditionalVerifiers map[string]string    `json:"additionalVerifiers,omitempty"`
}

// Dependency represents a software dependency for SLSA level analysis
type Dependency struct {
	Name          string            `json:"name"`
	Digest        map[string]string `json:"digest"`
	URI           string            `json:"uri,omitempty"`
	VerifiedLevel string            `json:"verifiedLevel,omitempty"`
}

// GenerateVSAWithOptions creates a VSA with enhanced v1.1 features
func GenerateVSAWithOptions(imageRef string, policyURI string, verificationResults map[string]bool, opts VSAOptions) (*VSA, error) {
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

	// Determine version to use
	version := "v1.0.0"
	if opts.AutoGovVersion != "" {
		version = opts.AutoGovVersion
	}

	// Build verifier versions map
	verifierVersions := map[string]string{
		"autogov-verify": version,
	}
	for tool, ver := range opts.AdditionalVerifiers {
		verifierVersions[tool] = ver
	}

	// Analyze dependencies for SLSA levels
	dependencyLevels := analyzeDependencyLevels(opts.Dependencies)

	vsa := &VSA{
		Type:          "https://in-toto.io/Statement/v1",
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
				ID:      "https://github.com/liatrio/autogov-verify",
				Version: verifierVersions,
			},
			TimeVerified: &now,
			ResourceURI:  imageRef,
			Policy: ResourceDescriptor{
				URI:    policyURI,
				Digest: opts.PolicyDigest,
			},
			InputAttestations:  opts.InputAttestations,
			VerificationResult: result,
			VerifiedLevels: []string{
				"SLSA_BUILD_LEVEL_3",
				"AUTOGOV_ATTESTATION_REQUIRED",
				"AUTOGOV_SECURITY_CONTEXT",
			},
			DependencyLevels: dependencyLevels,
			SlsaVersion:      "1.1",
		},
		Metadata: map[string]interface{}{
			"autogov.verification.details": verificationResults,
			"autogov.policy.version":       "v1",
		},
	}

	return vsa, nil
}

// GenerateVSA creates a VSA for successful AutoGov validation (SLSA v1.1 compliant)
// This is a convenience function that calls GenerateVSAWithOptions with default options
func GenerateVSA(imageRef string, policyURI string, verificationResults map[string]bool) (*VSA, error) {
	return GenerateVSAWithOptions(imageRef, policyURI, verificationResults, VSAOptions{})
}

// analyzeDependencyLevels analyzes dependencies and counts them by SLSA level
func analyzeDependencyLevels(dependencies []Dependency) map[string]int {
	levels := make(map[string]int)

	for _, dep := range dependencies {
		if dep.VerifiedLevel != "" {
			levels[dep.VerifiedLevel]++
		}
	}

	return levels
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
	// Look for @sha256: pattern in the image reference
	parts := strings.Split(imageRef, "@sha256:")
	if len(parts) != 2 {
		return "", fmt.Errorf("no SHA256 digest found in image reference")
	}

	digest := parts[1]
	if len(digest) != 64 {
		return "", fmt.Errorf("invalid SHA256 digest length: expected 64 characters, got %d", len(digest))
	}

	return digest, nil
}

// SerializeVSA converts VSA to JSON bytes
func (v *VSA) SerializeVSA() ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// IsVerificationPassed checks if the VSA indicates successful verification
func (v *VSA) IsVerificationPassed() bool {
	return v.Predicate.VerificationResult == "PASSED"
}
