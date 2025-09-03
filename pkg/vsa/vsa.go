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
		return nil, NewParsingError("json", "failed to unmarshal VSA", err)
	}

	if err := vsa.ValidateComprehensive(); err != nil {
		return nil, err
	}

	return &vsa, nil
}

// ValidateComprehensive performs comprehensive VSA validation
func (v *VSA) ValidateComprehensive() error {
	// Validate statement type
	if err := v.validateStatementType(); err != nil {
		return err
	}

	// Validate predicate type
	if err := v.validatePredicateType(); err != nil {
		return err
	}

	// Validate subject digests
	if err := v.validateSubjectDigests(); err != nil {
		return err
	}

	// Validate verifier
	if err := v.validateVerifier(); err != nil {
		return err
	}

	// Validate resource URI
	if err := v.validateResourceURI(); err != nil {
		return err
	}

	// Validate verification result
	if err := v.validateVerificationResult(); err != nil {
		return err
	}

	// Validate SLSA levels
	if err := v.validateSLSALevels(); err != nil {
		return err
	}

	// Validate digest formats
	if err := v.ValidateDigestFormats(); err != nil {
		return err
	}

	return nil
}

// validateStatementType validates the VSA statement type
func (v *VSA) validateStatementType() error {
	// Support both v0.1 and v1 for backward compatibility
	if v.Type != "https://in-toto.io/Statement/v1" && v.Type != "https://in-toto.io/Statement/v0.1" {
		return NewValidationError("_type", 
			fmt.Sprintf("invalid statement type: %s (expected https://in-toto.io/Statement/v1 or v0.1)", v.Type), nil)
	}
	return nil
}

// validatePredicateType validates the VSA predicate type
func (v *VSA) validatePredicateType() error {
	if v.PredicateType != "https://slsa.dev/verification_summary/v1" {
		return NewValidationError("predicateType", 
			fmt.Sprintf("invalid predicate type: %s (expected https://slsa.dev/verification_summary/v1)", v.PredicateType), nil)
	}
	return nil
}

// validateSubjectDigests validates VSA subjects have proper structure
func (v *VSA) validateSubjectDigests() error {
	if len(v.Subject) == 0 {
		return NewValidationError("subject", "no subjects found in VSA", nil)
	}

	for i, subject := range v.Subject {
		if subject.Name == "" {
			return NewValidationError("subject", 
				fmt.Sprintf("subject %d missing name", i), nil)
		}

		if len(subject.Digest) == 0 {
			return NewValidationError("subject", 
				fmt.Sprintf("subject %d missing digest", i), nil)
		}
	}

	return nil
}

// validateVerifier validates the VSA verifier
func (v *VSA) validateVerifier() error {
	if v.Predicate.Verifier.ID == "" {
		return NewValidationError("verifier", "verifier ID is required", nil)
	}

	// Validate verifier ID format (should be a URL)
	if !strings.HasPrefix(v.Predicate.Verifier.ID, "https://") {
		return NewValidationError("verifier", 
			fmt.Sprintf("verifier ID should be a URL: %s", v.Predicate.Verifier.ID), nil)
	}

	return nil
}

// validateResourceURI validates the resource URI
func (v *VSA) validateResourceURI() error {
	if v.Predicate.ResourceURI == "" {
		return NewValidationError("resourceUri", "resourceURI is required", nil)
	}
	return nil
}

// validateVerificationResult validates the verification result
func (v *VSA) validateVerificationResult() error {
	if v.Predicate.VerificationResult == "" {
		return NewValidationError("verificationResult", "verificationResult is required", nil)
	}

	if v.Predicate.VerificationResult != "PASSED" && v.Predicate.VerificationResult != "FAILED" {
		return NewValidationError("verificationResult", 
			fmt.Sprintf("invalid verificationResult: %s (must be PASSED or FAILED)", v.Predicate.VerificationResult), nil)
	}

	return nil
}

// validateSLSALevels validates SLSA level formats
func (v *VSA) validateSLSALevels() error {
	_, err := ExtractSLSATrackLevels(v.Predicate.VerifiedLevels)
	return err
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
