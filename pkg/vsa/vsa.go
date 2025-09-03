// Package vsa - vsa.go
// Core VSA types, structures, and generation functions.
// Contains the main VSA data structures and factory functions for creating VSAs.

package vsa

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VSA represents a Verification Summary Attestation
// Based on the in-toto VSA specification and SLSA v1.1
type VSA struct {
	Type          string                 `json:"_type"`
	PredicateType string                 `json:"predicateType"`
	Subject       []VSASubject           `json:"subject"`
	Predicate     VSAPredicate           `json:"predicate"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type VSASubject struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

// ResourceDescriptor represents a resource with URI and digest (SLSA v1.1)
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// VSAPolicy represents policy information (supports both content and URI)
type VSAPolicy struct {
	Content string            `json:"content,omitempty"` // Policy content (e.g., Datalog, Rego)
	URI     string            `json:"uri,omitempty"`     // Policy URI
	Digest  map[string]string `json:"digest,omitempty"`  // Policy digest
}

// VSALevel represents a verified SLSA level (for internal use only)
// The actual VSA predicate uses string array for verifiedLevels per spec
type VSALevel struct {
	Level string `json:"level"`           // e.g., "SLSA_BUILD_LEVEL_3"
	Track string `json:"track,omitempty"` // e.g., "BUILD", "SOURCE"
}

// UnmarshalJSON implements custom JSON unmarshaling for backward compatibility
// Supports both string format (legacy) and object format (new)
func (v *VSALevel) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first (legacy format)
	var levelStr string
	if err := json.Unmarshal(data, &levelStr); err == nil {
		// Parse the string format to extract track if present
		if strings.HasPrefix(levelStr, "SLSA_BUILD_LEVEL_") {
			v.Level = levelStr
			v.Track = "BUILD"
		} else {
			v.Level = levelStr
		}
		return nil
	}

	// Try to unmarshal as object (new format)
	type Alias VSALevel
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(v),
	}
	return json.Unmarshal(data, aux)
}

type VSAPredicate struct {
	Verifier           VSAVerifier          `json:"verifier"`
	TimeVerified       string               `json:"timeVerified"` // ISO 8601 timestamp
	ResourceURI        string               `json:"resourceUri"`
	Policy             VSAPolicy            `json:"policy"`                      // Support both content and URI
	InputAttestations  []ResourceDescriptor `json:"inputAttestations,omitempty"` // NEW in v1.1
	VerificationResult string               `json:"verificationResult"`          // PASSED or FAILED
	VerifiedLevels     []string             `json:"verifiedLevels,omitempty"`    // SLSA levels achieved (spec: array of strings)
	DependencyLevels   map[string]uint64    `json:"dependencyLevels,omitempty"`  // NEW in v1.1: count of deps at each level
	SlsaVersion        string               `json:"slsaVersion,omitempty"`       // NEW in v1.1
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

	// Note: Dependency level analysis moved to policy evaluation layer
	dependencyLevels := make(map[string]uint64) // Empty map for backward compatibility

	vsa := &VSA{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Subject: []VSASubject{
			{
				URI: imageRef,
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
			TimeVerified: now.Format(time.RFC3339),
			ResourceURI:  imageRef,
			Policy: VSAPolicy{
				URI:    policyURI,
				Digest: opts.PolicyDigest,
			},
			InputAttestations:  opts.InputAttestations,
			VerificationResult: result,
			VerifiedLevels: []string{
				"SLSA_BUILD_LEVEL_3",
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
