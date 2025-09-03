// Package vsa - validation.go
// Contains all VSA validation logic and comprehensive validation functions.
// Consolidates validation methods for better organization and maintainability.

package vsa

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DigestSet represents a collection of digests organized by algorithm
type DigestSet map[string]map[string]bool

// ValidateDigests validates that expected digests are present in VSA subjects
// Supports multiple digest formats: sha256:abc123, sha1:def456, etc.
func (v *VSA) ValidateDigests(expectedDigests []string) error {
	if len(expectedDigests) == 0 {
		return NewValidationError("digest", "no expected digests provided", nil)
	}

	// Collect all VSA subject digests by algorithm
	vsaDigests := make(DigestSet)
	for _, subject := range v.Subject {
		for alg, digest := range subject.Digest {
			if _, ok := vsaDigests[alg]; !ok {
				vsaDigests[alg] = make(map[string]bool)
			}
			vsaDigests[alg][digest] = true
		}
	}

	if len(vsaDigests) == 0 {
		return NewValidationError("digest", "no subject digests found in VSA", nil)
	}

	// Validate each expected digest
	for _, expected := range expectedDigests {
		if err := v.validateSingleDigest(expected, vsaDigests); err != nil {
			return err
		}
	}

	return nil
}

// validateSingleDigest validates a single digest against the VSA digest set
func (v *VSA) validateSingleDigest(expected string, vsaDigests DigestSet) error {
	parts := strings.SplitN(expected, ":", 2)
	if len(parts) != 2 {
		return NewValidationError("digest",
			fmt.Sprintf("invalid digest format: %s (expected <algorithm>:<digest>)", expected), nil)
	}

	alg, digest := parts[0], parts[1]

	// Validate algorithm exists
	algDigests, algExists := vsaDigests[alg]
	if !algExists {
		return NewValidationError("digest",
			fmt.Sprintf("digest algorithm not found in VSA: %s", alg), nil)
	}

	// Validate specific digest exists
	if !algDigests[digest] {
		return NewValidationError("digest",
			fmt.Sprintf("digest not found: %s", expected), nil)
	}

	return nil
}

// GetSupportedDigestAlgorithms returns the digest algorithms present in VSA subjects
func (v *VSA) GetSupportedDigestAlgorithms() []string {
	algSet := make(map[string]bool)

	for _, subject := range v.Subject {
		for alg := range subject.Digest {
			algSet[alg] = true
		}
	}

	var algorithms []string
	for alg := range algSet {
		algorithms = append(algorithms, alg)
	}

	return algorithms
}

// ValidateDigestFormats validates that all digests in VSA subjects have proper format
func (v *VSA) ValidateDigestFormats() error {
	for i, subject := range v.Subject {
		for alg, digest := range subject.Digest {
			if err := validateDigestFormat(alg, digest); err != nil {
				return NewValidationError("digest",
					fmt.Sprintf("invalid digest format in subject %d: %s:%s", i, alg, digest), err)
			}
		}
	}

	return nil
}

// validateDigestFormat validates digest format based on algorithm
func validateDigestFormat(algorithm, digest string) error {
	if digest == "" {
		return fmt.Errorf("empty digest value")
	}

	// Basic format validation based on common algorithms
	switch algorithm {
	case "sha256":
		if len(digest) != 64 {
			return fmt.Errorf("invalid SHA256 digest length: expected 64 characters, got %d", len(digest))
		}
	case "sha1":
		if len(digest) != 40 {
			return fmt.Errorf("invalid SHA1 digest length: expected 40 characters, got %d", len(digest))
		}
	case "sha512":
		if len(digest) != 128 {
			return fmt.Errorf("invalid SHA512 digest length: expected 128 characters, got %d", len(digest))
		}
	case "md5":
		if len(digest) != 32 {
			return fmt.Errorf("invalid MD5 digest length: expected 32 characters, got %d", len(digest))
		}
	default:
		// For unknown algorithms, just check it's not empty and is hex
		if !isHexString(digest) {
			return fmt.Errorf("digest contains non-hexadecimal characters")
		}
	}

	return nil
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
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
		if subject.URI == "" {
			return NewValidationError("subject",
				fmt.Sprintf("subject %d missing URI", i), nil)
		}

		// Digest is optional for some subject types (e.g., repositories)
		// but recommended for artifacts
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
	// Convert VSALevel slice to string slice for compatibility
	levelStrings := make([]string, len(v.Predicate.VerifiedLevels))
	for i, level := range v.Predicate.VerifiedLevels {
		levelStrings[i] = level.Level
	}

	_, err := ExtractSLSATrackLevels(levelStrings)
	return err
}
