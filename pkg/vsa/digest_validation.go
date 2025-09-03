package vsa

import (
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
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
