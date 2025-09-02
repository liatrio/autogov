package vsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"
)

// VSAVerificationOptions contains options for VSA verification
type VSAVerificationOptions struct {
	PublicKey         crypto.PublicKey
	PublicKeyID       *string
	PublicKeyHashAlgo crypto.Hash
}

// VSAValidationOptions contains expected values for VSA validation
type VSAValidationOptions struct {
	ExpectedDigests        []string
	ExpectedVerifierID     string
	ExpectedResourceURI    string
	ExpectedVerifiedLevels []string
}

// matchExpectedValues checks if the expected values are present in the VSA
// Adapted from slsa-verifier/verifiers/internal/vsa/verifier.go
func matchExpectedValues(vsa *VSA, validationOpts VSAValidationOptions) error {
	// Match expected subject digests
	if err := matchExpectedSubjectDigests(vsa, validationOpts.ExpectedDigests); err != nil {
		return err
	}

	// Match verifier ID
	if err := matchVerifierID(vsa, validationOpts.ExpectedVerifierID); err != nil {
		return err
	}

	// Match expected resourceURI
	if err := matchResourceURI(vsa, validationOpts.ExpectedResourceURI); err != nil {
		return err
	}

	// Confirm verification result is PASSED
	if err := confirmVerificationResult(vsa); err != nil {
		return err
	}

	// Match verified levels
	if err := matchVerifiedLevels(vsa, validationOpts.ExpectedVerifiedLevels); err != nil {
		return err
	}

	return nil
}

// matchExpectedSubjectDigests checks if the expected subject digests are present in the VSA
// Adapted from slsa-verifier/verifiers/internal/vsa/verifier.go
func matchExpectedSubjectDigests(vsa *VSA, expectedDigests []string) error {
	if len(expectedDigests) == 0 {
		return fmt.Errorf("no subject digests provided")
	}

	// Collect all digests from the VSA for efficient searching
	allVSASubjectDigests := make(map[string]map[string]bool)
	for _, subject := range vsa.Subject {
		for digestType, digestValue := range subject.Digest {
			if _, ok := allVSASubjectDigests[digestType]; !ok {
				allVSASubjectDigests[digestType] = make(map[string]bool)
			}
			allVSASubjectDigests[digestType][digestValue] = true
		}
	}

	if len(allVSASubjectDigests) == 0 {
		return fmt.Errorf("no subject digests found in the VSA")
	}

	// Search for the expected digests in the VSA
	for _, expectedDigest := range expectedDigests {
		parts := strings.SplitN(expectedDigest, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("expected digest %s is not in the format <digest type>:<digest value>", expectedDigest)
		}
		digestType := parts[0]
		digestValue := parts[1]

		if _, ok := allVSASubjectDigests[digestType]; !ok {
			return fmt.Errorf("expected digest not found: %s", expectedDigest)
		}
		if _, ok := allVSASubjectDigests[digestType][digestValue]; !ok {
			return fmt.Errorf("expected digest not found: %s", expectedDigest)
		}
	}

	return nil
}

// matchVerifierID checks if the verifier ID in the VSA matches the expected value
func matchVerifierID(vsa *VSA, expectedVerifierID string) error {
	if vsa.Predicate.Verifier.ID == "" {
		return fmt.Errorf("no verifierID found in the VSA")
	}
	if expectedVerifierID != vsa.Predicate.Verifier.ID {
		return fmt.Errorf("verifier ID mismatch: wanted %s, got %s", expectedVerifierID, vsa.Predicate.Verifier.ID)
	}
	return nil
}

// matchResourceURI checks if the resource URI in the VSA matches the expected value
func matchResourceURI(vsa *VSA, expectedResourceURI string) error {
	if vsa.Predicate.ResourceURI == "" {
		return fmt.Errorf("no resourceURI provided")
	}
	if expectedResourceURI != vsa.Predicate.ResourceURI {
		return fmt.Errorf("resource URI mismatch: wanted %s, got %s", expectedResourceURI, vsa.Predicate.ResourceURI)
	}
	return nil
}

// confirmVerificationResult checks that the policy verification result is "PASSED"
func confirmVerificationResult(vsa *VSA) error {
	if vsa.Predicate.VerificationResult != "PASSED" {
		return fmt.Errorf("verification result is not PASSED: %s", vsa.Predicate.VerificationResult)
	}
	return nil
}

// matchVerifiedLevels checks if the verified levels in the VSA match the expected values
// Adapted from slsa-verifier/verifiers/internal/vsa/verifier.go
func matchVerifiedLevels(vsa *VSA, expectedVerifiedLevels []string) error {
	// Check for SLSA track levels
	wantedSLSALevels, err := ExtractSLSALevels(expectedVerifiedLevels)
	if err != nil {
		return err
	}

	gotSLSALevels, err := ExtractSLSALevels(vsa.Predicate.VerifiedLevels)
	if err != nil {
		return err
	}

	for track, expectedMinSLSALevel := range wantedSLSALevels {
		if vsaLevel, exists := gotSLSALevels[track]; !exists {
			return fmt.Errorf("expected SLSA level not found: %s", track)
		} else if vsaLevel < expectedMinSLSALevel {
			return fmt.Errorf("expected SLSA level %s to be at least %d, got %d", track, expectedMinSLSALevel, vsaLevel)
		}
	}

	// Check for non-SLSA track levels
	nonSLSAVSALevels := make(map[string]bool)
	for _, level := range vsa.Predicate.VerifiedLevels {
		if IsSLSATrackLevel(level) {
			continue
		}
		nonSLSAVSALevels[level] = true
	}

	for _, expectedLevel := range expectedVerifiedLevels {
		if IsSLSATrackLevel(expectedLevel) {
			continue
		}
		if _, ok := nonSLSAVSALevels[expectedLevel]; !ok {
			return fmt.Errorf("expected verified level not found: %s", expectedLevel)
		}
	}

	return nil
}

// ExtractSLSALevels extracts the SLSA levels from the verified levels
// Adapted from slsa-verifier/verifiers/internal/vsa/verifier.go
func ExtractSLSALevels(trackLevels []string) (map[string]int, error) {
	vsaSLSATrackLadder := make(map[string]int)
	for _, trackLevel := range trackLevels {
		if !strings.HasPrefix(trackLevel, "SLSA_") {
			continue
		}
		parts := strings.SplitN(trackLevel, "_", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid SLSA level: %s", trackLevel)
		}
		if parts[2] != "LEVEL" {
			return nil, fmt.Errorf("invalid SLSA level: %s", trackLevel)
		}
		track := parts[1]
		level, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid SLSA level: %s", trackLevel)
		}
		if currentLevel, exists := vsaSLSATrackLadder[track]; exists {
			vsaSLSATrackLadder[track] = max(currentLevel, level)
		} else {
			vsaSLSATrackLadder[track] = level
		}
	}
	return vsaSLSATrackLadder, nil
}

// IsSLSATrackLevel checks if the level is an SLSA track level
// Adapted from slsa-verifier/verifiers/internal/vsa/verifier.go
func IsSLSATrackLevel(level string) bool {
	return strings.HasPrefix(level, "SLSA_")
}

// determineSignatureHashAlgo determines the hash algorithm based on the public key
// Adapted from slsa-verifier/cli/slsa-verifier/verify/verify_vsa.go
func determineSignatureHashAlgo(pubKey crypto.PublicKey) crypto.Hash {
	switch pk := pubKey.(type) {
	case *rsa.PublicKey:
		return crypto.SHA256
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			return crypto.SHA256
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		default:
			return crypto.SHA256
		}
	case ed25519.PublicKey:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
