package vsa

import (
	"crypto"
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


// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
