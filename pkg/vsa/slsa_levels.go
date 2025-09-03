package vsa

import (
	"fmt"
	"strconv"
	"strings"
)

// SLSATrackLevels represents SLSA levels organized by track
type SLSATrackLevels map[string]int

// ExtractSLSATrackLevels extracts SLSA levels from verified levels with track-based parsing
// Parses SLSA_<TRACK>_LEVEL_<N> format and returns highest level per track
func ExtractSLSATrackLevels(verifiedLevels []string) (SLSATrackLevels, error) {
	trackLevels := make(SLSATrackLevels)
	
	for _, level := range verifiedLevels {
		if !strings.HasPrefix(level, "SLSA_") {
			continue
		}
		
		// Parse SLSA_<TRACK>_LEVEL_<N> format
		parts := strings.SplitN(level, "_", 4)
		if len(parts) != 4 {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("invalid SLSA level format: %s (expected SLSA_<TRACK>_LEVEL_<N>)", level), nil)
		}
		
		if parts[2] != "LEVEL" {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("invalid SLSA level format: %s (missing LEVEL component)", level), nil)
		}
		
		track := parts[1]
		levelNum, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("invalid SLSA level number: %s", level), err)
		}
		
		// Validate level number is reasonable (1-4 for current SLSA spec)
		if levelNum < 1 || levelNum > 4 {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("SLSA level out of range: %d (expected 1-4)", levelNum), nil)
		}
		
		// Keep highest level per track
		if current, exists := trackLevels[track]; exists {
			trackLevels[track] = max(current, levelNum)
		} else {
			trackLevels[track] = levelNum
		}
	}
	
	return trackLevels, nil
}

// ValidateSLSALevels validates that actual SLSA levels meet minimum requirements
func ValidateSLSALevels(actual, required SLSATrackLevels) error {
	for track, minLevel := range required {
		actualLevel, exists := actual[track]
		if !exists {
			return NewValidationError("verifiedLevels", 
				fmt.Sprintf("required SLSA track not found: %s", track), nil)
		}
		
		if actualLevel < minLevel {
			return NewValidationError("verifiedLevels", 
				fmt.Sprintf("SLSA level too low for track %s: got %d, required %d", 
					track, actualLevel, minLevel), nil)
		}
	}
	
	return nil
}

// GetNonSLSALevels extracts non-SLSA verified levels
func GetNonSLSALevels(verifiedLevels []string) []string {
	var nonSLSA []string
	
	for _, level := range verifiedLevels {
		if !strings.HasPrefix(level, "SLSA_") {
			nonSLSA = append(nonSLSA, level)
		}
	}
	
	return nonSLSA
}

// ValidateNonSLSALevels validates that required non-SLSA levels are present
func ValidateNonSLSALevels(actual, required []string) error {
	actualSet := make(map[string]bool)
	for _, level := range actual {
		actualSet[level] = true
	}
	
	for _, requiredLevel := range required {
		if !actualSet[requiredLevel] {
			return NewValidationError("verifiedLevels", 
				fmt.Sprintf("required verified level not found: %s", requiredLevel), nil)
		}
	}
	
	return nil
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
