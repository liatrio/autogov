// Package vsa - levels.go
// Contains SLSA level parsing, validation, and utility functions.
// Handles SLSA track level extraction and validation logic.

package vsa

import (
	"fmt"
	"strconv"
	"strings"
)

// SLSATrackLevels represents SLSA levels organized by track
type SLSATrackLevels map[string]int

// ExtractSLSATrackLevels parses SLSA levels from string format and returns highest level per track
func ExtractSLSATrackLevels(verifiedLevels []string) (SLSATrackLevels, error) {
	trackLevels := make(SLSATrackLevels)
	
	for _, level := range verifiedLevels {
		if !strings.HasPrefix(level, "SLSA_") {
			continue
		}
		
		parts := strings.SplitN(level, "_", 4)
		if len(parts) != 4 {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("invalid SLSA level format: %s (expected SLSA_<TRACK>_LEVEL_<N>)", level), nil)
		}
		
		track := parts[1]
		levelStr := parts[3]
		
		levelNum, err := strconv.Atoi(levelStr)
		if err != nil {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("invalid SLSA level number: %s", levelStr), err)
		}
		
		if levelNum < 1 || levelNum > 4 {
			return nil, NewValidationError("verifiedLevels", 
				fmt.Sprintf("SLSA level out of range (1-4): %d", levelNum), nil)
		}
		
		// Keep the highest level for each track
		if currentLevel, exists := trackLevels[track]; !exists || levelNum > currentLevel {
			trackLevels[track] = levelNum
		}
	}
	
	return trackLevels, nil
}

// ExtractSLSALevels extracts SLSA levels from a list of verified levels
func ExtractSLSALevels(verifiedLevels []string) []string {
	var slsaLevels []string
	for _, level := range verifiedLevels {
		if IsSLSATrackLevel(level) {
			slsaLevels = append(slsaLevels, level)
		}
	}
	return slsaLevels
}

// IsSLSATrackLevel checks if a level string represents a valid SLSA track level
func IsSLSATrackLevel(level string) bool {
	if !strings.HasPrefix(level, "SLSA_") {
		return false
	}
	
	parts := strings.SplitN(level, "_", 4)
	if len(parts) != 4 || parts[2] != "LEVEL" {
		return false
	}
	
	levelNum, err := strconv.Atoi(parts[3])
	return err == nil && levelNum >= 1 && levelNum <= 4
}
