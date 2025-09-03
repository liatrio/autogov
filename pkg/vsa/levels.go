package vsa

import (
	"fmt"
	"strings"
)

// SLSATrackLevels represents the SLSA tracks and their levels
type SLSATrackLevels struct {
	BuildTrack      int
	DependencyTrack int
}

// ExtractSLSATrackLevels parses SLSA track levels from a list of strings
func ExtractSLSATrackLevels(trackLevels []string) (SLSATrackLevels, error) {
	var result SLSATrackLevels

	for _, level := range trackLevels {
		parts := strings.Split(level, "_")
		if len(parts) < 4 {
			continue
		}

		// Format: SLSA_<TRACK>_LEVEL_<NUMBER>
		if parts[0] != "SLSA" || parts[2] != "LEVEL" {
			continue
		}

		track := parts[1]
		levelNum := 0
		_, err := fmt.Sscanf(parts[3], "%d", &levelNum)
		if err != nil {
			continue
		}

		switch track {
		case "BUILD":
			if levelNum > result.BuildTrack {
				result.BuildTrack = levelNum
			}
		case "DEPENDENCY":
			if levelNum > result.DependencyTrack {
				result.DependencyTrack = levelNum
			}
		}
	}

	return result, nil
}

// ExtractSLSALevels extracts SLSA levels from VSALevel slice
func ExtractSLSALevels(levels []VSALevel) []string {
	var result []string
	for _, level := range levels {
		if IsSLSATrackLevel(level.Level) {
			result = append(result, level.Level)
		}
	}
	return result
}

// IsSLSATrackLevel checks if a level string is a valid SLSA track level
func IsSLSATrackLevel(level string) bool {
	// Valid SLSA v1.1 track levels
	validLevels := []string{
		"SLSA_BUILD_LEVEL_0",
		"SLSA_BUILD_LEVEL_1",
		"SLSA_BUILD_LEVEL_2",
		"SLSA_BUILD_LEVEL_3",
		"SLSA_DEPENDENCY_LEVEL_0",
		"SLSA_DEPENDENCY_LEVEL_1",
		"SLSA_DEPENDENCY_LEVEL_2",
		"SLSA_DEPENDENCY_LEVEL_3",
	}

	for _, valid := range validLevels {
		if level == valid {
			return true
		}
	}
	return false
}
