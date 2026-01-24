package release

import (
	"fmt"
	"strconv"
	"strings"
)

// BumpType represents the type of version bump
type BumpType string

const (
	BumpMajor BumpType = "major"
	BumpMinor BumpType = "minor"
	BumpPatch BumpType = "patch"
	BumpNone  BumpType = "none"
)

// Version represents a semantic version
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Metadata   string
}

// ParseVersion parses a semver string into a Version struct
// accepts formats: v1.2.3, 1.2.3, v1.2.3-rc.1, 1.2.3+build.123
func ParseVersion(s string) (*Version, error) {
	s = strings.TrimPrefix(s, "v")

	// split off metadata
	var metadata string
	if idx := strings.Index(s, "+"); idx != -1 {
		metadata = s[idx+1:]
		s = s[:idx]
	}

	// split off prerelease
	var prerelease string
	if idx := strings.Index(s, "-"); idx != -1 {
		prerelease = s[idx+1:]
		s = s[:idx]
	}

	// parse major.minor.patch
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid semver format: expected X.Y.Z, got %s", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %w", err)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %w", err)
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid patch version: %w", err)
	}

	return &Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Metadata:   metadata,
	}, nil
}

// String returns the version as a string with v prefix
func (v *Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Metadata != "" {
		s += "+" + v.Metadata
	}
	return s
}

// StringWithoutV returns the version as a string without v prefix
func (v *Version) StringWithoutV() string {
	return strings.TrimPrefix(v.String(), "v")
}

// Bump returns a new version with the specified bump applied
func (v *Version) Bump(bump BumpType) *Version {
	newVer := &Version{
		Major: v.Major,
		Minor: v.Minor,
		Patch: v.Patch,
	}

	switch bump {
	case BumpMajor:
		newVer.Major++
		newVer.Minor = 0
		newVer.Patch = 0
	case BumpMinor:
		newVer.Minor++
		newVer.Patch = 0
	case BumpPatch:
		newVer.Patch++
	}

	return newVer
}

// Compare compares two versions: returns -1 if v < other, 0 if equal, 1 if v > other
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// LessThan returns true if v < other
func (v *Version) LessThan(other *Version) bool {
	return v.Compare(other) < 0
}

// ZeroVersion returns version 0.0.0
func ZeroVersion() *Version {
	return &Version{Major: 0, Minor: 0, Patch: 0}
}

// ComputeNextVersion determines the next version based on commit types
func ComputeNextVersion(current *Version, commits []ParsedCommit) (*Version, BumpType) {
	if len(commits) == 0 {
		return current, BumpNone
	}

	// determine the highest bump level needed
	bumpType := BumpNone

	for _, c := range commits {
		// breaking changes always result in major bump
		if c.Breaking {
			bumpType = BumpMajor
			break // can't go higher than major
		}

		switch c.Type {
		case "feat":
			if bumpType != BumpMajor {
				bumpType = BumpMinor
			}
		case "fix", "perf":
			if bumpType == BumpNone {
				bumpType = BumpPatch
			}
		}
	}

	if bumpType == BumpNone {
		return current, BumpNone
	}

	return current.Bump(bumpType), bumpType
}
