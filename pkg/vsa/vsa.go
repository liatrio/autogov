// provides types, structures, and generation functions for Verification Summary Attestations.
package vsa

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liatrio/autogov/pkg/attestations"
)

// Verification Summary Attestation based on the in-toto VSA specification / SLSA v1.1
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

// a resource with URI and digest
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// policy information (supports both content and URI)
type VSAPolicy struct {
	Content string            `json:"content,omitempty"` // Policy content (e.g., Datalog, Rego)
	URI     string            `json:"uri,omitempty"`     // Policy URI
	Digest  map[string]string `json:"digest,omitempty"`  // Policy digest
}

// represents a verified SLSA level (for internal use only)
// actual VSA predicate uses string array for verifiedLevels per spec
type VSALevel struct {
	Level string `json:"level"`           // e.g., "SLSA_BUILD_LEVEL_3"
	Track string `json:"track,omitempty"` // e.g., "BUILD", "SOURCE"
}

// implements custom JSON unmarshaling for backward compatibility
// both string format (legacy) and object format (new) are supported
func (v *VSALevel) UnmarshalJSON(data []byte) error {
	// unmarshal as string first (legacy format)
	var levelStr string
	if err := json.Unmarshal(data, &levelStr); err == nil {
		// parse string format to extract track if present
		if strings.HasPrefix(levelStr, "SLSA_BUILD_LEVEL_") {
			v.Level = levelStr
			v.Track = "BUILD"
		} else {
			v.Level = levelStr
		}
		return nil
	}

	// unmarshal as object (new format)
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
	TimeVerified       string               `json:"timeVerified"`
	ResourceURI        string               `json:"resourceUri"`
	Policy             VSAPolicy            `json:"policy"`
	InputAttestations  []ResourceDescriptor `json:"inputAttestations,omitempty"`
	VerificationResult string               `json:"verificationResult"`
	VerifiedLevels     []string             `json:"verifiedLevels,omitempty"`
	DependencyLevels   map[string]uint64    `json:"dependencyLevels,omitempty"`
	SlsaVersion        string               `json:"slsaVersion,omitempty"`
}

type VSAVerifier struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

// provides config
type VSAOptions struct {
	Subjects            []VSASubject         `json:"subjects,omitempty"`
	InputAttestations   []ResourceDescriptor `json:"inputAttestations,omitempty"`
	PolicyDigest        map[string]string    `json:"policyDigest,omitempty"`
	Dependencies        []Dependency         `json:"dependencies,omitempty"`
	AdditionalVerifiers map[string]string    `json:"additionalVerifiers,omitempty"`
}

// represents a software dependency for SLSA level analysis
type Dependency struct {
	Name          string            `json:"name"`
	Digest        map[string]string `json:"digest"`
	URI           string            `json:"uri,omitempty"`
	VerifiedLevel string            `json:"verifiedLevel,omitempty"`
}

// creates a VSA w/ opts
func GenerateVSAWithOptions(imageRef string, policyURI string, verificationResults map[string]bool, opts VSAOptions) (*VSA, error) {
	// if no subjects provided, create from imageRef
	if len(opts.Subjects) == 0 {
		digest, err := extractDigestFromImageRef(imageRef)
		if err != nil {
			return nil, fmt.Errorf("failed to extract digest: %w", err)
		}
		opts.Subjects = []VSASubject{
			{
				URI: imageRef,
				Digest: map[string]string{
					"sha256": digest,
				},
			},
		}
	}

	return generateVSACore(imageRef, opts.Subjects, policyURI, verificationResults, opts)
}

// creates a VSA for successful AutoGov validation
// calls GenerateVSAWithOptions w/ default options
func GenerateVSA(imageRef string, policyURI string, verificationResults map[string]bool) (*VSA, error) {
	return GenerateVSAWithOptions(imageRef, policyURI, verificationResults, VSAOptions{})
}

// creates a VSA with multiple subjects
func GenerateVSAWithSubjects(imageRef string, subjects []VSASubject, policyURI string, verificationResults map[string]bool, opts VSAOptions) (*VSA, error) {
	opts.Subjects = subjects
	return generateVSACore(imageRef, subjects, policyURI, verificationResults, opts)
}

// extracts SHA256 digest from image ref / direct digest
func extractDigestFromImageRef(imageRef string) (string, error) {
	// direct sha256 digest format (for blob verification)
	if strings.HasPrefix(imageRef, "sha256:") {
		digest := strings.TrimPrefix(imageRef, "sha256:")
		if len(digest) != 64 {
			return "", fmt.Errorf("invalid SHA256 digest length: expected 64 characters, got %d", len(digest))
		}
		return digest, nil
	}

	// container image ref format (registry/repo:tag@sha256:digest)
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

// converts VSA to JSON bytes
func (v *VSA) SerializeVSA() ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// checks if the VSA indicates successful verification
func (v *VSA) IsVerificationPassed() bool {
	return v.Predicate.VerificationResult == "PASSED"
}

// SLSA tracks and their levels
type SLSATrackLevels struct {
	BuildTrack      int
	DependencyTrack int
	SourceTrack     int
}

// parses SLSA track levels from a list of strings
func ExtractSLSATrackLevels(trackLevels []string) (SLSATrackLevels, error) {
	var result SLSATrackLevels

	for _, level := range trackLevels {
		parts := strings.Split(level, "_")
		if len(parts) < 4 {
			continue
		}

		// format: SLSA_<TRACK>_LEVEL_<NUMBER>
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
		case "SOURCE":
			if levelNum > result.SourceTrack {
				result.SourceTrack = levelNum
			}
		}
	}

	return result, nil
}

// extracts valid SLSA levels from a string slice
func ExtractSLSALevels(levels []string) []string {
	var result []string
	for _, level := range levels {
		if IsSLSATrackLevel(level) {
			result = append(result, level)
		}
	}
	return result
}

// checks if a level string is a valid SLSA track level
func IsSLSATrackLevel(level string) bool {
	// valid SLSA track levels (build, dependency, and source)
	validLevels := []string{
		"SLSA_BUILD_LEVEL_0",
		"SLSA_BUILD_LEVEL_1",
		"SLSA_BUILD_LEVEL_2",
		"SLSA_BUILD_LEVEL_3",
		"SLSA_DEPENDENCY_LEVEL_0",
		"SLSA_DEPENDENCY_LEVEL_1",
		"SLSA_DEPENDENCY_LEVEL_2",
		"SLSA_DEPENDENCY_LEVEL_3",
		"SLSA_SOURCE_LEVEL_0",
		"SLSA_SOURCE_LEVEL_1",
		"SLSA_SOURCE_LEVEL_2",
		"SLSA_SOURCE_LEVEL_3",
	}

	for _, valid := range validLevels {
		if level == valid {
			return true
		}
	}
	return false
}

// core VSA generation logic shared by all public functions
func generateVSACore(imageRef string, subjects []VSASubject, policyURI string, verificationResults map[string]bool, opts VSAOptions) (*VSA, error) {
	// overall result
	result := "PASSED"
	for _, passed := range verificationResults {
		if !passed {
			result = "FAILED"
			break
		}
	}

	// timestamp pointer for v1.1 compliance
	now := time.Now().UTC()

	// verifier versions map - only include additional verifiers
	verifierVersions := make(map[string]string)
	for tool, ver := range opts.AdditionalVerifiers {
		verifierVersions[tool] = ver
	}

	dependencyLevels := make(map[string]uint64) // empty map for backward compatibility

	// compute the build-track level from evidence rather than asserting it.
	// SLSA Build L3 requires non-falsifiable provenance from an isolated,
	// hosted builder; autogov's builds produce that via attest-build-provenance
	// on GitHub-hosted runners. we may only claim L3 when a build-provenance
	// attestation was verified AND the verification enforced the signer
	// identity (cert-identity / signer allowlist) that binds it to that trusted
	// builder — the resultKeyProvenanceIdentityBound signal. without that
	// binding (e.g. an unsafe verify with no --cert-identity, or a source-only
	// verify carrying no build provenance) the build track has no proven
	// guarantee and we honestly report L0 rather than over-claim L3.
	buildLevel := "SLSA_BUILD_LEVEL_0"
	if verificationResults[resultKeyProvenanceIdentityBound] {
		buildLevel = "SLSA_BUILD_LEVEL_3"
	}

	// use provided subjects if available, otherwise fall back to single subject
	var vsaSubjects []VSASubject
	if len(subjects) > 0 {
		vsaSubjects = subjects
	} else {
		// fall back to extracting from imageRef for backward compatibility
		digest, err := extractDigestFromImageRef(imageRef)
		if err != nil {
			return nil, fmt.Errorf("failed to extract digest: %w", err)
		}
		vsaSubjects = []VSASubject{
			{
				URI: imageRef,
				Digest: map[string]string{
					"sha256": digest,
				},
			},
		}
	}

	vsa := &VSA{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: attestations.PredicateTypeVSA,
		Subject:       vsaSubjects,
		Predicate: VSAPredicate{
			Verifier: VSAVerifier{
				ID:      "https://github.com/liatrio/autogov",
				Version: verifierVersions,
			},
			TimeVerified:       now.Format(time.RFC3339),
			ResourceURI:        imageRef,
			Policy:             VSAPolicy{URI: policyURI, Digest: opts.PolicyDigest},
			InputAttestations:  opts.InputAttestations,
			VerificationResult: result,
			VerifiedLevels:     []string{buildLevel},
			DependencyLevels:   dependencyLevels,
			SlsaVersion:        "1.1",
		},
		Metadata: map[string]interface{}{
			"autogov.verification.details": verificationResults,
			"autogov.policy.version":       "v1",
		},
	}

	// validate the generated VSA before returning
	if err := vsa.ValidateComprehensive(); err != nil {
		return nil, fmt.Errorf("generated VSA failed validation: %w", err)
	}

	return vsa, nil
}

// writes a VSA to a file in JSON format
func WriteToFile(vsa *VSA, outputPath string) error {
	// marshals VSA to JSON with indentation
	vsaJSON, err := json.MarshalIndent(vsa, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal VSA: %w", err)
	}

	// write to file
	if err := os.WriteFile(outputPath, vsaJSON, 0644); err != nil {
		return fmt.Errorf("failed to write VSA to file: %w", err)
	}

	return nil
}
