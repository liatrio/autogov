package vsa

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/liatrio/autogov-verify/pkg/digest"
)

// structured error for VSA operations
type VSAError struct {
	Type    string
	Field   string
	Message string
	Cause   error
}

func (e *VSAError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("VSA %s error in %s: %s: %v", e.Type, e.Field, e.Message, e.Cause)
	}
	return fmt.Sprintf("VSA %s error in %s: %s", e.Type, e.Field, e.Message)
}

func (e *VSAError) Unwrap() error {
	return e.Cause
}

// error types
var (
	ErrInvalidDigest             = &VSAError{Type: "validation", Field: "digest", Message: "invalid digest format or value"}
	ErrMismatchVerifier          = &VSAError{Type: "validation", Field: "verifier", Message: "verifier ID mismatch"}
	ErrInvalidSLSALevel          = &VSAError{Type: "validation", Field: "verifiedLevels", Message: "invalid SLSA level format"}
	ErrMissingRequiredField      = &VSAError{Type: "validation", Field: "required", Message: "missing required field"}
	ErrInvalidVerificationResult = &VSAError{Type: "validation", Field: "verificationResult", Message: "invalid verification result"}
	ErrInvalidResourceURI        = &VSAError{Type: "validation", Field: "resourceUri", Message: "invalid resource URI"}
	ErrInvalidPredicateType      = &VSAError{Type: "validation", Field: "predicateType", Message: "invalid predicate type"}
	ErrInvalidStatementType      = &VSAError{Type: "validation", Field: "_type", Message: "invalid statement type"}
)

// creates a new VSA error with the specified details
func NewVSAError(errorType, field, message string, cause error) *VSAError {
	return &VSAError{
		Type:    errorType,
		Field:   field,
		Message: message,
		Cause:   cause,
	}
}

// creates a validation error
func NewValidationError(field, message string, cause error) *VSAError {
	return NewVSAError("validation", field, message, cause)
}

// creates a parsing error
func NewParsingError(field, message string, cause error) *VSAError {
	return NewVSAError("parsing", field, message, cause)
}

// represents a collection of digests organized by algorithm
type DigestSet map[string]map[string]bool

// validates that expected digests are present in VSA subjects
// multiple digest formats: sha256:abc123, sha1:def456, etc. are supported
func (v *VSA) ValidateDigests(expectedDigests []string) error {
	if len(expectedDigests) == 0 {
		return NewValidationError("digest", "no expected digests provided", nil)
	}

	// all VSA subject digests by algorithm
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

	// validates expected digest
	for _, expected := range expectedDigests {
		if err := v.validateSingleDigest(expected, vsaDigests); err != nil {
			return err
		}
	}

	return nil
}

// validates a single digest against the VSA digest set
func (v *VSA) validateSingleDigest(expected string, vsaDigests DigestSet) error {
	parts := strings.SplitN(expected, ":", 2)
	if len(parts) != 2 {
		return NewValidationError("digest",
			fmt.Sprintf("invalid digest format: %s (expected <algorithm>:<digest>)", expected), nil)
	}

	alg, digest := parts[0], parts[1]

	// algorithm exists
	algDigests, algExists := vsaDigests[alg]
	if !algExists {
		return NewValidationError("digest",
			fmt.Sprintf("digest algorithm not found in VSA: %s", alg), nil)
	}

	// specific digest exists
	if !algDigests[digest] {
		return NewValidationError("digest",
			fmt.Sprintf("digest not found: %s", expected), nil)
	}

	return nil
}

// returns the digest algorithms present in VSA subjects
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

// validates that all digests in VSA subjects have proper format
func (v *VSA) ValidateDigestFormats() error {
	for i, subject := range v.Subject {
		for alg, hexDigest := range subject.Digest {
			if err := validateDigestFormat(alg, hexDigest); err != nil {
				return NewValidationError("digest",
					fmt.Sprintf("invalid digest format in subject %d: %s:%s", i, alg, hexDigest), err)
			}
		}
	}

	return nil
}

// validates digest format based on algorithm
func validateDigestFormat(algorithm, hexDigest string) error {
	return digest.ValidateFormat(algorithm, hexDigest)
}

// validates an existing VSA (SLSA v1.1 compliant)
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

// performs comprehensive VSA validation
func (v *VSA) ValidateComprehensive() error {
	// statement type
	if err := v.validateStatementType(); err != nil {
		return err
	}

	// predicate type
	if err := v.validatePredicateType(); err != nil {
		return err
	}

	// subject digests
	if err := v.validateSubjectDigests(); err != nil {
		return err
	}

	// verifier
	if err := v.validateVerifier(); err != nil {
		return err
	}

	// resource URI
	if err := v.validateResourceURI(); err != nil {
		return err
	}

	// verification result
	if err := v.validateVerificationResult(); err != nil {
		return err
	}

	// SLSA levels
	if err := v.validateSLSALevels(); err != nil {
		return err
	}

	// digest formats
	if err := v.ValidateDigestFormats(); err != nil {
		return err
	}

	return nil
}

// validates the VSA statement type
func (v *VSA) validateStatementType() error {
	// Support both v0.1 and v1 for backward compatibility
	if v.Type != "https://in-toto.io/Statement/v1" && v.Type != "https://in-toto.io/Statement/v0.1" {
		return NewValidationError("_type",
			fmt.Sprintf("invalid statement type: %s (expected https://in-toto.io/Statement/v1 or v0.1)", v.Type), nil)
	}
	return nil
}

// validates the VSA predicate type
func (v *VSA) validatePredicateType() error {
	if v.PredicateType != "https://slsa.dev/verification_summary/v1" {
		return NewValidationError("predicateType",
			fmt.Sprintf("invalid predicate type: %s (expected https://slsa.dev/verification_summary/v1)", v.PredicateType), nil)
	}
	return nil
}

// validates VSA subjects have proper structure
func (v *VSA) validateSubjectDigests() error {
	if len(v.Subject) == 0 {
		return NewValidationError("subject", "no subjects found in VSA", nil)
	}

	for i, subject := range v.Subject {
		if subject.URI == "" {
			return NewValidationError("subject",
				fmt.Sprintf("subject %d missing URI", i), nil)
		}

		// digest optional for some subject types (e.g., repositories)
		// but recommended for artifacts
	}

	return nil
}

// validates the VSA verifier
func (v *VSA) validateVerifier() error {
	if v.Predicate.Verifier.ID == "" {
		return NewValidationError("verifier", "verifier ID is required", nil)
	}

	// validates verifier ID format (should be a URL)
	if !strings.HasPrefix(v.Predicate.Verifier.ID, "https://") {
		return NewValidationError("verifier",
			fmt.Sprintf("verifier ID should be a URL: %s", v.Predicate.Verifier.ID), nil)
	}

	return nil
}

// validates the resource URI
func (v *VSA) validateResourceURI() error {
	if v.Predicate.ResourceURI == "" {
		return NewValidationError("resourceUri", "resourceURI is required", nil)
	}
	return nil
}

// validates the verification result
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

// validates SLSA level formats
func (v *VSA) validateSLSALevels() error {
	// VerifiedLevels is already a string slice per spec
	_, err := ExtractSLSATrackLevels(v.Predicate.VerifiedLevels)
	return err
}
