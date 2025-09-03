// Package vsa - errors.go
// Contains error types and constructors for VSA validation and parsing errors.
// Provides standardized error handling across the VSA package.

package vsa

import (
	"fmt"
)

// VSAError represents a structured error for VSA operations
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

// Predefined error types
var (
	ErrInvalidDigest        = &VSAError{Type: "validation", Field: "digest", Message: "invalid digest format or value"}
	ErrMismatchVerifier     = &VSAError{Type: "validation", Field: "verifier", Message: "verifier ID mismatch"}
	ErrInvalidSLSALevel     = &VSAError{Type: "validation", Field: "verifiedLevels", Message: "invalid SLSA level format"}
	ErrMissingRequiredField = &VSAError{Type: "validation", Field: "required", Message: "missing required field"}
	ErrInvalidVerificationResult = &VSAError{Type: "validation", Field: "verificationResult", Message: "invalid verification result"}
	ErrInvalidResourceURI   = &VSAError{Type: "validation", Field: "resourceUri", Message: "invalid resource URI"}
	ErrInvalidPredicateType = &VSAError{Type: "validation", Field: "predicateType", Message: "invalid predicate type"}
	ErrInvalidStatementType = &VSAError{Type: "validation", Field: "_type", Message: "invalid statement type"}
)

// NewVSAError creates a new VSA error with the specified details
func NewVSAError(errorType, field, message string, cause error) *VSAError {
	return &VSAError{
		Type:    errorType,
		Field:   field,
		Message: message,
		Cause:   cause,
	}
}

// NewValidationError creates a validation error
func NewValidationError(field, message string, cause error) *VSAError {
	return NewVSAError("validation", field, message, cause)
}

// NewParsingError creates a parsing error
func NewParsingError(field, message string, cause error) *VSAError {
	return NewVSAError("parsing", field, message, cause)
}
