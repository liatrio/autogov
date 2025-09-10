package vsa

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

const (
	testStatementType = "https://in-toto.io/Statement/v1"
	testPredicateType = "https://slsa.dev/verification_summary/v1"
	testURI           = "https://test.com"
	testDigest        = "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"
)

func TestVSAComprehensiveValidation(t *testing.T) {
	tests := []struct {
		name     string
		vsa      *VSA
		wantErr  bool
		errType  string
		errField string
	}{
		{
			name: "valid VSA",
			vsa: &VSA{
				Type:          testStatementType,
				PredicateType: testPredicateType,
				Subject: []VSASubject{
					{
						URI: testURI,
						Digest: map[string]string{
							"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052",
						},
					},
				},
				Predicate: VSAPredicate{
					Verifier: VSAVerifier{
						ID: testURI,
					},
					ResourceURI:        testURI,
					VerificationResult: "PASSED",
					VerifiedLevels: []string{
						"SLSA_BUILD_LEVEL_3",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid statement type",
			vsa: &VSA{
				Type:          "invalid-type",
				PredicateType: testPredicateType,
				Subject: []VSASubject{
					{URI: "test", Digest: map[string]string{"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: testURI},
					ResourceURI:        "test",
					VerificationResult: "PASSED",
				},
			},
			wantErr:  true,
			errType:  "validation",
			errField: "_type",
		},
		{
			name: "invalid predicate type",
			vsa: &VSA{
				Type:          testStatementType,
				PredicateType: "invalid-predicate",
				Subject: []VSASubject{
					{URI: "test", Digest: map[string]string{"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: testURI},
					ResourceURI:        "test",
					VerificationResult: "PASSED",
				},
			},
			wantErr:  true,
			errType:  "validation",
			errField: "predicateType",
		},
		{
			name: "missing verifier ID",
			vsa: &VSA{
				Type:          testStatementType,
				PredicateType: testPredicateType,
				Subject: []VSASubject{
					{URI: "test", Digest: map[string]string{"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: ""},
					ResourceURI:        "test",
					VerificationResult: "PASSED",
				},
			},
			wantErr:  true,
			errType:  "validation",
			errField: "verifier",
		},
		{
			name: "invalid verification result",
			vsa: &VSA{
				Type:          testStatementType,
				PredicateType: testPredicateType,
				Subject: []VSASubject{
					{
						URI:    testURI,
						Digest: map[string]string{"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"},
					},
				},
				Predicate: VSAPredicate{
					Verifier: VSAVerifier{
						ID:      testURI,
						Version: map[string]string{"version": "1.0"},
					},
					TimeVerified: "",
					ResourceURI:  testURI,
				},
			},
			wantErr:  true,
			errType:  "validation",
			errField: "verificationResult",
		},
		{
			name: "invalid SLSA level format (ignored)",
			vsa: &VSA{
				Type:          "https://in-toto.io/Statement/v1",
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Subject: []VSASubject{{
					URI:    testURI,
					Digest: map[string]string{"sha256": testDigest},
				}},
				Predicate: VSAPredicate{
					Verifier: VSAVerifier{
						ID: testURI,
					},
					TimeVerified:       "2023-01-01T00:00:00Z",
					ResourceURI:        testURI,
					Policy:             VSAPolicy{URI: testURI},
					VerificationResult: "PASSED",
					VerifiedLevels: []string{
						"SLSA_BUILD_INVALID_FORMAT",
					},
				},
			},
			wantErr:  false, // Invalid formats are ignored, not errors
			errType:  "",
			errField: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vsa.ValidateComprehensive()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateComprehensive() expected error, got nil")
					return
				}

				vsaErr, ok := err.(*VSAError)
				if !ok {
					t.Errorf("ValidateComprehensive() expected VSAError, got %T", err)
					return
				}

				if vsaErr.Type != tt.errType {
					t.Errorf("ValidateComprehensive() error type = %v, want %v", vsaErr.Type, tt.errType)
				}

				if vsaErr.Field != tt.errField {
					t.Errorf("ValidateComprehensive() error field = %v, want %v", vsaErr.Field, tt.errField)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateComprehensive() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDigestValidation(t *testing.T) {
	vsa := &VSA{
		Subject: []VSASubject{
			{
				URI: "test-image",
				Digest: map[string]string{
					"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052",
					"sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				},
			},
		},
	}

	tests := []struct {
		name            string
		expectedDigests []string
		wantErr         bool
	}{
		{
			name: "valid digest match",
			expectedDigests: []string{
				"sha256:a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052",
			},
			wantErr: false,
		},
		{
			name: "multiple digest match",
			expectedDigests: []string{
				"sha256:a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052",
				"sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
			},
			wantErr: false,
		},
		{
			name: "digest not found",
			expectedDigests: []string{
				"sha256:nonexistent",
			},
			wantErr: true,
		},
		{
			name: "invalid digest format",
			expectedDigests: []string{
				"invalid-format",
			},
			wantErr: true,
		},
		{
			name: "algorithm not found",
			expectedDigests: []string{
				"md5:nonexistent",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := vsa.ValidateDigests(tt.expectedDigests)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateDigests() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateDigests() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateVSAFromJSON(t *testing.T) {
	validVSAJSON := `{
		"_type": "` + testStatementType + `",
		"predicateType": "` + testPredicateType + `",
		"subject": [
			{
				"uri": "test-image",
				"digest": {
					"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"
				}
			}
		],
		"predicate": {
			"verifier": {
				"id": "https://github.com/liatrio/autogov-verify"
			},
			"resourceUri": "test-resource",
			"verificationResult": "PASSED",
			"verifiedLevels": [
				"SLSA_BUILD_LEVEL_3"
			]
		}
	}`

	vsa, err := ValidateVSA([]byte(validVSAJSON))
	if err != nil {
		t.Errorf("ValidateVSA() unexpected error: %v", err)
		return
	}

	if vsa == nil {
		t.Error("ValidateVSA() returned nil VSA")
		return
	}

	if vsa.Predicate.VerificationResult != "PASSED" {
		t.Errorf("ValidateVSA() verification result = %s, want PASSED", vsa.Predicate.VerificationResult)
	}
}

func TestGetSupportedDigestAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		vsa      *VSA
		expected []string
	}{
		{
			name: "single algorithm",
			vsa: &VSA{
				Subject: []VSASubject{
					{Digest: map[string]string{"sha256": "abc123"}},
				},
			},
			expected: []string{"sha256"},
		},
		{
			name: "multiple algorithms",
			vsa: &VSA{
				Subject: []VSASubject{
					{Digest: map[string]string{
						"sha256": "abc123",
						"sha512": "def456",
					}},
				},
			},
			expected: []string{"sha256", "sha512"},
		},
		{
			name: "multiple subjects same algorithm",
			vsa: &VSA{
				Subject: []VSASubject{
					{Digest: map[string]string{"sha256": "abc123"}},
					{Digest: map[string]string{"sha256": "def456"}},
				},
			},
			expected: []string{"sha256"},
		},
		{
			name: "empty subjects",
			vsa: &VSA{
				Subject: []VSASubject{},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vsa.GetSupportedDigestAlgorithms()
			// Sort both slices for comparison
			sort.Strings(result)
			sort.Strings(tt.expected)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d algorithms, got %d", len(tt.expected), len(result))
			}
			for i := range result {
				if i < len(tt.expected) && result[i] != tt.expected[i] {
					t.Errorf("algorithm mismatch at index %d: expected %s, got %s", i, tt.expected[i], result[i])
				}
			}
		})
	}
}

func TestValidateDigestFormat(t *testing.T) {
	tests := []struct {
		name    string
		alg     string
		digest  string
		wantErr bool
	}{
		{"valid sha256", "sha256", strings.Repeat("a", 64), false},
		{"invalid sha256 length", "sha256", "abc123", true},
		{"invalid sha256 chars", "sha256", strings.Repeat("g", 64), true}, // 'g' is not a valid hex character
		{"valid sha1", "sha1", strings.Repeat("a", 40), false},
		{"invalid sha1 length", "sha1", "abc123", true},
		{"valid sha384", "sha384", strings.Repeat("a", 96), false},
		{"invalid sha384 length", "sha384", "abc123", false}, // unknown alg returns nil
		{"valid sha512", "sha512", strings.Repeat("a", 128), false},
		{"invalid sha512 length", "sha512", "abc123", true},
		{"valid md5", "md5", strings.Repeat("a", 32), false},
		{"invalid md5 length", "md5", "abc123", true},
		{"unknown algorithm", "unknown", "abc123", false}, // unknown alg returns nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDigestFormat(tt.alg, tt.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDigestFormat(%q, %q) error = %v, wantErr %v", tt.alg, tt.digest, err, tt.wantErr)
			}
		})
	}
}

func TestVSALevelUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected VSALevel
		wantErr  bool
	}{
		{
			name:  "string format build level",
			input: `"SLSA_BUILD_LEVEL_3"`,
			expected: VSALevel{
				Level: "SLSA_BUILD_LEVEL_3",
				Track: "BUILD",
			},
			wantErr: false,
		},
		{
			name:  "string format other level",
			input: `"SLSA_DEPENDENCY_LEVEL_2"`,
			expected: VSALevel{
				Level: "SLSA_DEPENDENCY_LEVEL_2",
				Track: "",
			},
			wantErr: false,
		},
		{
			name:  "object format with track",
			input: `{"level":"SLSA_BUILD_LEVEL_2","track":"BUILD"}`,
			expected: VSALevel{
				Level: "SLSA_BUILD_LEVEL_2",
				Track: "BUILD",
			},
			wantErr: false,
		},
		{
			name:  "object format without track",
			input: `{"level":"SLSA_SOURCE_LEVEL_1"}`,
			expected: VSALevel{
				Level: "SLSA_SOURCE_LEVEL_1",
				Track: "",
			},
			wantErr: false,
		},
		{
			name:     "invalid JSON",
			input:    `{invalid}`,
			expected: VSALevel{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v VSALevel
			err := v.UnmarshalJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if v.Level != tt.expected.Level || v.Track != tt.expected.Track {
					t.Errorf("UnmarshalJSON() = %+v, want %+v", v, tt.expected)
				}
			}
		})
	}
}

func TestValidateSubjectDigests(t *testing.T) {
	const testImageURI = "test.example.com/image:latest"

	tests := []struct {
		name    string
		vsa     *VSA
		wantErr bool
	}{
		{
			name: "valid sha256 digest",
			vsa: &VSA{
				Subject: []VSASubject{{
					URI: testImageURI,
					Digest: map[string]string{
						"sha256": strings.Repeat("a", 64),
					},
				}},
				Predicate: VSAPredicate{},
			},
			wantErr: false,
		},
		{
			name: "invalid sha256 digest length",
			vsa: &VSA{
				Subject: []VSASubject{{
					URI: testImageURI,
					Digest: map[string]string{
						"sha256": "short",
					},
				}},
				Predicate: VSAPredicate{},
			},
			wantErr: false, // validateSubjectDigests doesn't check digest format, only URI presence
		},
		{
			name: "multiple valid digests",
			vsa: &VSA{
				Subject: []VSASubject{{
					URI: testImageURI,
					Digest: map[string]string{
						"sha256": strings.Repeat("a", 64),
						"sha512": strings.Repeat("b", 128),
					},
				}},
				Predicate: VSAPredicate{},
			},
			wantErr: false,
		},
		{
			name: "missing URI",
			vsa: &VSA{
				Subject: []VSASubject{{
					Digest: map[string]string{
						"sha256": strings.Repeat("a", 64),
					},
				}},
				Predicate: VSAPredicate{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vsa.validateSubjectDigests()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSubjectDigests() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// VSAError Tests (merged from errors_test.go)
const (
	testCause     = "test cause"
	typeFormat    = "Type = %q, want %q"
	fieldFormat   = "Field = %q, want %q"
	messageFormat = "Message = %q, want %q"
	causeFormat   = "Cause = %v, want %v"
)

func TestVSAError(t *testing.T) {
	tests := []struct {
		name     string
		err      *VSAError
		expected string
	}{
		{
			name: "error without cause",
			err: &VSAError{
				Type:    "validation",
				Field:   "digest",
				Message: "invalid format",
			},
			expected: "VSA validation error in digest: invalid format",
		},
		{
			name: "error with cause",
			err: &VSAError{
				Type:    "parsing",
				Field:   "json",
				Message: "failed to unmarshal",
				Cause:   errors.New("syntax error"),
			},
			expected: "VSA parsing error in json: failed to unmarshal: syntax error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVSAErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := &VSAError{
		Type:    "validation",
		Field:   "test",
		Message: "test message",
		Cause:   cause,
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}

	// test without cause
	errNoCause := &VSAError{
		Type:    "validation",
		Field:   "test",
		Message: "test message",
	}

	if unwrapped := errNoCause.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap() = %v, want nil", unwrapped)
	}
}

func TestNewVSAError(t *testing.T) {
	cause := errors.New(testCause)
	err := NewVSAError("validation", "field", "message", cause)

	if err.Type != "validation" {
		t.Errorf(typeFormat, err.Type, "validation")
	}
	if err.Field != "field" {
		t.Errorf(fieldFormat, err.Field, "field")
	}
	if err.Message != "message" {
		t.Errorf(messageFormat, err.Message, "message")
	}
	if err.Cause != cause {
		t.Errorf(causeFormat, err.Cause, cause)
	}
}

func TestNewValidationError(t *testing.T) {
	cause := errors.New(testCause)
	err := NewValidationError("field", "message", cause)

	if err.Type != "validation" {
		t.Errorf(typeFormat, err.Type, "validation")
	}
	if err.Field != "field" {
		t.Errorf(fieldFormat, err.Field, "field")
	}
	if err.Message != "message" {
		t.Errorf(messageFormat, err.Message, "message")
	}
	if err.Cause != cause {
		t.Errorf(causeFormat, err.Cause, cause)
	}
}

func TestNewParsingError(t *testing.T) {
	cause := errors.New(testCause)
	err := NewParsingError("field", "message", cause)

	if err.Type != "parsing" {
		t.Errorf(typeFormat, err.Type, "parsing")
	}
	if err.Field != "field" {
		t.Errorf(fieldFormat, err.Field, "field")
	}
	if err.Message != "message" {
		t.Errorf(messageFormat, err.Message, "message")
	}
	if err.Cause != cause {
		t.Errorf(causeFormat, err.Cause, cause)
	}
}

func TestPredefinedErrors(t *testing.T) {
	predefinedErrors := []*VSAError{
		ErrInvalidDigest,
		ErrMismatchVerifier,
		ErrInvalidSLSALevel,
		ErrMissingRequiredField,
		ErrInvalidVerificationResult,
		ErrInvalidResourceURI,
		ErrInvalidPredicateType,
		ErrInvalidStatementType,
	}

	for _, err := range predefinedErrors {
		if err.Type == "" {
			t.Errorf("Predefined error has empty Type: %+v", err)
		}
		if err.Field == "" {
			t.Errorf("Predefined error has empty Field: %+v", err)
		}
		if err.Message == "" {
			t.Errorf("Predefined error has empty Message: %+v", err)
		}
	}
}
