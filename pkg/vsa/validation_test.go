package vsa

import (
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
		name    string
		vsa     *VSA
		wantErr bool
		errType string
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
					VerifiedLevels: []VSALevel{
						{Level: "SLSA_BUILD_LEVEL_3", Track: "BUILD"},
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
						URI: testURI,
						Digest: map[string]string{"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052"},
					},
				},
				Predicate: VSAPredicate{
					Verifier: VSAVerifier{
						ID: testURI,
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
				Type: "https://in-toto.io/Statement/v1",
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
					VerifiedLevels: []VSALevel{
						{Level: "SLSA_BUILD_INVALID_FORMAT"},
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
