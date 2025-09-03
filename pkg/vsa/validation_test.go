package vsa

import (
	"testing"
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
				Type:          "https://in-toto.io/Statement/v1",
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Subject: []VSASubject{
					{
						Name: "test-image",
						Digest: map[string]string{
							"sha256": "a7833c841a486169ec4b376ebec4561f9de5280add97b86ebd075e401d3fd052",
						},
					},
				},
				Predicate: VSAPredicate{
					Verifier: VSAVerifier{
						ID: "https://github.com/liatrio/autogov-verify",
					},
					ResourceURI:        "test-resource",
					VerificationResult: "PASSED",
					VerifiedLevels: []string{
						"SLSA_BUILD_LEVEL_3",
						"AUTOGOV_ATTESTATION_REQUIRED",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid statement type",
			vsa: &VSA{
				Type:          "invalid-type",
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Subject: []VSASubject{
					{Name: "test", Digest: map[string]string{"sha256": "abc123"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: "https://test.com"},
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
				Type:          "https://in-toto.io/Statement/v1",
				PredicateType: "invalid-predicate",
				Subject: []VSASubject{
					{Name: "test", Digest: map[string]string{"sha256": "abc123"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: "https://test.com"},
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
				Type:          "https://in-toto.io/Statement/v1",
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Subject: []VSASubject{
					{Name: "test", Digest: map[string]string{"sha256": "abc123"}},
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
				Type:          "https://in-toto.io/Statement/v1",
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Subject: []VSASubject{
					{Name: "test", Digest: map[string]string{"sha256": "abc123"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: "https://test.com"},
					ResourceURI:        "test",
					VerificationResult: "INVALID",
				},
			},
			wantErr:  true,
			errType:  "validation",
			errField: "verificationResult",
		},
		{
			name: "invalid SLSA level format",
			vsa: &VSA{
				Type:          "https://in-toto.io/Statement/v1",
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Subject: []VSASubject{
					{Name: "test", Digest: map[string]string{"sha256": "abc123"}},
				},
				Predicate: VSAPredicate{
					Verifier:           VSAVerifier{ID: "https://test.com"},
					ResourceURI:        "test",
					VerificationResult: "PASSED",
					VerifiedLevels: []string{
						"SLSA_INVALID_FORMAT",
					},
				},
			},
			wantErr:  true,
			errType:  "validation",
			errField: "verifiedLevels",
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

func TestExtractSLSATrackLevels(t *testing.T) {
	tests := []struct {
		name           string
		verifiedLevels []string
		expected       SLSATrackLevels
		wantErr        bool
	}{
		{
			name: "valid SLSA levels",
			verifiedLevels: []string{
				"SLSA_BUILD_LEVEL_3",
				"SLSA_SOURCE_LEVEL_2",
				"AUTOGOV_CUSTOM_LEVEL",
			},
			expected: SLSATrackLevels{
				"BUILD":  3,
				"SOURCE": 2,
			},
			wantErr: false,
		},
		{
			name: "highest level per track",
			verifiedLevels: []string{
				"SLSA_BUILD_LEVEL_2",
				"SLSA_BUILD_LEVEL_3",
				"SLSA_BUILD_LEVEL_1",
			},
			expected: SLSATrackLevels{
				"BUILD": 3,
			},
			wantErr: false,
		},
		{
			name: "invalid SLSA level format",
			verifiedLevels: []string{
				"SLSA_INVALID_FORMAT",
			},
			wantErr: true,
		},
		{
			name: "invalid level number",
			verifiedLevels: []string{
				"SLSA_BUILD_LEVEL_INVALID",
			},
			wantErr: true,
		},
		{
			name: "level out of range",
			verifiedLevels: []string{
				"SLSA_BUILD_LEVEL_5",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractSLSATrackLevels(tt.verifiedLevels)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("ExtractSLSATrackLevels() expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Errorf("ExtractSLSATrackLevels() unexpected error: %v", err)
				return
			}
			
			if len(result) != len(tt.expected) {
				t.Errorf("ExtractSLSATrackLevels() result length = %d, want %d", len(result), len(tt.expected))
			}
			
			for track, expectedLevel := range tt.expected {
				if actualLevel, exists := result[track]; !exists {
					t.Errorf("ExtractSLSATrackLevels() missing track %s", track)
				} else if actualLevel != expectedLevel {
					t.Errorf("ExtractSLSATrackLevels() track %s level = %d, want %d", track, actualLevel, expectedLevel)
				}
			}
		})
	}
}

func TestDigestValidation(t *testing.T) {
	vsa := &VSA{
		Subject: []VSASubject{
			{
				Name: "test-image",
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
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"subject": [
			{
				"name": "test-image",
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
	}
	
	if vsa == nil {
		t.Error("ValidateVSA() returned nil VSA")
	}
	
	if vsa.Predicate.VerificationResult != "PASSED" {
		t.Errorf("ValidateVSA() verification result = %s, want PASSED", vsa.Predicate.VerificationResult)
	}
}
