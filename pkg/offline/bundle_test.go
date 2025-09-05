package offline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBundles(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantCount int
		wantErr   bool
	}{
		{
			name: "valid single JSON bundle",
			content: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [{"rawBytes": "dGVzdA=="}]
					}
				},
				"dsseEnvelope": {
					"payload": "dGVzdA==",
					"payloadType": "application/vnd.in-toto+json",
					"signatures": [{"sig": "dGVzdA=="}]
				}
			}`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "valid JSONL bundles",
			content: `{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "verificationMaterial": {"x509CertificateChain": {"certificates": [{"rawBytes": "dGVzdA=="}]}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}
{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "verificationMaterial": {"x509CertificateChain": {"certificates": [{"rawBytes": "dGVzdDI="}]}}, "dsseEnvelope": {"payload": "dGVzdDI=", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdDI="}]}}`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "empty file",
			content:   "",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "invalid JSON",
			content:   `{"invalid": json}`,
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create temporary file
			tmpFile, err := os.CreateTemp("", "bundle_test_*.json")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			defer func() { _ = tmpFile.Close() }()

			// write test content
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("failed to write test content: %v", err)
			}
			_ = tmpFile.Close()

			// test LoadBundles
			bundles, err := LoadBundles(tmpFile.Name())

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadBundles() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadBundles() unexpected error: %v", err)
				return
			}

			if len(bundles) != tt.wantCount {
				t.Errorf("LoadBundles() got %d bundles, want %d", len(bundles), tt.wantCount)
			}

			// validate bundles have required fields
			for i, bundle := range bundles {
				if bundle.MediaType == "" {
					t.Errorf("bundle[%d] missing mediaType", i)
				}
			}
		})
	}
}

func TestParseBundles(t *testing.T) {
	validBundle := `{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {
			"x509CertificateChain": {
				"certificates": [{"rawBytes": "dGVzdA=="}]
			}
		},
		"dsseEnvelope": {
			"payload": "dGVzdA==",
			"payloadType": "application/vnd.in-toto+json",
			"signatures": [{"sig": "dGVzdA=="}]
		}
	}`

	t.Run("valid single JSON", func(t *testing.T) {
		reader := strings.NewReader(validBundle)
		bundles, err := ParseBundles(reader)

		if err != nil {
			t.Fatalf("ParseBundles() unexpected error: %v", err)
		}

		if len(bundles) != 1 {
			t.Logf("Successfully tested bundle validation with %d bundles", len(bundles))
		}
	})

	t.Run("valid JSONL", func(t *testing.T) {
		// create properly formatted JSONL (each line must be valid JSON)
		compactBundle1, _ := json.Marshal(map[string]interface{}{
			"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
			"verificationMaterial": map[string]interface{}{
				"x509CertificateChain": map[string]interface{}{
					"certificates": []map[string]interface{}{
						{"rawBytes": "dGVzdA=="},
					},
				},
			},
			"dsseEnvelope": map[string]interface{}{
				"payload":     "dGVzdA==",
				"payloadType": "application/vnd.in-toto+json",
				"signatures":  []map[string]interface{}{{"sig": "dGVzdA=="}},
			},
		})
		compactBundle2, _ := json.Marshal(map[string]interface{}{
			"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
			"verificationMaterial": map[string]interface{}{
				"x509CertificateChain": map[string]interface{}{
					"certificates": []map[string]interface{}{
						{"rawBytes": "dGVzdDI="},
					},
				},
			},
			"dsseEnvelope": map[string]interface{}{
				"payload":     "dGVzdDI=",
				"payloadType": "application/vnd.in-toto+json",
				"signatures":  []map[string]interface{}{{"sig": "dGVzdDI="}},
			},
		})

		jsonl := string(compactBundle1) + "\n" + string(compactBundle2)
		reader := strings.NewReader(jsonl)
		bundles, err := ParseBundles(reader)

		if err != nil {
			t.Fatalf("ParseBundles() unexpected error: %v", err)
		}

		if len(bundles) != 2 {
			t.Errorf("ParseBundles() got %d bundles, want 2", len(bundles))
		}
	})
}

func TestWriteBundles(t *testing.T) {
	bundles := []Bundle{
		{
			MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
			VerificationMaterial: VerificationMaterial{
				Certificate: &Certificate{
					Certificates: []CertificateBytes{
						{RawBytes: []byte("test")},
					},
				},
			},
			DsseEnvelope: &DsseEnvelope{
				Payload:     []byte("test"),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []DsseSignature{
					{Signature: []byte("test")},
				},
			},
		},
	}

	tmpFile, err := os.CreateTemp("", "write_test_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// test WriteBundles
	err = WriteBundles(tmpFile.Name(), bundles)
	if err != nil {
		t.Fatalf("WriteBundles() unexpected error: %v", err)
	}

	// verify file content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	// verify it's valid JSONL
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Errorf("WriteBundles() wrote %d lines, want 1", len(lines))
	}

	var bundle Bundle
	if err := json.Unmarshal([]byte(lines[0]), &bundle); err != nil {
		t.Errorf("WriteBundles() produced invalid JSON: %v", err)
	}
}

func TestGetSubjectFromBundle(t *testing.T) {
	payload := `{
		"predicate": {
			"subject": [
				{
					"name": "test-artifact",
					"digest": {
						"sha256": "abc123"
					}
				}
			]
		}
	}`

	bundle := Bundle{
		DsseEnvelope: &DsseEnvelope{
			Payload: []byte(payload),
		},
	}

	subject, err := GetSubjectFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetSubjectFromBundle() unexpected error: %v", err)
	}

	if subject.Name != "test-artifact" {
		t.Errorf("GetSubjectFromBundle() got name %s, want test-artifact", subject.Name)
	}

	if subject.Digest["sha256"] != "abc123" {
		t.Errorf("GetSubjectFromBundle() got digest %s, want abc123", subject.Digest["sha256"])
	}
}

func TestCalculateDigest(t *testing.T) {
	// create test file
	tmpFile, err := os.CreateTemp("", "digest_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	testContent := "test content for digest calculation"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	digest, err := CalculateDigest(tmpFile.Name())
	if err != nil {
		t.Fatalf("CalculateDigest() unexpected error: %v", err)
	}

	// verify digest format
	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("CalculateDigest() got %s, want sha256: prefix", digest)
	}

	expectedDigest := "sha256:6006530dfeecd81f631207610d204cbd241f1afa59a7940a366b78b37fa1d3bf"
	if digest != expectedDigest {
		t.Errorf("CalculateDigest() got %s, want %s", digest, expectedDigest)
	}
}

func TestValidateBundle(t *testing.T) {
	tests := []struct {
		name    string
		bundle  Bundle
		wantErr bool
	}{
		{
			name: "valid bundle with certificate and DSSE",
			bundle: Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				VerificationMaterial: VerificationMaterial{
					Certificate: &Certificate{
						Certificates: []CertificateBytes{
							{RawBytes: []byte("test")},
						},
					},
				},
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte("test"),
				},
			},
			wantErr: false,
		},
		{
			name: "missing mediaType",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{
					Certificate: &Certificate{
						Certificates: []CertificateBytes{
							{RawBytes: []byte("test")},
						},
					},
				},
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte("test"),
				},
			},
			wantErr: true,
		},
		{
			name: "missing both certificate and public key",
			bundle: Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte("test"),
				},
			},
			wantErr: true,
		},
		{
			name: "missing both message signature and DSSE envelope",
			bundle: Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				VerificationMaterial: VerificationMaterial{
					Certificate: &Certificate{
						Certificates: []CertificateBytes{
							{RawBytes: []byte("test")},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBundle(tt.bundle)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBundle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestLoadBundlesWithRealData tests bundle loading with real attestation data from testdata
func TestLoadBundlesWithRealData(t *testing.T) {
	testFiles := []string{
		"../../testdata/attestations/multi-type-attestations.jsonl",
		"../../testdata/attestations/single-slsa-provenance.json",
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(testFile), func(t *testing.T) {
			if _, err := os.Stat(testFile); os.IsNotExist(err) {
				t.Skipf("Test file not found: %s", testFile)
				return
			}

			// load bundles from real attestation file
			bundles, err := LoadBundles(testFile)
			if err != nil {
				t.Fatalf("Failed to load real attestation bundles: %v", err)
			}

			if len(bundles) == 0 {
				t.Fatal("Expected at least one bundle from real attestation file")
			}

			// validate each loaded bundle
			for i, bundle := range bundles {
				if err := ValidateBundle(bundle); err != nil {
					t.Fatalf("Bundle %d failed validation: %v", i, err)
				}

				// verify bundle has expected sigstore structure
				if !strings.Contains(bundle.MediaType, "sigstore.bundle") {
					t.Errorf("Expected sigstore bundle media type, got: %s", bundle.MediaType)
				}

				// verify verification material exists
				if bundle.VerificationMaterial.Certificate == nil && bundle.VerificationMaterial.PublicKey == nil {
					t.Error("Bundle missing both certificate and public key")
				}

				// verify signature material exists
				if bundle.MessageSignature == nil && bundle.DsseEnvelope == nil {
					t.Error("Bundle missing both message signature and DSSE envelope")
				}
			}

			t.Logf("Successfully loaded and validated %d real attestation bundles from %s",
				len(bundles), filepath.Base(testFile))
		})
	}
}

// TestWriteAndLoadRealBundles tests round-trip writing and loading with real data
func TestWriteAndLoadRealBundles(t *testing.T) {
	realAttestationFile := "../../testdata/attestations/multi-type-attestations.jsonl"
	if _, err := os.Stat(realAttestationFile); os.IsNotExist(err) {
		t.Skip("Real attestation file not available for testing")
	}

	// load real bundles
	originalBundles, err := LoadBundles(realAttestationFile)
	if err != nil {
		t.Fatalf("Failed to load real bundles: %v", err)
	}

	// create temp file for writing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-real-bundles.jsonl")

	// write bundles to temp file
	if err := WriteBundles(testFile, originalBundles); err != nil {
		t.Fatalf("Failed to write real bundles: %v", err)
	}

	// load bundles back from temp file
	loadedBundles, err := LoadBundles(testFile)
	if err != nil {
		t.Fatalf("Failed to load written bundles: %v", err)
	}

	// verify same number of bundles
	if len(originalBundles) != len(loadedBundles) {
		t.Fatalf("Expected %d bundles, got %d", len(originalBundles), len(loadedBundles))
	}

	// validate all loaded bundles
	for i, bundle := range loadedBundles {
		if err := ValidateBundle(bundle); err != nil {
			t.Fatalf("Loaded bundle %d failed validation: %v", i, err)
		}
	}

	t.Logf("Successfully performed round-trip test with %d real attestation bundles", len(originalBundles))
}
