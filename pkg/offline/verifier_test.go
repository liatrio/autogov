package offline

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewOfflineVerifier(t *testing.T) {
	// create temporary trusted root file
	tmpFile, err := os.CreateTemp("", "verifier_test_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [],
		"certificateAuthorities": [],
		"ctlogs": [],
		"timestampAuthorities": []
	}`

	if _, err := tmpFile.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}
	_ = tmpFile.Close()

	tests := []struct {
		name            string
		trustedRootPath string
		options         VerifyOptions
		wantErr         bool
	}{
		{
			name:            "valid with custom trusted root",
			trustedRootPath: tmpFile.Name(),
			options:         VerifyOptions{},
			wantErr:         false,
		},
		{
			name:            "empty trusted root path uses default",
			trustedRootPath: "",
			options:         VerifyOptions{},
			wantErr:         true, // will fail because default trusted root doesn't exist
		},
		{
			name:            "invalid trusted root path",
			trustedRootPath: "/invalid/path/file.json",
			options:         VerifyOptions{},
			wantErr:         true,
		},
		{
			name:            "with verify options",
			trustedRootPath: tmpFile.Name(),
			options: VerifyOptions{
				CertIdentity:   "https://github.com/owner/repo/.github/workflows/test.yml@refs/heads/main",
				SkipTLogVerify: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewOfflineVerifier(tt.trustedRootPath, tt.options)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewOfflineVerifier() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewOfflineVerifier() unexpected error: %v", err)
				return
			}

			if verifier == nil {
				t.Errorf("NewOfflineVerifier() returned nil verifier")
				return
			}

			if verifier.trustedRootLoader == nil {
				t.Errorf("NewOfflineVerifier() trusted root loader is nil")
			}

			if verifier.options.CertIdentity != tt.options.CertIdentity {
				t.Errorf("NewOfflineVerifier() cert identity = %s, want %s", verifier.options.CertIdentity, tt.options.CertIdentity)
			}
		})
	}
}

func TestLoadBundlesFromFile(t *testing.T) {
	// create test verifier
	tmpRoot, err := os.CreateTemp("", "root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp root file: %v", err)
	}
	defer func() { _ = os.Remove(tmpRoot.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`
	if _, err := tmpRoot.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write root data: %v", err)
	}
	_ = tmpRoot.Close()

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// create test bundle file
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "verificationMaterial": {"x509CertificateChain": {"certificates": [{"rawBytes": "dGVzdA=="}]}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	tests := []struct {
		name       string
		bundlePath string
		wantErr    bool
	}{
		{
			name:       "valid bundle file",
			bundlePath: tmpBundle.Name(),
			wantErr:    false,
		},
		{
			name:       "nonexistent file",
			bundlePath: "/invalid/path/bundle.jsonl",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.LoadBundlesFromFile(tt.bundlePath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadBundlesFromFile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadBundlesFromFile() unexpected error: %v", err)
				return
			}

			if len(verifier.bundles) == 0 {
				t.Errorf("LoadBundlesFromFile() no bundles loaded")
			}
		})
	}
}

func TestVerifyArtifact(t *testing.T) {
	// create test artifact
	tmpArtifact, err := os.CreateTemp("", "artifact_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp artifact: %v", err)
	}
	defer func() { _ = os.Remove(tmpArtifact.Name()) }()

	if _, err := tmpArtifact.WriteString("test content"); err != nil {
		t.Fatalf("failed to write artifact content: %v", err)
	}
	_ = tmpArtifact.Close()

	// create test verifier
	tmpRoot, err := os.CreateTemp("", "root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp root file: %v", err)
	}
	defer func() { _ = os.Remove(tmpRoot.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`
	if _, err := tmpRoot.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write root data: %v", err)
	}
	_ = tmpRoot.Close()

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	tests := []struct {
		name         string
		setupBundles bool
		artifactPath string
		wantErr      bool
	}{
		{
			name:         "no bundles loaded",
			setupBundles: false,
			artifactPath: tmpArtifact.Name(),
			wantErr:      true,
		},
		{
			name:         "valid artifact with bundles",
			setupBundles: true,
			artifactPath: tmpArtifact.Name(),
			wantErr:      false,
		},
		{
			name:         "invalid artifact path",
			setupBundles: true,
			artifactPath: "/invalid/path/artifact.txt",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupBundles {
				// add a test bundle
				verifier.bundles = []Bundle{
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
							Payload:     []byte(`{"subject":[{"name":"test","digest":{"sha256":"unknown"}}]}`),
							PayloadType: "application/vnd.in-toto+json",
							Signatures: []DsseSignature{
								{Signature: []byte("test")},
							},
						},
					},
				}
			}

			result, err := verifier.VerifyArtifact(tt.artifactPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("VerifyArtifact() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("VerifyArtifact() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("VerifyArtifact() returned nil result")
				return
			}

			if result.Attestations == nil {
				t.Errorf("VerifyArtifact() attestations is nil")
			}
		})
	}
}

func TestDetectAttestationType(t *testing.T) {
	verifier := &OfflineVerifier{}

	tests := []struct {
		name     string
		bundle   Bundle
		expected string
	}{
		{
			name: "SLSA provenance",
			bundle: Bundle{
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte(`{"predicateType": "https://slsa.dev/provenance/v1"}`),
				},
			},
			expected: "slsa-provenance",
		},
		{
			name: "vulnerability scan",
			bundle: Bundle{
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte(`{"predicateType": "https://in-toto.io/attestation/vulns/v0.1"}`),
				},
			},
			expected: "vulnerability-scan",
		},
		{
			name: "SBOM",
			bundle: Bundle{
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte(`{"predicateType": "https://cyclonedx.org/bom"}`),
				},
			},
			expected: "sbom",
		},
		{
			name: "custom type",
			bundle: Bundle{
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte(`{"predicateType": "https://example.com/custom"}`),
				},
			},
			expected: "custom",
		},
		{
			name: "no DSSE envelope",
			bundle: Bundle{
				DsseEnvelope: nil,
			},
			expected: "unknown",
		},
		{
			name: "invalid JSON payload",
			bundle: Bundle{
				DsseEnvelope: &DsseEnvelope{
					Payload: []byte(`invalid json`),
				},
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.detectAttestationType(tt.bundle)
			if result != tt.expected {
				t.Errorf("detectAttestationType() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestDigestMatches(t *testing.T) {
	verifier := &OfflineVerifier{}

	subject := &Subject{
		Digest: map[string]string{
			"sha256": "abc123",
			"sha1":   "def456",
		},
	}

	tests := []struct {
		name           string
		subject        *Subject
		expectedDigest string
		expected       bool
	}{
		{
			name:           "matching sha256",
			subject:        subject,
			expectedDigest: "sha256:abc123",
			expected:       true,
		},
		{
			name:           "matching sha1",
			subject:        subject,
			expectedDigest: "sha1:def456",
			expected:       true,
		},
		{
			name:           "non-matching digest",
			subject:        subject,
			expectedDigest: "sha256:xyz789",
			expected:       false,
		},
		{
			name:           "non-matching algorithm",
			subject:        subject,
			expectedDigest: "md5:abc123",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.digestMatches(tt.subject, tt.expectedDigest)
			if result != tt.expected {
				t.Errorf("digestMatches() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchesCertificateIdentity(t *testing.T) {
	verifier := &OfflineVerifier{
		options: VerifyOptions{
			CertIdentity: "https://github.com/owner/repo/.github/workflows/test.yml@refs/heads/main",
		},
	}

	tests := []struct {
		name     string
		identity *CertificateIdentity
		expected bool
	}{
		{
			name: "matching SAN",
			identity: &CertificateIdentity{
				Subject: "CN=test",
				SubjectAlternativeNames: []string{
					"https://github.com/owner/repo/.github/workflows/test.yml@refs/heads/main",
				},
			},
			expected: true,
		},
		{
			name: "matching subject",
			identity: &CertificateIdentity{
				Subject:                 "https://github.com/owner/repo/.github/workflows/test.yml@refs/heads/main",
				SubjectAlternativeNames: []string{},
			},
			expected: true,
		},
		{
			name: "no match",
			identity: &CertificateIdentity{
				Subject: "CN=different",
				SubjectAlternativeNames: []string{
					"https://github.com/different/repo/.github/workflows/test.yml@refs/heads/main",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.matchesCertificateIdentity(tt.identity)
			if result != tt.expected {
				t.Errorf("matchesCertificateIdentity() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVerifySignatureErrors(t *testing.T) {
	verifier := &OfflineVerifier{}

	tests := []struct {
		name   string
		bundle Bundle
	}{
		{
			name: "no signature",
			bundle: Bundle{
				DsseEnvelope:     nil,
				MessageSignature: nil,
			},
		},
		{
			name: "empty DSSE signatures",
			bundle: Bundle{
				DsseEnvelope: &DsseEnvelope{
					Signatures: []DsseSignature{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.verifySignature(tt.bundle)
			if err == nil {
				t.Errorf("verifySignature() expected error, got nil")
			}
		})
	}
}

func TestExtractPublicKey(t *testing.T) {
	// create test certificate
	testCert := generateTestCertificateBytes(t)

	verifier := &OfflineVerifier{}

	tests := []struct {
		name    string
		bundle  Bundle
		wantErr bool
	}{
		{
			name: "valid certificate",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{
					Certificate: &Certificate{
						Certificates: []CertificateBytes{
							{RawBytes: testCert},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid public key",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{
					PublicKey: &PublicKey{
						RawBytes: []byte("test public key"),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no key or certificate",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{},
			},
			wantErr: true,
		},
		{
			name: "invalid certificate",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{
					Certificate: &Certificate{
						Certificates: []CertificateBytes{
							{RawBytes: []byte("invalid cert data")},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := verifier.extractPublicKey(tt.bundle)

			if tt.wantErr {
				if err == nil {
					t.Errorf("extractPublicKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("extractPublicKey() unexpected error: %v", err)
				return
			}

			if key == nil {
				t.Errorf("extractPublicKey() returned nil key")
			}
		})
	}
}

func TestVerifyWithPublicKey(t *testing.T) {
	verifier := &OfflineVerifier{}

	tests := []struct {
		name      string
		publicKey interface{}
		message   []byte
		signature []byte
		wantErr   bool
	}{
		{
			name:      "unsupported key type",
			publicKey: "string key",
			message:   []byte("test message"),
			signature: []byte("test signature"),
			wantErr:   true,
		},
		{
			name:      "nil key",
			publicKey: nil,
			message:   []byte("test message"),
			signature: []byte("test signature"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.verifyWithPublicKey(tt.publicKey, tt.message, tt.signature)

			if tt.wantErr {
				if err == nil {
					t.Errorf("verifyWithPublicKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("verifyWithPublicKey() unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyCertificate(t *testing.T) {
	// create test verifier with empty trusted root
	tmpRoot, err := os.CreateTemp("", "root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp root file: %v", err)
	}
	defer func() { _ = os.Remove(tmpRoot.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`
	if _, err := tmpRoot.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write root data: %v", err)
	}
	_ = tmpRoot.Close()

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		CertIdentity: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	tests := []struct {
		name   string
		bundle Bundle
	}{
		{
			name: "no certificate",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{},
			},
		},
		{
			name: "empty certificates",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{
					Certificate: &Certificate{
						Certificates: []CertificateBytes{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.verifyCertificate(tt.bundle)
			if err == nil {
				t.Errorf("verifyCertificate() expected error, got nil")
			}
		})
	}
}

func TestVerifyTLogEntries(t *testing.T) {
	// create test verifier
	tmpRoot, err := os.CreateTemp("", "root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp root file: %v", err)
	}
	defer func() { _ = os.Remove(tmpRoot.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`
	if _, err := tmpRoot.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write root data: %v", err)
	}
	_ = tmpRoot.Close()

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	tests := []struct {
		name   string
		bundle Bundle
	}{
		{
			name: "no tlog entries",
			bundle: Bundle{
				VerificationMaterial: VerificationMaterial{
					TlogEntries: []TlogEntry{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.verifyTLogEntries(tt.bundle)
			if err == nil {
				t.Errorf("verifyTLogEntries() expected error, got nil")
			}

			expectedMsg := "no transparency log entries found"
			if !strings.Contains(err.Error(), expectedMsg) {
				t.Errorf("verifyTLogEntries() expected error containing %q, got: %v", expectedMsg, err)
			}
		})
	}
}

// Helper function to generate test certificate bytes
func generateTestCertificateBytes(t *testing.T) []byte {
	t.Helper()

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		EmailAddresses: []string{"test@example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

// TestOfflineVerifierWithRealData tests offline verification with real attestation data
func TestOfflineVerifierWithRealData(t *testing.T) {
	realAttestationFile := "../../testdata/attestations/multi-type-attestations.jsonl"
	if _, err := os.Stat(realAttestationFile); os.IsNotExist(err) {
		t.Skip("Real attestation file not available for testing")
	}

	// create temp trusted root file for testing
	tmpRoot, err := os.CreateTemp("", "root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp root file: %v", err)
	}
	defer func() { _ = os.Remove(tmpRoot.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`
	if _, err := tmpRoot.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write root data: %v", err)
	}
	_ = tmpRoot.Close()

	// create offline verifier with mock trusted root
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{})
	if err != nil {
		t.Fatalf("NewOfflineVerifier() unexpected error: %v", err)
	}

	// test loading bundles from file
	err = verifier.LoadBundlesFromFile(realAttestationFile)
	if err != nil {
		t.Fatalf("LoadBundlesFromFile() with real data unexpected error: %v", err)
	}

	if len(verifier.bundles) == 0 {
		t.Fatal("Expected at least one bundle loaded from real attestation file")
	}

	// test attestation type detection with real bundles
	for i, bundle := range verifier.bundles {
		attestationType := verifier.detectAttestationType(bundle)
		if attestationType == "" {
			t.Errorf("Failed to detect attestation type for real bundle %d", i)
		}
		t.Logf("Real bundle %d detected as type: %s", i, attestationType)
	}

	t.Logf("Successfully tested offline verifier with %d real attestation bundles", len(verifier.bundles))
}

// TestVerifyArtifactWithRealBundles tests artifact verification using real attestation bundles
func TestVerifyArtifactWithRealBundles(t *testing.T) {
	realAttestationFile := "../../testdata/attestations/single-slsa-provenance.json"
	if _, err := os.Stat(realAttestationFile); os.IsNotExist(err) {
		t.Skip("Real attestation file not available for testing")
	}

	// create temp artifact file for testing
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "test-artifact")
	artifactContent := []byte("test artifact content for verification")
	if err := os.WriteFile(artifactPath, artifactContent, 0644); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	// create temp trusted root file for testing
	tmpRoot, err := os.CreateTemp("", "root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp root file: %v", err)
	}
	defer func() { _ = os.Remove(tmpRoot.Name()) }()

	trustedRootJSON := `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`
	if _, err := tmpRoot.WriteString(trustedRootJSON); err != nil {
		t.Fatalf("failed to write root data: %v", err)
	}
	_ = tmpRoot.Close()

	// create offline verifier with expected cert identity and mock trusted root
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		CertIdentity: "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main",
	})
	if err != nil {
		t.Fatalf("NewOfflineVerifier() unexpected error: %v", err)
	}

	// load real bundles from file
	err = verifier.LoadBundlesFromFile(realAttestationFile)
	if err != nil {
		t.Fatalf("LoadBundlesFromFile() unexpected error: %v", err)
	}

	// calculate artifact digest
	digest, err := CalculateDigest(artifactPath)
	if err != nil {
		t.Fatalf("Failed to calculate artifact digest: %v", err)
	}

	// test artifact verification (will likely fail due to digest mismatch, but should not error)
	// note: we expect this to fail because our test artifact doesn't match the real attestation
	result, err := verifier.VerifyArtifact(artifactPath)

	// this verification will fail because the test artifact doesn't match the real attestation digest
	// but we're testing that the verification process runs without panicking
	if err != nil {
		t.Logf("Expected verification failure with test artifact: %v", err)
	} else if result != nil {
		t.Logf("Verification result: verified=%v, attestations=%d", result.Verified, len(result.Attestations))
	}

	t.Logf("Successfully tested artifact verification process with real bundles (digest: %s)", digest)
}
