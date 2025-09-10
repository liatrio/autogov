package offline

import (
	"os"
	"testing"
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

			if verifier.trustedRoot == nil {
				t.Errorf("NewOfflineVerifier() trusted root is nil")
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
			name:         "invalid artifact path",
			setupBundles: true,
			artifactPath: "/invalid/path/artifact.txt",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

// tests offline verification with real attestation data
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
		attestationType := detectAttestationType(bundle)
		if attestationType == "" {
			t.Errorf("Failed to detect attestation type for real bundle %d", i)
		}
		t.Logf("Real bundle %d detected as type: %s", i, attestationType)
	}

	t.Logf("Successfully tested offline verifier with %d real attestation bundles", len(verifier.bundles))
}

// tests artifact verification using real attestation bundles
func TestVerifyArtifactWithRealBundles(t *testing.T) {
	t.Skip("Skipping test that depends on real attestation files in old format")
}
