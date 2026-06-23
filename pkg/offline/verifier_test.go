package offline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bundleutils "github.com/liatrio/autogov/pkg/bundle"
)

// the offline policy build is driven by AcceptedIdentities: a non-empty allowlist
// (even with an empty --cert-identity) takes the identity branch — observable via the
// issuer-default warning it emits — instead of the accept-any (WithoutIdentitiesUnsafe)
// branch. this is the offline counterpart of the online multi-identity policy.
func TestOfflineAcceptedIdentitiesSelectsIdentityBranch(t *testing.T) {
	dir := t.TempDir()

	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, []byte(`{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "verificationMaterial": {"x509CertificateChain": {"certificates": [{"rawBytes": "dGVzdA=="}]}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	const issuerWarning = "no OIDC issuer specified"

	newV := func(t *testing.T, opts VerifyOptions) *OfflineVerifier {
		t.Helper()
		opts.SkipTLogVerify = true
		opts.Quiet = true
		v, err := NewOfflineVerifier(rootPath, opts)
		if err != nil {
			t.Fatalf("NewOfflineVerifier: %v", err)
		}
		if err := v.LoadBundlesFromFile(bundlePath); err != nil {
			t.Fatalf("LoadBundlesFromFile: %v", err)
		}
		return v
	}

	hasWarning := func(res *VerificationResult, sub string) bool {
		for _, att := range res.Attestations {
			for _, w := range att.Warnings {
				if strings.Contains(w, sub) {
					return true
				}
			}
		}
		return false
	}

	// allowlist supplied, no explicit issuer → identity branch → issuer-default warning
	withList := newV(t, VerifyOptions{AcceptedIdentities: []string{"https://github.com/liatrio/test/.github/workflows/wf.yml@refs/heads/main"}})
	res, err := withList.VerifyArtifactDigest("")
	if err != nil {
		t.Fatalf("VerifyArtifactDigest (allowlist): %v", err)
	}
	if !hasWarning(res, issuerWarning) {
		t.Errorf("expected identity branch (issuer-default warning) when AcceptedIdentities is set; attestations: %+v", res.Attestations)
	}

	// no identities at all → accept-any branch → no issuer warning
	none := newV(t, VerifyOptions{})
	res2, err := none.VerifyArtifactDigest("")
	if err != nil {
		t.Fatalf("VerifyArtifactDigest (none): %v", err)
	}
	if hasWarning(res2, issuerWarning) {
		t.Errorf("expected accept-any branch (no issuer warning) when no identities supplied; attestations: %+v", res2.Attestations)
	}
}

// when an allowlist is enforced, a multi-bundle set where one bundle verifies but another
// is signed by a non-allowlisted signer must fail overall (the #258 image+VSA case) —
// offline parity with the online path. Without an allowlist, a non-allowlisted signer
// error is tolerated (accept-any) and only integrity failures fail the run.
func TestAggregateHasFailures(t *testing.T) {
	verified := AttestationResult{Verified: true}
	identityFail := AttestationResult{Verified: false, Error: "no matching CertificateIdentity found, got [https://github.com/x/.github/workflows/rogue.yml@refs/heads/main]"}
	integrityFail := AttestationResult{Verified: false, Error: "verification failed: artifact digest does not match"}

	cases := []struct {
		name      string
		enforcing bool
		atts      []AttestationResult
		want      bool
	}{
		{"enforced: one verified + one non-allowlisted signer fails overall", true, []AttestationResult{verified, identityFail}, true},
		{"enforced: all verified", true, []AttestationResult{verified, verified}, false},
		{"enforced: integrity failure", true, []AttestationResult{verified, integrityFail}, true},
		{"no allowlist: non-allowlisted signer tolerated", false, []AttestationResult{verified, identityFail}, false},
		{"no allowlist: integrity failure still fails", false, []AttestationResult{integrityFail}, true},
		{"no allowlist: all verified", false, []AttestationResult{verified}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aggregateHasFailures(tc.enforcing, tc.atts); got != tc.want {
				t.Errorf("aggregateHasFailures(enforcing=%v) = %v, want %v", tc.enforcing, got, tc.want)
			}
		})
	}
}

// a direct caller passing an empty SAN in the allowlist must fail closed — an empty
// subject makes sigstore's identity matcher match ANY cert from the issuer (accept-any).
func TestEmptyAcceptedIdentityFailsClosed(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, []byte(`{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
	}`), 0644); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "verificationMaterial": {"x509CertificateChain": {"certificates": [{"rawBytes": "dGVzdA=="}]}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	v, err := NewOfflineVerifier(rootPath, VerifyOptions{SkipTLogVerify: true, Quiet: true, AcceptedIdentities: []string{""}})
	if err != nil {
		t.Fatalf("NewOfflineVerifier: %v", err)
	}
	if err := v.LoadBundlesFromFile(bundlePath); err != nil {
		t.Fatalf("LoadBundlesFromFile: %v", err)
	}

	res, err := v.VerifyArtifactDigest("")
	if err != nil {
		t.Fatalf("VerifyArtifactDigest: %v", err)
	}
	if res.Verified {
		t.Error("expected verification to fail closed for an empty accepted identity")
	}
	found := false
	for _, a := range res.Attestations {
		if strings.Contains(a.Error, "empty certificate identity") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an 'empty certificate identity' error; attestations: %+v", res.Attestations)
	}
}

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
			wantErr:         false, // uses embedded trusted root as fallback
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
		attestationType := bundleutils.DetectType(bundle)
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

func TestVerifyArtifactDigest(t *testing.T) {
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	tests := []struct {
		name    string
		digest  string
		wantErr bool
	}{
		{
			name:    "no bundles loaded",
			digest:  "sha256:abc123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.VerifyArtifactDigest(tt.digest)

			if tt.wantErr {
				if err == nil {
					t.Errorf("VerifyArtifactDigest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("VerifyArtifactDigest() unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyArtifactDirectory(t *testing.T) {
	// Create a temp directory with artifacts
	tmpDir, err := os.MkdirTemp("", "artifacts_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create some artifact files
	if err := os.WriteFile(tmpDir+"/artifact1.txt", []byte("test artifact 1"), 0644); err != nil {
		t.Fatalf("failed to write artifact1: %v", err)
	}
	if err := os.WriteFile(tmpDir+"/artifact2.txt", []byte("test artifact 2"), 0644); err != nil {
		t.Fatalf("failed to write artifact2: %v", err)
	}

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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Test with no bundles
	_, err = verifier.VerifyArtifact(tmpDir)
	if err == nil {
		t.Error("VerifyArtifact() on directory with no bundles expected error")
	}
}

func TestVerifyArtifactEmptyDirectory(t *testing.T) {
	// Create an empty temp directory
	tmpDir, err := os.MkdirTemp("", "empty_artifacts_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load some bundles first
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

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test with empty directory - should fail because no files found
	_, err = verifier.VerifyArtifact(tmpDir)
	if err == nil {
		t.Error("VerifyArtifact() on empty directory expected error")
	}
}

func TestVerifyArtifactNoPath(t *testing.T) {
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load some bundles first
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

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test with empty path (attestation-only verification)
	result, err := verifier.VerifyArtifact("")
	if err != nil {
		t.Errorf("VerifyArtifact() with empty path unexpected error: %v", err)
		return
	}

	// Should get a result (though may not be verified without proper bundles)
	if result == nil {
		t.Error("VerifyArtifact() with empty path returned nil result")
	}
}

func TestLoadTrustedRootWithSource(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		source  string
		wantErr bool
	}{
		{
			name:    "empty path and empty source uses default",
			path:    "",
			source:  "",
			wantErr: false,
		},
		{
			name:    "source github",
			path:    "",
			source:  "github",
			wantErr: false,
		},
		{
			name:    "source public",
			path:    "",
			source:  "public",
			wantErr: false,
		},
		{
			name:    "source auto",
			path:    "",
			source:  "auto",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewOfflineVerifier(tt.path, VerifyOptions{
				TrustedRootSource: tt.source,
				Quiet:             true,
			})

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
				t.Error("NewOfflineVerifier() returned nil")
			}
		})
	}
}

func TestVerifyOptionsDefaults(t *testing.T) {
	// Test cert identity without issuer (should default to GitHub Actions)
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
		CertIdentity: "https://github.com/owner/repo/.github/workflows/test.yml@refs/heads/main",
		// No CertOIDCIssuer - should default
		Quiet: true,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	if verifier.options.CertIdentity == "" {
		t.Error("CertIdentity should be preserved")
	}
}

func TestVerificationResultTypes(t *testing.T) {
	// Test that struct types work correctly
	result := &VerificationResult{
		Verified:     true,
		Attestations: []AttestationResult{},
		Errors:       []string{},
		Warnings:     []string{},
	}

	if !result.Verified {
		t.Error("VerificationResult.Verified should be true")
	}

	att := AttestationResult{
		Type:             "test-type",
		Verified:         true,
		SignatureValid:   true,
		CertificateValid: true,
		TLogVerified:     false,
	}

	if att.Type != "test-type" {
		t.Error("AttestationResult.Type should be 'test-type'")
	}

	subject := &Subject{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "abc123"},
	}

	if subject.Name != "test-subject" {
		t.Error("Subject.Name should be 'test-subject'")
	}

	certId := &CertificateIdentity{
		SubjectAlternativeName: "test-san",
		Issuer:                 "test-issuer",
	}

	if certId.Issuer != "test-issuer" {
		t.Error("CertificateIdentity.Issuer should be 'test-issuer'")
	}
}

func TestVerifyDirectoryVerbose(t *testing.T) {
	// Create a temp directory with artifacts
	tmpDir, err := os.MkdirTemp("", "verbose_artifacts_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create artifact files
	if err := os.WriteFile(tmpDir+"/artifact1.txt", []byte("test artifact 1"), 0644); err != nil {
		t.Fatalf("failed to write artifact1: %v", err)
	}
	if err := os.WriteFile(tmpDir+"/artifact2.txt", []byte("test artifact 2"), 0644); err != nil {
		t.Fatalf("failed to write artifact2: %v", err)
	}

	// Create subdirectory (should be skipped)
	if err := os.MkdirAll(tmpDir+"/subdir", 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// create test verifier with Quiet=false to exercise verbose paths
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: false})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Test with no bundles - should fail
	_, err = verifier.VerifyArtifact(tmpDir)
	if err == nil {
		t.Error("VerifyArtifact() on directory with no bundles expected error")
	}
}

func TestVerifyWithSourceRef(t *testing.T) {
	// Create temp trusted root
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

	// Create verifier with source ref option
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		Quiet:     true,
		SourceRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Without bundles, verification should fail
	_, err = verifier.VerifyArtifact("")
	if err == nil {
		t.Error("VerifyArtifact() without bundles should fail")
	}
}

func TestVerifyWithCertIdentityNoIssuer(t *testing.T) {
	// Create temp trusted root
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

	// Create verifier with cert identity but no issuer - should default to GitHub
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		Quiet:        true,
		CertIdentity: "test@example.com",
		// CertOIDCIssuer left empty - should default
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Without bundles, verification should fail
	_, err = verifier.VerifyArtifact("")
	if err == nil {
		t.Error("VerifyArtifact() without bundles should fail")
	}
}

func TestVerifyWithCertIdentityAndIssuer(t *testing.T) {
	// Create temp trusted root
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

	// Create verifier with both cert identity and issuer
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		Quiet:          true,
		CertIdentity:   "test@example.com",
		CertOIDCIssuer: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Without bundles, verification should fail
	_, err = verifier.VerifyArtifact("")
	if err == nil {
		t.Error("VerifyArtifact() without bundles should fail")
	}
}

func TestVerifyDigestInvalidFormat(t *testing.T) {
	// Create temp trusted root
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Create a temp bundle file
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test with invalid hex digest
	result, err := verifier.VerifyArtifactDigest("sha256:not-valid-hex")
	if err == nil && result != nil && result.Verified {
		t.Error("VerifyArtifactDigest() with invalid hex should fail or return unverified result")
	}
}

func TestVerifyDigestWithAlgorithm(t *testing.T) {
	// Create temp trusted root
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Create a temp bundle file
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test with algorithm prefix
	_, err = verifier.VerifyArtifactDigest("sha512:abc123def456")
	// Will fail verification but exercises the digest parsing code path
	if err == nil {
		t.Log("VerifyArtifactDigest() succeeded unexpectedly")
	}
}

func TestVerifyArtifactWithValidFile(t *testing.T) {
	// Create temp trusted root
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Create a temp artifact file
	tmpArtifact, err := os.CreateTemp("", "artifact_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp artifact file: %v", err)
	}
	defer func() { _ = os.Remove(tmpArtifact.Name()) }()

	if _, err := tmpArtifact.WriteString("test artifact content"); err != nil {
		t.Fatalf("failed to write artifact data: %v", err)
	}
	_ = tmpArtifact.Close()

	// Create a temp bundle file
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test with file - will fail verification but exercises file handling code path
	_, err = verifier.VerifyArtifact(tmpArtifact.Name())
	if err == nil {
		t.Log("VerifyArtifact() with file succeeded unexpectedly")
	}
}

func TestSkipTLogVerify(t *testing.T) {
	// Create temp trusted root
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

	// Test with SkipTLogVerify=false (will add tlog verification requirement)
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		Quiet:          true,
		SkipTLogVerify: false,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Without bundles, verification should fail
	_, err = verifier.VerifyArtifact("")
	if err == nil {
		t.Error("VerifyArtifact() without bundles should fail")
	}
}

func TestVerifyDirectoryWithBundles(t *testing.T) {
	// Create a temp directory with artifacts
	tmpDir, err := os.MkdirTemp("", "dir_bundles_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create artifact files
	if err := os.WriteFile(tmpDir+"/artifact1.txt", []byte("test artifact 1"), 0644); err != nil {
		t.Fatalf("failed to write artifact1: %v", err)
	}

	// Create temp trusted root
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

	// Create verifier with verbose mode to hit the directory output code
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: false})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load a bundle
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Verify directory with bundles loaded - will fail verification but exercises the directory paths
	result, err := verifier.VerifyArtifact(tmpDir)
	if err == nil && result != nil && result.Verified {
		t.Log("VerifyArtifact() on directory succeeded unexpectedly")
	}
}

func TestVerifyWithBundlesVerboseFailure(t *testing.T) {
	// Create temp trusted root
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

	// Create verifier with verbose mode
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: false})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load a bundle
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Verify without artifact - exercises the verbose failure output path
	result, err := verifier.VerifyArtifact("")
	if err == nil && result != nil && result.Verified {
		t.Log("VerifyArtifact() succeeded unexpectedly")
	}
}

func TestVerifyMultipleBundlesVerbose(t *testing.T) {
	// Create temp trusted root
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

	// Create verifier with verbose mode
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: false})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load multiple bundles
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	// Two bundles - one standard, one with unknown type
	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}
{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdDI=", "payloadType": "application/custom-type+json", "signatures": [{"sig": "dGVzdDI="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Verify - exercises the verbose output with multiple bundles and unknown type warning
	result, err := verifier.VerifyArtifact("")
	if err == nil && result != nil && result.Verified {
		t.Log("VerifyArtifact() with multiple bundles succeeded unexpectedly")
	}
}

func TestVerificationResultStructure(t *testing.T) {
	// Test VerificationResult struct construction
	result := &VerificationResult{
		Verified:         true,
		Attestations:     make([]AttestationResult, 0),
		PolicyCompliance: make(map[string]bool),
		Errors:           make([]string, 0),
		Warnings:         make([]string, 0),
	}

	// Add attestation result
	att := AttestationResult{
		Type:             "https://slsa.dev/provenance/v1",
		Verified:         true,
		SignatureValid:   true,
		CertificateValid: true,
		TLogVerified:     false,
		Subject: &Subject{
			Name:   "test-subject",
			Digest: map[string]string{"sha256": "abc123"},
		},
	}
	result.Attestations = append(result.Attestations, att)
	result.PolicyCompliance["test-policy"] = true

	if len(result.Attestations) != 1 {
		t.Error("VerificationResult should have 1 attestation")
	}
	if !result.PolicyCompliance["test-policy"] {
		t.Error("PolicyCompliance should be true for test-policy")
	}
}

func TestAttestationResultWithWarnings(t *testing.T) {
	att := AttestationResult{
		Type:             "test-type",
		Verified:         true,
		SignatureValid:   true,
		CertificateValid: true,
		TLogVerified:     false,
		Warnings:         []string{"warning1", "warning2"},
	}

	if len(att.Warnings) != 2 {
		t.Error("AttestationResult should have 2 warnings")
	}
}

func TestVerifyBundleWithCertIdentityNoIssuerWarning(t *testing.T) {
	// Create temp trusted root
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

	// Create verifier with cert identity but no issuer - should trigger defaulting warning
	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{
		Quiet:        false, // verbose to see warning output
		CertIdentity: "test@example.com",
		// CertOIDCIssuer left empty - should trigger default
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load a bundle
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Verify - exercises the cert identity path with default issuer
	result, err := verifier.VerifyArtifact("")
	if err == nil && result != nil && result.Verified {
		t.Log("VerifyArtifact() succeeded unexpectedly")
	}
}

func TestVerifyReadDirError(t *testing.T) {
	// Create temp trusted root
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load a bundle
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test with non-existent directory
	_, err = verifier.VerifyArtifact("/nonexistent/directory/path")
	if err == nil {
		t.Error("VerifyArtifact() with nonexistent directory should fail")
	}
}

func TestLoadTrustedRootFromInvalidJSON(t *testing.T) {
	// Create temp file with invalid JSON
	tmpFile, err := os.CreateTemp("", "invalid_root_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString("not valid json"); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	_, err = NewOfflineVerifier(tmpFile.Name(), VerifyOptions{})
	if err == nil {
		t.Error("NewOfflineVerifier() with invalid JSON should fail")
	}
}

func TestVerifyWithRealAttestationsGitHubRoot(t *testing.T) {
	// Test using real attestations with the default GitHub trusted root
	realAttestationFile := "../../../testdata/real_attestations.jsonl"
	if _, err := os.Stat(realAttestationFile); os.IsNotExist(err) {
		t.Skip("Skipping test: real attestation file not found")
	}

	// Create verifier with default GitHub trusted root (empty path = use default)
	verifier, err := NewOfflineVerifier("", VerifyOptions{
		Quiet:          false,
		SkipTLogVerify: true, // Skip tlog verification in offline mode
	})
	if err != nil {
		t.Fatalf("NewOfflineVerifier() unexpected error: %v", err)
	}

	// Load real attestation bundles
	if err := verifier.LoadBundlesFromFile(realAttestationFile); err != nil {
		t.Fatalf("LoadBundlesFromFile() unexpected error: %v", err)
	}

	// Try to verify - this will exercise the verification paths
	// May fail due to expired certs or missing tlog, but exercises the code
	result, err := verifier.VerifyArtifact("")
	if err != nil {
		t.Logf("Verification error (expected in test context): %v", err)
	}
	if result != nil {
		t.Logf("Verification result: verified=%v, attestations=%d", result.Verified, len(result.Attestations))
		for i, att := range result.Attestations {
			t.Logf("  Attestation %d: type=%s, verified=%v, error=%s", i+1, att.Type, att.Verified, att.Error)
		}
	}
}

func TestVerifyBundleDigestParsing(t *testing.T) {
	// Create temp trusted root
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

	verifier, err := NewOfflineVerifier(tmpRoot.Name(), VerifyOptions{Quiet: true})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Load a bundle
	tmpBundle, err := os.CreateTemp("", "bundle_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp bundle file: %v", err)
	}
	defer func() { _ = os.Remove(tmpBundle.Name()) }()

	bundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpBundle.WriteString(bundleJSON); err != nil {
		t.Fatalf("failed to write bundle data: %v", err)
	}
	_ = tmpBundle.Close()

	if err := verifier.LoadBundlesFromFile(tmpBundle.Name()); err != nil {
		t.Fatalf("failed to load bundles: %v", err)
	}

	// Test various digest formats
	testDigests := []string{
		"abcd1234", // no algorithm prefix
		"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // with algorithm
		"sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce", // different algorithm
	}

	for _, digest := range testDigests {
		_, err := verifier.VerifyArtifactDigest(digest)
		// Verification will fail but we're testing digest parsing
		t.Logf("VerifyArtifactDigest(%s): %v", digest, err)
	}
}
