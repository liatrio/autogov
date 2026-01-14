package root

import (
	"encoding/json"
	"testing"
)

func TestFetchTrustedRoot(t *testing.T) {
	// embedded trusted root
	if len(GithubTrustedRoot) == 0 {
		t.Error("embedded GithubTrustedRoot is empty")
	}

	// verify valid JSON
	var trustedRoot map[string]interface{}
	if err := json.Unmarshal(GithubTrustedRoot, &trustedRoot); err != nil {
		t.Errorf("embedded GithubTrustedRoot is not valid JSON: %v", err)
	}

	// verify structure
	cas, ok := trustedRoot["certificateAuthorities"].([]interface{})
	if !ok {
		t.Error("embedded GithubTrustedRoot missing certificateAuthorities array")
		return
	}

	if len(cas) == 0 {
		t.Error("embedded GithubTrustedRoot has no certificate authorities")
		return
	}

	// verify each CA
	for i, caInterface := range cas {
		ca, ok := caInterface.(map[string]interface{})
		if !ok {
			t.Errorf("certificate authority %d is not an object", i)
			continue
		}

		// check required fields
		requiredFields := []string{"uri", "certChain", "validFor"}
		for _, field := range requiredFields {
			if _, ok := ca[field]; !ok {
				t.Errorf("certificate authority %d missing required field: %s", i, field)
			}
		}

		// check certChain is an object with required fields
		certChain, ok := ca["certChain"].(map[string]interface{})
		if !ok {
			t.Errorf("certificate authority %d certChain is not an object", i)
		} else {
			if _, ok := certChain["certificates"]; !ok {
				t.Errorf("certificate authority %d certChain missing certificates field", i)
			}
		}

		// check validFor is an object with start time
		validFor, ok := ca["validFor"].(map[string]interface{})
		if !ok {
			t.Errorf("certificate authority %d validFor is not an object", i)
		} else {
			if _, ok := validFor["start"]; !ok {
				t.Errorf("certificate authority %d validFor missing start field", i)
			}
		}
	}

	// tests gh-cli
	root, err := FetchTrustedRoot()
	if err != nil {
		// skip if gh-cli is not installed / authenticated
		t.Skipf("skipping GitHub CLI test: %v", err)
	}

	// check fetched root is valid JSON
	if err := json.Unmarshal(root, &trustedRoot); err != nil {
		t.Errorf("fetched trusted root is not valid JSON: %v", err)
	}

	// check fetched root has the same structure
	cas, ok = trustedRoot["certificateAuthorities"].([]interface{})
	if !ok {
		t.Error("fetched trusted root missing certificateAuthorities array")
		return
	}

	if len(cas) == 0 {
		t.Error("fetched trusted root has no certificate authorities")
	}
}

func TestTrustedRootContent(t *testing.T) {
	// check content of embedded root
	var trustedRoot struct {
		CertificateAuthorities []struct {
			URI       string `json:"uri"`
			CertChain struct {
				Certificates []interface{} `json:"certificates"`
			} `json:"certChain"`
			ValidFor struct {
				Start string `json:"start"`
				End   string `json:"end,omitempty"`
			} `json:"validFor"`
		} `json:"certificateAuthorities"`
	}

	if err := json.Unmarshal(GithubTrustedRoot, &trustedRoot); err != nil {
		t.Fatalf("failed to unmarshal trusted root: %v", err)
	}

	// check each CA's URI format
	for i, ca := range trustedRoot.CertificateAuthorities {
		if ca.URI == "" {
			t.Errorf("CA %d has empty URI", i)
		}
	}

	// check cert chain format
	for i, ca := range trustedRoot.CertificateAuthorities {
		if len(ca.CertChain.Certificates) == 0 {
			t.Errorf("CA %d has no certificates", i)
		}
		for j, cert := range ca.CertChain.Certificates {
			if cert == nil {
				t.Errorf("CA %d has nil certificate at position %d", i, j)
			}
		}
	}

	// check validFor timestamps
	for i, ca := range trustedRoot.CertificateAuthorities {
		if ca.ValidFor.Start == "" {
			t.Errorf("CA %d has no start time", i)
		}
	}
}

func TestPublicSigstoreTrustedRoot(t *testing.T) {
	// verify public Sigstore trusted root is embedded
	if len(PublicSigstoreTrustedRoot) == 0 {
		t.Error("embedded PublicSigstoreTrustedRoot is empty")
	}

	// verify valid JSON
	var trustedRoot map[string]interface{}
	if err := json.Unmarshal(PublicSigstoreTrustedRoot, &trustedRoot); err != nil {
		t.Errorf("embedded PublicSigstoreTrustedRoot is not valid JSON: %v", err)
	}

	// verify structure has certificate authorities
	cas, ok := trustedRoot["certificateAuthorities"].([]interface{})
	if !ok {
		t.Error("embedded PublicSigstoreTrustedRoot missing certificateAuthorities array")
		return
	}

	if len(cas) == 0 {
		t.Error("embedded PublicSigstoreTrustedRoot has no certificate authorities")
		return
	}

	// verify it contains fulcio.sigstore.dev (not GitHub's fulcio)
	foundPublicFulcio := false
	for _, caInterface := range cas {
		ca, ok := caInterface.(map[string]interface{})
		if !ok {
			continue
		}
		if uri, ok := ca["uri"].(string); ok && uri == "https://fulcio.sigstore.dev" {
			foundPublicFulcio = true
			break
		}
	}
	if !foundPublicFulcio {
		t.Error("PublicSigstoreTrustedRoot does not contain fulcio.sigstore.dev CA")
	}

	// verify timestamp authorities exist
	tsas, ok := trustedRoot["timestampAuthorities"].([]interface{})
	if !ok || len(tsas) == 0 {
		t.Error("PublicSigstoreTrustedRoot missing timestampAuthorities")
	}
}

func TestSelectTrustedRoot(t *testing.T) {
	tests := []struct {
		name           string
		source         TrustedRootSource
		certPEM        []byte
		expectedSource TrustedRootSource
		expectError    bool
	}{
		{
			name:           "explicit github source",
			source:         TrustedRootSourceGitHub,
			certPEM:        nil,
			expectedSource: TrustedRootSourceGitHub,
			expectError:    false,
		},
		{
			name:           "explicit public source",
			source:         TrustedRootSourcePublic,
			certPEM:        nil,
			expectedSource: TrustedRootSourcePublic,
			expectError:    false,
		},
		{
			name:           "auto without cert defaults to github",
			source:         TrustedRootSourceAuto,
			certPEM:        nil,
			expectedSource: TrustedRootSourceGitHub,
			expectError:    false,
		},
		{
			name:           "invalid source",
			source:         TrustedRootSource("invalid"),
			certPEM:        nil,
			expectedSource: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootData, actualSource, err := SelectTrustedRoot(tt.source, tt.certPEM)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if actualSource != tt.expectedSource {
				t.Errorf("expected source %s, got %s", tt.expectedSource, actualSource)
			}

			if len(rootData) == 0 {
				t.Errorf("expected non-empty root data")
			}

			// Verify returned data is valid JSON
			var trustedRoot map[string]interface{}
			if err := json.Unmarshal(rootData, &trustedRoot); err != nil {
				t.Errorf("returned root data is not valid JSON: %v", err)
			}
		})
	}
}

func TestDetectFromIssuer(t *testing.T) {
	tests := []struct {
		issuer         string
		expectedSource TrustedRootSource
	}{
		{GitHubActionsIssuer, TrustedRootSourceGitHub},
		{GoogleOIDCIssuer, TrustedRootSourcePublic},
		{GitHubOAuthIssuer, TrustedRootSourcePublic},
		{GitLabIssuer, TrustedRootSourcePublic},
		{"https://unknown-issuer.com", TrustedRootSourcePublic}, // default to public for unknown
	}

	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			result := detectFromIssuer(tt.issuer)
			if result != tt.expectedSource {
				t.Errorf("issuer %s: expected %s, got %s", tt.issuer, tt.expectedSource, result)
			}
		})
	}
}

func TestGetPublicTrustedRoot(t *testing.T) {
	root := GetPublicTrustedRoot()
	if len(root) == 0 {
		t.Error("GetPublicTrustedRoot returned empty data")
	}

	// Should match embedded variable
	if string(root) != string(PublicSigstoreTrustedRoot) {
		t.Error("GetPublicTrustedRoot does not match PublicSigstoreTrustedRoot")
	}
}

func TestGetGitHubTrustedRoot(t *testing.T) {
	root := GetGitHubTrustedRoot()
	if len(root) == 0 {
		t.Error("GetGitHubTrustedRoot returned empty data")
	}

	// Should match embedded variable
	if string(root) != string(GithubTrustedRoot) {
		t.Error("GetGitHubTrustedRoot does not match GithubTrustedRoot")
	}
}

func TestGetTrustedRoot(t *testing.T) {
	// GetTrustedRoot attempts to fetch dynamically, then falls back to embedded
	// In most test environments, dynamic fetch will fail (no gh CLI auth)
	root, err := GetTrustedRoot()
	if err != nil {
		t.Errorf("GetTrustedRoot() unexpected error: %v", err)
	}

	if len(root) == 0 {
		t.Error("GetTrustedRoot() returned empty data")
	}

	// Verify it's valid JSON
	var trustedRoot map[string]interface{}
	if err := json.Unmarshal(root, &trustedRoot); err != nil {
		t.Errorf("GetTrustedRoot() returned invalid JSON: %v", err)
	}
}

func TestDetectTrustedRootFromCertInvalidPEM(t *testing.T) {
	// Test with invalid PEM data
	invalidPEM := []byte("not valid PEM data")

	_, err := DetectTrustedRootFromCert(invalidPEM)
	if err == nil {
		t.Error("DetectTrustedRootFromCert() with invalid PEM expected error")
	}
}

func TestDetectTrustedRootFromCertEmptyInput(t *testing.T) {
	// Test with empty input
	_, err := DetectTrustedRootFromCert([]byte{})
	if err == nil {
		t.Error("DetectTrustedRootFromCert() with empty input expected error")
	}
}

func TestDetectTrustedRootFromCertValidPEM(t *testing.T) {
	// Create a simple self-signed cert PEM for testing
	// This is a minimal valid certificate structure
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBkjCB/AIJAKHBfpWTbMdJMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC0WnHJXW0PZmHSxJJSAAIL
MjxEFPzLPFRTvuCRWKkHKPxcJhQcVgDkGQYfkBzHK8A0LqHKKQHXN8HXFsVxjH/9
AgMBAAGjUDBOMB0GA1UdDgQWBBQvZ8dIhO8kgXVqvH4S3D5W5ZYNKTAFBGMFAADB
MB8GA1UdIwQYMBaAFC9nx0iE7ySBdWq8fhLcPlbllg0pMA0GCSqGSIb3DQEBCwUA
A0EA
-----END CERTIFICATE-----`

	// This cert won't have the Fulcio OIDC extension, so it should try the fallback
	source, err := DetectTrustedRootFromCert([]byte(certPEM))
	if err == nil {
		// If it succeeds, we got a source
		t.Logf("DetectTrustedRootFromCert() detected source: %s", source)
	} else {
		// If it fails due to no OIDC issuer, that's expected
		t.Logf("DetectTrustedRootFromCert() error (expected for test cert): %v", err)
	}
}

func TestDetectFromIssuerWithGitHubVariants(t *testing.T) {
	tests := []struct {
		issuer         string
		expectedSource TrustedRootSource
	}{
		// GitHub Actions
		{GitHubActionsIssuer, TrustedRootSourceGitHub},
		// Other GitHub-related patterns
		{"https://github.com/actions/checkout", TrustedRootSourceGitHub},
		// Non-GitHub
		{GoogleOIDCIssuer, TrustedRootSourcePublic},
		{GitHubOAuthIssuer, TrustedRootSourcePublic},
		{GitLabIssuer, TrustedRootSourcePublic},
		// Unknown defaults to public
		{"https://example.com/oidc", TrustedRootSourcePublic},
	}

	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			result := detectFromIssuer(tt.issuer)
			if result != tt.expectedSource {
				t.Errorf("issuer %s: expected %s, got %s", tt.issuer, tt.expectedSource, result)
			}
		})
	}
}

func TestSelectTrustedRootWithCertPEM(t *testing.T) {
	// Test SelectTrustedRoot with auto source and a cert PEM that can't be parsed
	invalidCertPEM := []byte("invalid cert data")

	rootData, source, err := SelectTrustedRoot(TrustedRootSourceAuto, invalidCertPEM)
	if err != nil {
		t.Errorf("SelectTrustedRoot() with invalid cert should still work (default): %v", err)
	}

	// Should default to GitHub when cert parsing fails
	if source != TrustedRootSourceGitHub {
		t.Errorf("expected source %s (default), got %s", TrustedRootSourceGitHub, source)
	}

	if len(rootData) == 0 {
		t.Error("expected non-empty root data")
	}
}

func TestTrustedRootSourceConstants(t *testing.T) {
	// Verify constants are as expected
	if TrustedRootSourceGitHub != "github" {
		t.Error("TrustedRootSourceGitHub should be 'github'")
	}
	if TrustedRootSourcePublic != "public" {
		t.Error("TrustedRootSourcePublic should be 'public'")
	}
	if TrustedRootSourceAuto != "auto" {
		t.Error("TrustedRootSourceAuto should be 'auto'")
	}
}

func TestOIDCIssuerConstants(t *testing.T) {
	// Verify OIDC issuer constants
	if GitHubActionsIssuer != "https://token.actions.githubusercontent.com" {
		t.Error("GitHubActionsIssuer constant incorrect")
	}
	if GoogleOIDCIssuer != "https://accounts.google.com" {
		t.Error("GoogleOIDCIssuer constant incorrect")
	}
	if GitHubOAuthIssuer != "https://github.com/login/oauth" {
		t.Error("GitHubOAuthIssuer constant incorrect")
	}
	if GitLabIssuer != "https://gitlab.com" {
		t.Error("GitLabIssuer constant incorrect")
	}
}
