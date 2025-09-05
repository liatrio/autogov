package offline

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// Test data constants
const (
	testTrustedRootJSON = `{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": [
			{
				"baseUrl": "https://rekor.sigstore.dev",
				"hashAlgorithm": "SHA2_256",
				"publicKey": {
					"rawBytes": "dGVzdA==",
					"keyDetails": "ECDSA"
				},
				"logId": {
					"keyId": "dGVzdGxvZ2lk"
				}
			}
		],
		"certificateAuthorities": [
			{
				"subject": {
					"organization": "Test Org",
					"commonName": "Test CA"
				},
				"uri": "https://test-ca.example.com",
				"certChain": {
					"certificates": ["dGVzdGNlcnQ="]
				}
			}
		],
		"ctlogs": [],
		"timestampAuthorities": [
			{
				"subject": {
					"organization": "Test TSA",
					"commonName": "Test TSA"
				},
				"uri": "https://test-tsa.example.com",
				"certChain": {
					"certificates": ["dGVzdHRzYWNlcnQ="]
				}
			}
		]
	}`
)

func TestLoadTrustedRootFromFile(t *testing.T) {
	// create temporary test file
	tmpFile, err := os.CreateTemp("", "trust_test_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// write test trusted root data
	if _, err := tmpFile.WriteString(testTrustedRootJSON); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}
	_ = tmpFile.Close()

	tests := []struct {
		name     string
		filepath string
		wantErr  bool
	}{
		{
			name:     "valid trusted root file",
			filepath: tmpFile.Name(),
			wantErr:  false,
		},
		{
			name:     "nonexistent file",
			filepath: "/path/to/nonexistent/file.json",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader, err := LoadTrustedRootFromFile(tt.filepath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadTrustedRootFromFile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadTrustedRootFromFile() unexpected error: %v", err)
				return
			}

			if loader == nil {
				t.Errorf("LoadTrustedRootFromFile() returned nil loader")
				return
			}

			if loader.trustedRoot == nil {
				t.Errorf("LoadTrustedRootFromFile() trusted root is nil")
			}
		})
	}
}

func TestLoadTrustedRootFromFile_InvalidJSON(t *testing.T) {
	// create temporary file with invalid JSON
	tmpFile, err := os.CreateTemp("", "invalid_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString("invalid json content"); err != nil {
		t.Fatalf("failed to write invalid JSON: %v", err)
	}
	_ = tmpFile.Close()

	_, err = LoadTrustedRootFromFile(tmpFile.Name())
	if err == nil {
		t.Errorf("LoadTrustedRootFromFile() expected error for invalid JSON, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse trusted root") {
		t.Errorf("LoadTrustedRootFromFile() expected parse error, got: %v", err)
	}
}

func TestGetTrustedTLogs(t *testing.T) {
	// create loader with test data
	tmpFile, err := os.CreateTemp("", "trust_test_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(testTrustedRootJSON); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}
	_ = tmpFile.Close()

	loader, err := LoadTrustedRootFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadTrustedRootFromFile() unexpected error: %v", err)
	}

	tlogs := loader.GetTrustedTLogs()
	if len(tlogs) != 1 {
		t.Errorf("GetTrustedTLogs() returned %d logs, want 1", len(tlogs))
	}

	if tlogs[0].BaseURL != "https://rekor.sigstore.dev" {
		t.Errorf("GetTrustedTLogs() got base URL %s, want https://rekor.sigstore.dev", tlogs[0].BaseURL)
	}
}

func TestValidateTimestamp(t *testing.T) {
	loader := &TrustedRootLoader{
		trustedRoot: &TrustedRoot{},
	}

	tests := []struct {
		name          string
		timestampData []byte
		wantErr       bool
	}{
		{
			name:          "valid timestamp",
			timestampData: []byte("test timestamp data"),
			wantErr:       false,
		},
		{
			name:          "empty timestamp",
			timestampData: []byte{},
			wantErr:       true,
		},
		{
			name:          "nil timestamp",
			timestampData: nil,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loader.ValidateTimestamp(tt.timestampData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTimestamp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompareLogIDs(t *testing.T) {
	tests := []struct {
		name   string
		id1    []byte
		id2    []byte
		expect bool
	}{
		{
			name:   "identical IDs",
			id1:    []byte("testid"),
			id2:    []byte("testid"),
			expect: true,
		},
		{
			name:   "different IDs",
			id1:    []byte("testid1"),
			id2:    []byte("testid2"),
			expect: false,
		},
		{
			name:   "different lengths",
			id1:    []byte("short"),
			id2:    []byte("longer"),
			expect: false,
		},
		{
			name:   "empty IDs",
			id1:    []byte{},
			id2:    []byte{},
			expect: true,
		},
		{
			name:   "one empty, one not",
			id1:    []byte("test"),
			id2:    []byte{},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareLogIDs(tt.id1, tt.id2)
			if result != tt.expect {
				t.Errorf("compareLogIDs() = %v, want %v", result, tt.expect)
			}
		})
	}
}

func TestValidateTLogEntry(t *testing.T) {
	// create test loader
	loader := &TrustedRootLoader{
		trustedRoot: &TrustedRoot{
			TlogRoots: []TransparencyLogRoot{
				{
					BaseURL:       "https://rekor.sigstore.dev",
					HashAlgorithm: "SHA2_256",
					LogID: LogIDInfo{
						KeyId: []byte("testlogid"),
					},
				},
			},
		},
	}

	integratedTime := int64(1642723200)

	tests := []struct {
		name    string
		entry   TlogEntry
		wantErr bool
	}{
		{
			name: "valid entry",
			entry: TlogEntry{
				LogId: &LogId{
					KeyId: []byte("testlogid"),
				},
				IntegratedTime:    &integratedTime,
				CanonicalizedBody: []byte("test body"),
			},
			wantErr: false,
		},
		{
			name: "missing log ID",
			entry: TlogEntry{
				IntegratedTime:    &integratedTime,
				CanonicalizedBody: []byte("test body"),
			},
			wantErr: true,
		},
		{
			name: "untrusted log ID",
			entry: TlogEntry{
				LogId: &LogId{
					KeyId: []byte("unknownlogid"),
				},
				IntegratedTime:    &integratedTime,
				CanonicalizedBody: []byte("test body"),
			},
			wantErr: true,
		},
		{
			name: "missing integrated time",
			entry: TlogEntry{
				LogId: &LogId{
					KeyId: []byte("testlogid"),
				},
				CanonicalizedBody: []byte("test body"),
			},
			wantErr: true,
		},
		{
			name: "missing canonicalized body",
			entry: TlogEntry{
				LogId: &LogId{
					KeyId: []byte("testlogid"),
				},
				IntegratedTime: &integratedTime,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loader.ValidateTLogEntry(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTLogEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractCertificateIdentity(t *testing.T) {
	// generate a test certificate
	testCert := generateTestCertificate(t)

	tests := []struct {
		name     string
		certData []byte
		wantErr  bool
	}{
		{
			name:     "valid certificate",
			certData: testCert,
			wantErr:  false,
		},
		{
			name:     "invalid PEM",
			certData: []byte("invalid pem data"),
			wantErr:  true,
		},
		{
			name:     "empty certificate",
			certData: []byte{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ExtractCertificateIdentity(tt.certData)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExtractCertificateIdentity() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ExtractCertificateIdentity() unexpected error: %v", err)
				return
			}

			if identity == nil {
				t.Errorf("ExtractCertificateIdentity() returned nil identity")
				return
			}

			if identity.Subject == "" {
				t.Errorf("ExtractCertificateIdentity() subject is empty")
			}

			if identity.Issuer == "" {
				t.Errorf("ExtractCertificateIdentity() issuer is empty")
			}
		})
	}
}

func TestValidateCertificate_InvalidPEM(t *testing.T) {
	loader := &TrustedRootLoader{
		trustedRoot: &TrustedRoot{
			CertificateAuthorities: []CertificateAuthority{},
		},
	}

	err := loader.ValidateCertificate([]byte("invalid pem"))
	if err == nil {
		t.Errorf("ValidateCertificate() expected error for invalid PEM, got nil")
	}

	expectedMsg := "failed to decode PEM certificate"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("ValidateCertificate() expected error containing %q, got: %v", expectedMsg, err)
	}
}

func TestValidateCertificate_ExpiredCert(t *testing.T) {
	// create an expired certificate
	expiredCert := generateExpiredCertificate(t)

	loader := &TrustedRootLoader{
		trustedRoot: &TrustedRoot{
			CertificateAuthorities: []CertificateAuthority{},
		},
	}

	err := loader.ValidateCertificate(expiredCert)
	if err == nil {
		t.Errorf("ValidateCertificate() expected error for expired certificate, got nil")
	}

	expectedMsg := "certificate is not valid at current time"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("ValidateCertificate() expected error containing %q, got: %v", expectedMsg, err)
	}
}

func TestValidateAgainstCA_EmptyCA(t *testing.T) {
	loader := &TrustedRootLoader{}

	// create a test certificate
	testCert := createValidTestCertificate(t)

	ca := CertificateAuthority{
		CertChain: CertChain{
			Certificates: [][]byte{}, // empty certificates
		},
	}

	err := loader.validateAgainstCA(testCert, ca)
	if err == nil {
		t.Errorf("validateAgainstCA() expected error for empty CA, got nil")
	}

	expectedMsg := "CA has no certificates"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("validateAgainstCA() expected error containing %q, got: %v", expectedMsg, err)
	}
}

// Helper functions for generating test certificates

func generateTestCertificate(t *testing.T) []byte {
	t.Helper()

	// create a simple test certificate
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
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// generate key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// encode as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

func generateExpiredCertificate(t *testing.T) []byte {
	t.Helper()

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "expired.example.com",
		},
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-time.Hour), // expired
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
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

func createValidTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
