// Package offline - trust.go
// Handles trusted root verification for offline attestation validation
package offline

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// TrustedRoot represents a trusted root configuration
type TrustedRoot struct {
	MediaType         string                  `json:"mediaType"`
	TlogRoots         []TransparencyLogRoot   `json:"tlogs"`
	CertificateAuthorities []CertificateAuthority `json:"certificateAuthorities"`
	CTLogRoots        []CTLogRoot             `json:"ctlogs"`
	TimestampAuthorities []TimestampAuthority   `json:"timestampAuthorities"`
}

// TransparencyLogRoot represents a transparency log root
type TransparencyLogRoot struct {
	BaseURL   string    `json:"baseUrl"`
	HashAlgorithm string `json:"hashAlgorithm"`
	PublicKey PublicKeyInfo `json:"publicKey"`
	LogID     LogIDInfo     `json:"logId"`
	ValidFor  *ValidityPeriod `json:"validFor,omitempty"`
}

// CertificateAuthority represents a certificate authority
type CertificateAuthority struct {
	Subject      SubjectInfo   `json:"subject"`
	URI          string        `json:"uri"`
	CertChain    CertChain     `json:"certChain"`
	ValidFor     *ValidityPeriod `json:"validFor,omitempty"`
}

// CTLogRoot represents a Certificate Transparency log root
type CTLogRoot struct {
	BaseURL   string        `json:"baseUrl"`
	HashAlgorithm string    `json:"hashAlgorithm"`
	PublicKey PublicKeyInfo `json:"publicKey"`
	LogID     []byte        `json:"logId"`
	ValidFor  *ValidityPeriod `json:"validFor,omitempty"`
}

// TimestampAuthority represents a timestamp authority
type TimestampAuthority struct {
	Subject      SubjectInfo   `json:"subject"`
	URI          string        `json:"uri"`
	CertChain    CertChain     `json:"certChain"`
	ValidFor     *ValidityPeriod `json:"validFor,omitempty"`
}

// PublicKeyInfo contains public key information
type PublicKeyInfo struct {
	RawBytes  []byte `json:"rawBytes"`
	KeyType   string `json:"keyDetails"`
	ValidFor  *ValidityPeriod `json:"validFor,omitempty"`
}

// LogIDInfo contains log identifier information
type LogIDInfo struct {
	KeyId []byte `json:"keyId"`
}

// SubjectInfo contains certificate subject information
type SubjectInfo struct {
	Organization string `json:"organization"`
	CommonName   string `json:"commonName"`
}

// CertChain represents a certificate chain
type CertChain struct {
	Certificates [][]byte `json:"certificates"`
}

// TrustedRootLoader handles loading and validating trusted roots
type TrustedRootLoader struct {
	trustedRoot *TrustedRoot
}

// LoadTrustedRoot loads trusted root from the embedded file
func LoadTrustedRoot() (*TrustedRootLoader, error) {
	// Load from embedded trusted root file
	trustedRootPath := "pkg/root/github-trusted-root.json"
	
	data, err := os.ReadFile(trustedRootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}

	var trustedRoot TrustedRoot
	if err := json.Unmarshal(data, &trustedRoot); err != nil {
		return nil, fmt.Errorf("failed to parse trusted root: %w", err)
	}

	return &TrustedRootLoader{
		trustedRoot: &trustedRoot,
	}, nil
}

// LoadTrustedRootFromFile loads trusted root from a custom file path
func LoadTrustedRootFromFile(filepath string) (*TrustedRootLoader, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root from %s: %w", filepath, err)
	}

	var trustedRoot TrustedRoot
	if err := json.Unmarshal(data, &trustedRoot); err != nil {
		return nil, fmt.Errorf("failed to parse trusted root: %w", err)
	}

	return &TrustedRootLoader{
		trustedRoot: &trustedRoot,
	}, nil
}

// ValidateCertificate validates a certificate against trusted CAs
func (trl *TrustedRootLoader) ValidateCertificate(certBytes []byte) error {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is not valid at current time")
	}

	// Validate against trusted CAs
	for _, ca := range trl.trustedRoot.CertificateAuthorities {
		if err := trl.validateAgainstCA(cert, ca); err == nil {
			return nil // Found valid CA
		}
	}

	return fmt.Errorf("certificate not signed by any trusted CA")
}

// validateAgainstCA validates a certificate against a specific CA
func (trl *TrustedRootLoader) validateAgainstCA(cert *x509.Certificate, ca CertificateAuthority) error {
	if len(ca.CertChain.Certificates) == 0 {
		return fmt.Errorf("CA has no certificates")
	}

	// Parse CA certificate
	caCert, err := x509.ParseCertificate(ca.CertChain.Certificates[0])
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Create certificate pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	return err
}

// ValidateTimestamp validates a timestamp against trusted TSAs
func (trl *TrustedRootLoader) ValidateTimestamp(timestampBytes []byte) error {
	// Basic timestamp validation - in production would implement full RFC 3161 validation
	if len(timestampBytes) == 0 {
		return fmt.Errorf("empty timestamp")
	}

	// For now, accept any non-empty timestamp
	// TODO: Implement full RFC 3161 timestamp validation
	return nil
}

// GetTrustedTLogs returns the list of trusted transparency logs
func (trl *TrustedRootLoader) GetTrustedTLogs() []TransparencyLogRoot {
	return trl.trustedRoot.TlogRoots
}

// ValidateTLogEntry validates a transparency log entry
func (trl *TrustedRootLoader) ValidateTLogEntry(entry TlogEntry) error {
	if entry.LogId == nil {
		return fmt.Errorf("tlog entry missing log ID")
	}

	// Find matching trusted log
	for _, tlog := range trl.trustedRoot.TlogRoots {
		if compareLogIDs(entry.LogId.KeyId, tlog.LogID.KeyId) {
			return trl.validateTLogEntryAgainstRoot(entry, tlog)
		}
	}

	return fmt.Errorf("tlog entry from untrusted log")
}

// validateTLogEntryAgainstRoot validates a tlog entry against a specific trusted root
func (trl *TrustedRootLoader) validateTLogEntryAgainstRoot(entry TlogEntry, root TransparencyLogRoot) error {
	// Basic validation - check if entry has required fields
	if entry.IntegratedTime == nil {
		return fmt.Errorf("tlog entry missing integrated time")
	}

	if len(entry.CanonicalizedBody) == 0 {
		return fmt.Errorf("tlog entry missing canonicalized body")
	}

	// TODO: Implement full cryptographic validation of tlog entry
	// This would include verifying the inclusion proof and signed entry timestamp
	
	return nil
}

// compareLogIDs compares two log IDs for equality
func compareLogIDs(id1, id2 []byte) bool {
	if len(id1) != len(id2) {
		return false
	}
	
	for i := range id1 {
		if id1[i] != id2[i] {
			return false
		}
	}
	
	return true
}

// ExtractCertificateIdentity extracts identity information from a certificate
func ExtractCertificateIdentity(certBytes []byte) (*CertificateIdentity, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	identity := &CertificateIdentity{
		Subject:  cert.Subject.String(),
		Issuer:   cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}

	// Extract SAN (Subject Alternative Names) for OIDC identity
	for _, san := range cert.URIs {
		identity.SubjectAlternativeNames = append(identity.SubjectAlternativeNames, san.String())
	}

	identity.SubjectAlternativeNames = append(identity.SubjectAlternativeNames, cert.EmailAddresses...)

	return identity, nil
}

// CertificateIdentity contains extracted certificate identity information
type CertificateIdentity struct {
	Subject                 string    `json:"subject"`
	Issuer                  string    `json:"issuer"`
	NotBefore               time.Time `json:"notBefore"`
	NotAfter                time.Time `json:"notAfter"`
	SubjectAlternativeNames []string  `json:"subjectAlternativeNames"`
}
