// Package offline - verifier.go
// Main offline verification logic using Sigstore bundles and trusted roots
package offline

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// handles offline attestation verification
type OfflineVerifier struct {
	trustedRootLoader *TrustedRootLoader
	bundles           []Bundle
	options           VerifyOptions
}

// options for offline verification
type VerifyOptions struct {
	CertIdentity      string   // expected certificate identity (workflow URL)
	CertIdentityRegex string   // regex pattern for certificate identity
	CertOIDCIssuer    string   // expected OIDC issuer
	PolicyURIs        []string // expected policy URIs
	SkipTLogVerify    bool     // skip transparency log verification
	SkipSCTVerify     bool     // skip certificate transparency verification
}

// result of offline verification
type VerificationResult struct {
	Verified            bool                 `json:"verified"`
	Attestations        []AttestationResult  `json:"attestations"`
	CertificateIdentity *CertificateIdentity `json:"certificateIdentity,omitempty"`
	PolicyCompliance    map[string]bool      `json:"policyCompliance,omitempty"`
	Errors              []string             `json:"errors,omitempty"`
	Warnings            []string             `json:"warnings,omitempty"`
}

// attestation result for a single attestation
type AttestationResult struct {
	Type             string   `json:"type"`
	Subject          *Subject `json:"subject"`
	Verified         bool     `json:"verified"`
	SignatureValid   bool     `json:"signatureValid"`
	CertificateValid bool     `json:"certificateValid"`
	TLogVerified     bool     `json:"tlogVerified"`
	Error            string   `json:"error,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// creates a new offline verifier
func NewOfflineVerifier(trustedRootPath string, options VerifyOptions) (*OfflineVerifier, error) {
	var loader *TrustedRootLoader
	var err error

	if trustedRootPath != "" {
		loader, err = LoadTrustedRootFromFile(trustedRootPath)
	} else {
		loader, err = LoadTrustedRoot()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}

	return &OfflineVerifier{
		trustedRootLoader: loader,
		options:           options,
	}, nil
}

// load bundles from a file
func (ov *OfflineVerifier) LoadBundlesFromFile(bundlePath string) error {
	bundles, err := LoadBundles(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load bundles: %w", err)
	}

	ov.bundles = bundles
	return nil
}

// verify artifact verifies an artifact against loaded bundles
func (ov *OfflineVerifier) VerifyArtifact(artifactPath string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	// calculate artifact digest
	expectedDigest, err := CalculateDigest(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate artifact digest: %w", err)
	}

	result := &VerificationResult{
		Attestations:     make([]AttestationResult, 0),
		PolicyCompliance: make(map[string]bool),
		Errors:           make([]string, 0),
		Warnings:         make([]string, 0),
	}

	// verify each bundle
	validAttestations := 0
	for _, bundle := range ov.bundles {
		attestationResult := ov.verifyBundle(bundle, expectedDigest)
		result.Attestations = append(result.Attestations, attestationResult)

		if attestationResult.Verified {
			validAttestations++
		}
	}

	// Set overall verification status
	result.Verified = validAttestations > 0

	// Extract certificate identity from first valid attestation
	for _, attestation := range result.Attestations {
		if attestation.Verified && result.CertificateIdentity == nil {
			if bundle := ov.findBundleForAttestation(attestation); bundle != nil {
				if certIdentity, err := ov.extractCertificateIdentity(*bundle); err == nil {
					result.CertificateIdentity = certIdentity
					break
				}
			}
		}
	}

	return result, nil
}

// verify bundle verifies a single bundle against the expected digest
func (ov *OfflineVerifier) verifyBundle(bundle Bundle, expectedDigest string) AttestationResult {
	result := AttestationResult{
		Type:             ov.detectAttestationType(bundle),
		SignatureValid:   false,
		CertificateValid: false,
		TLogVerified:     false,
		Verified:         false,
	}

	// validate bundle structure
	if err := ValidateBundle(bundle); err != nil {
		result.Error = fmt.Sprintf("bundle validation failed: %v", err)
		return result
	}

	// extract subject from bundle
	subject, err := GetSubjectFromBundle(bundle)
	if err != nil {
		result.Error = fmt.Sprintf("failed to extract subject: %v", err)
		return result
	}
	result.Subject = subject

	// check if subject digest matches expected artifact digest
	if !ov.digestMatches(subject, expectedDigest) {
		result.Error = "subject digest does not match artifact digest"
		return result
	}

	// verify signature
	if err := ov.verifySignature(bundle); err != nil {
		result.Error = fmt.Sprintf("signature verification failed: %v", err)
		return result
	}
	result.SignatureValid = true

	// verify certificate
	if err := ov.verifyCertificate(bundle); err != nil {
		result.Error = fmt.Sprintf("certificate verification failed: %v", err)
		return result
	}
	result.CertificateValid = true

	// verify transparency log entry (optional)
	if !ov.options.SkipTLogVerify {
		if err := ov.verifyTLogEntries(bundle); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("tlog verification failed: %v", err))
		} else {
			result.TLogVerified = true
		}
	}

	result.Verified = result.SignatureValid && result.CertificateValid
	return result
}

// verify signature verifies the signature in a bundle
func (ov *OfflineVerifier) verifySignature(bundle Bundle) error {
	if bundle.DsseEnvelope != nil {
		return ov.verifyDSSESignature(bundle)
	}

	if bundle.MessageSignature != nil {
		return ov.verifyMessageSignature(bundle)
	}

	return fmt.Errorf("no signature found in bundle")
}

// verify dSSE signature verifies a DSSE envelope signature
func (ov *OfflineVerifier) verifyDSSESignature(bundle Bundle) error {
	envelope := bundle.DsseEnvelope
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("no signatures found in DSSE envelope")
	}

	// extract public key or certificate
	publicKey, err := ov.extractPublicKey(bundle)
	if err != nil {
		return fmt.Errorf("failed to extract public key: %w", err)
	}

	// create canonical payload for verification
	canonicalPayload := fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(envelope.PayloadType), envelope.PayloadType,
		len(envelope.Payload), envelope.Payload)

	// verify signature
	signature := envelope.Signatures[0].Signature
	return ov.verifyWithPublicKey(publicKey, []byte(canonicalPayload), signature)
}

// verify message signature verifies a message signature
func (ov *OfflineVerifier) verifyMessageSignature(bundle Bundle) error {
	msgSig := bundle.MessageSignature
	if msgSig == nil {
		return fmt.Errorf("no message signature found")
	}

	publicKey, err := ov.extractPublicKey(bundle)
	if err != nil {
		return fmt.Errorf("failed to extract public key: %w", err)
	}

	return ov.verifyWithPublicKey(publicKey, msgSig.MessageDigest.Digest, msgSig.Signature)
}

// extract public key extracts the public key from a bundle
func (ov *OfflineVerifier) extractPublicKey(bundle Bundle) (interface{}, error) {
	vm := bundle.VerificationMaterial

	// try certificate first - check both formats
	var certBytes []byte
	if vm.Certificate != nil {
		// real sigstore format: rawBytes string
		if vm.Certificate.RawBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(vm.Certificate.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decode certificate rawBytes: %w", err)
			}
			certBytes = decoded
		} else if len(vm.Certificate.Certificates) > 0 {
			// test format: certificates array
			certBytes = vm.Certificate.Certificates[0].RawBytes
		}
	}

	// check x509CertificateChain field (alternative format)
	if certBytes == nil && vm.X509CertificateChain != nil {
		if vm.X509CertificateChain.RawBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(vm.X509CertificateChain.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decode x509CertificateChain rawBytes: %w", err)
			}
			certBytes = decoded
		} else if len(vm.X509CertificateChain.Certificates) > 0 {
			certBytes = vm.X509CertificateChain.Certificates[0].RawBytes
		}
	}

	if certBytes != nil {
		// try PEM format first
		block, _ := pem.Decode(certBytes)
		if block != nil {
			// PEM format
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
			}
			return cert.PublicKey, nil
		} else {
			// try DER format (raw binary certificate)
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
			}
			return cert.PublicKey, nil
		}
	}

	// try public key
	if vm.PublicKey != nil {
		// simplified implementation
		// production would need to handle different key types properly
		return vm.PublicKey.RawBytes, nil
	}

	return nil, fmt.Errorf("no public key or certificate found")
}

// verify with public key verifies a signature using a public key
func (ov *OfflineVerifier) verifyWithPublicKey(publicKey interface{}, message, signature []byte) error {
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, message, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil

	case *ecdsa.PublicKey:
		// ECDSA signature verification
		hash := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	case *rsa.PublicKey:
		// RSA signature verification with PSS padding
		hash := sha256.Sum256(message)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		if err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], signature, opts); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// verify certificate verifies the certificate in a bundle
func (ov *OfflineVerifier) verifyCertificate(bundle Bundle) error {
	vm := bundle.VerificationMaterial

	// extract certificate bytes - check both formats
	var certBytes []byte
	if vm.Certificate != nil {
		// real sigstore format: rawBytes string
		if vm.Certificate.RawBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(vm.Certificate.RawBytes)
			if err != nil {
				return fmt.Errorf("failed to decode certificate rawBytes: %w", err)
			}
			certBytes = decoded
		} else if len(vm.Certificate.Certificates) > 0 {
			// test format: certificates array
			certBytes = vm.Certificate.Certificates[0].RawBytes
		}
	}

	// check x509CertificateChain field (alternative format)
	if certBytes == nil && vm.X509CertificateChain != nil {
		if vm.X509CertificateChain.RawBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(vm.X509CertificateChain.RawBytes)
			if err != nil {
				return fmt.Errorf("failed to decode x509CertificateChain rawBytes: %w", err)
			}
			certBytes = decoded
		} else if len(vm.X509CertificateChain.Certificates) > 0 {
			certBytes = vm.X509CertificateChain.Certificates[0].RawBytes
		}
	}

	if certBytes == nil {
		return fmt.Errorf("no certificate found in bundle")
	}

	if err := ov.trustedRootLoader.ValidateCertificate(certBytes); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// verify certificate identity if specified
	if ov.options.CertIdentity != "" {
		identity, err := ExtractCertificateIdentity(certBytes)
		if err != nil {
			return fmt.Errorf("failed to extract certificate identity: %w", err)
		}

		if !ov.matchesCertificateIdentity(identity) {
			return fmt.Errorf("certificate identity does not match expected value")
		}
	}

	return nil
}

// verify tlog entries verifies transparency log entries in a bundle
func (ov *OfflineVerifier) verifyTLogEntries(bundle Bundle) error {
	vm := bundle.VerificationMaterial
	if len(vm.TlogEntries) == 0 {
		return fmt.Errorf("no transparency log entries found")
	}

	for _, entry := range vm.TlogEntries {
		if err := ov.trustedRootLoader.ValidateTLogEntry(entry); err != nil {
			return fmt.Errorf("tlog entry validation failed: %w", err)
		}
	}

	return nil
}

// helper functions

func (ov *OfflineVerifier) detectAttestationType(bundle Bundle) string {
	if bundle.DsseEnvelope == nil {
		return "unknown"
	}

	// parse payload to detect attestation type
	var envelope struct {
		PredicateType string `json:"predicateType"`
	}

	if err := json.Unmarshal(bundle.DsseEnvelope.Payload, &envelope); err != nil {
		return "unknown"
	}

	switch {
	case strings.Contains(envelope.PredicateType, "slsa.dev/provenance"):
		return "slsa-provenance"
	case strings.Contains(envelope.PredicateType, "vulns"):
		return "vulnerability-scan"
	case strings.Contains(envelope.PredicateType, "cyclonedx"):
		return "sbom"
	default:
		return "custom"
	}
}

func (ov *OfflineVerifier) digestMatches(subject *Subject, expectedDigest string) bool {
	for alg, digest := range subject.Digest {
		fullDigest := fmt.Sprintf("%s:%s", alg, digest)
		if fullDigest == expectedDigest {
			return true
		}
	}
	return false
}

func (ov *OfflineVerifier) matchesCertificateIdentity(identity *CertificateIdentity) bool {
	expectedIdentity := ov.options.CertIdentity

	// check subject alternative names (typically contains the workflow URL)
	for _, san := range identity.SubjectAlternativeNames {
		if san == expectedIdentity {
			return true
		}
	}

	// check subject
	if identity.Subject == expectedIdentity {
		return true
	}

	return false
}

func (ov *OfflineVerifier) findBundleForAttestation(attestation AttestationResult) *Bundle {
	for _, bundle := range ov.bundles {
		if subject, err := GetSubjectFromBundle(bundle); err == nil {
			if attestation.Subject != nil &&
				subject.Name == attestation.Subject.Name &&
				len(subject.Digest) > 0 && len(attestation.Subject.Digest) > 0 {
				// simple comparison / in production would do more thorough matching
				for alg, digest := range subject.Digest {
					if attestation.Subject.Digest[alg] == digest {
						return &bundle
					}
				}
			}
		}
	}
	return nil
}

func (ov *OfflineVerifier) extractCertificateIdentity(bundle Bundle) (*CertificateIdentity, error) {
	vm := bundle.VerificationMaterial

	// extract certificate bytes - check both formats
	var certBytes []byte
	if vm.Certificate != nil {
		// real sigstore format: rawBytes string
		if vm.Certificate.RawBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(vm.Certificate.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decode certificate rawBytes: %w", err)
			}
			certBytes = decoded
		} else if len(vm.Certificate.Certificates) > 0 {
			// test format: certificates array
			certBytes = vm.Certificate.Certificates[0].RawBytes
		}
	}

	// check x509CertificateChain field (alternative format)
	if certBytes == nil && vm.X509CertificateChain != nil {
		if vm.X509CertificateChain.RawBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(vm.X509CertificateChain.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decode x509CertificateChain rawBytes: %w", err)
			}
			certBytes = decoded
		} else if len(vm.X509CertificateChain.Certificates) > 0 {
			certBytes = vm.X509CertificateChain.Certificates[0].RawBytes
		}
	}

	if certBytes == nil {
		return nil, fmt.Errorf("no certificate found")
	}

	return ExtractCertificateIdentity(certBytes)
}
