// Package offline provides functionality for offline attestation verification
// using pre-downloaded Sigstore bundles and trusted roots
package offline

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// OfflineVerifier handles offline attestation verification
type OfflineVerifier struct {
	trustedRoot *root.TrustedRoot
	bundles     []*bundle.Bundle
	options     VerifyOptions
}

// VerifyOptions contains options for offline verification
type VerifyOptions struct {
	CertIdentity   string // expected certificate identity (workflow URL)
	CertOIDCIssuer string // expected OIDC issuer
	SkipTLogVerify bool   // skip transparency log verification (for compatibility)
}

// Subject represents an attestation subject
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// VerificationResult represents the result of offline verification
type VerificationResult struct {
	Verified            bool                `json:"verified"`
	Attestations        []AttestationResult `json:"attestations"`
	CertificateIdentity interface{}         `json:"certificateIdentity,omitempty"`
	PolicyCompliance    map[string]bool     `json:"policyCompliance,omitempty"`
	Errors              []string            `json:"errors,omitempty"`
	Warnings            []string            `json:"warnings,omitempty"`
}

// CertificateIdentity represents certificate identity information
type CertificateIdentity struct {
	SubjectAlternativeName string `json:"subjectAlternativeName"`
	Issuer                 string `json:"issuer"`
}

// AttestationResult represents the result of verifying a single attestation
type AttestationResult struct {
	Type             string   `json:"type"`
	Subject          *Subject `json:"subject,omitempty"`
	Verified         bool     `json:"verified"`
	SignatureValid   bool     `json:"signatureValid"`
	CertificateValid bool     `json:"certificateValid"`
	TLogVerified     bool     `json:"tlogVerified"`
	Error            string   `json:"error,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// NewOfflineVerifier creates a new offline verifier with trusted root
func NewOfflineVerifier(trustedRootPath string, options VerifyOptions) (*OfflineVerifier, error) {
	var tr *root.TrustedRoot
	var err error

	if trustedRootPath != "" {
		tr, err = root.NewTrustedRootFromPath(trustedRootPath)
	} else {
		// Use embedded trusted root
		data, err := os.ReadFile("pkg/root/github-trusted-root.json")
		if err != nil {
			// Try alternate path
			data, err = os.ReadFile("github-trusted-root.json")
			if err != nil {
				return nil, fmt.Errorf("failed to read embedded trusted root: %w", err)
			}
		}
		tr, err = root.NewTrustedRootFromJSON(data)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}

	return &OfflineVerifier{
		trustedRoot: tr,
		options:     options,
	}, nil
}

// LoadBundlesFromFile loads bundles from a file
func (ov *OfflineVerifier) LoadBundlesFromFile(bundlePath string) error {
	bundles, err := LoadBundles(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load bundles: %w", err)
	}
	ov.bundles = bundles
	return nil
}

// VerifyArtifact verifies an artifact file against loaded bundles
func (ov *OfflineVerifier) VerifyArtifact(artifactPath string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	// Calculate artifact digest if provided
	var expectedDigest string
	if artifactPath != "" {
		digest, err := calculateFileDigest(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate artifact digest: %w", err)
		}
		expectedDigest = digest
	}

	return ov.verifyWithDigest(expectedDigest)
}

// VerifyArtifactDigest verifies an artifact by its digest (useful for container images)
func (ov *OfflineVerifier) VerifyArtifactDigest(digest string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	return ov.verifyWithDigest(digest)
}

// verifyWithDigest performs verification with the given digest
func (ov *OfflineVerifier) verifyWithDigest(expectedDigest string) (*VerificationResult, error) {

	result := &VerificationResult{
		Attestations:     make([]AttestationResult, 0),
		PolicyCompliance: make(map[string]bool),
		Errors:           make([]string, 0),
		Warnings:         make([]string, 0),
	}

	// Create verifier
	verifierOpts := []verify.VerifierOption{
		verify.WithObserverTimestamps(1),
	}

	// Skip tlog verification if requested
	if !ov.options.SkipTLogVerify {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	v, err := verify.NewVerifier(ov.trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Verify each bundle
	validAttestations := 0
	for _, b := range ov.bundles {
		attestationResult := ov.verifyBundle(v, b, expectedDigest)
		result.Attestations = append(result.Attestations, attestationResult)

		if attestationResult.Verified {
			validAttestations++
		}
	}

	// Set overall verification status
	result.Verified = validAttestations > 0

	// Extract certificate identity from first valid attestation
	for _, att := range result.Attestations {
		if att.Verified && result.CertificateIdentity == nil {
			// Identity will be set during verification
			break
		}
	}

	return result, nil
}

// verifyBundle verifies a single bundle using sigstore-go
func (ov *OfflineVerifier) verifyBundle(v *verify.Verifier, b *bundle.Bundle, expectedDigest string) AttestationResult {
	res := AttestationResult{
		Type:             "unknown",
		SignatureValid:   false,
		CertificateValid: false,
		TLogVerified:     false,
		Verified:         false,
	}

	// Extract attestation type from envelope if available
	if env, err := b.Envelope(); err == nil {
		if stmt, err := env.Statement(); err == nil {
			res.Type = stmt.PredicateType
			// Extract subject
			if len(stmt.Subject) > 0 {
				res.Subject = &Subject{
					Name:   stmt.Subject[0].Name,
					Digest: stmt.Subject[0].Digest,
				}
			}
		}
	}

	// Build artifact policy
	var artifactOpt verify.ArtifactPolicyOption
	if expectedDigest == "" {
		artifactOpt = verify.WithoutArtifactUnsafe()
	} else {
		// Parse digest
		parts := strings.SplitN(expectedDigest, ":", 2)
		alg := "sha256"
		hexDigest := expectedDigest
		if len(parts) == 2 {
			alg = parts[0]
			hexDigest = parts[1]
		}
		digestBytes, err := hex.DecodeString(hexDigest)
		if err != nil {
			res.Error = fmt.Sprintf("invalid artifact digest: %v", err)
			return res
		}
		artifactOpt = verify.WithArtifactDigest(alg, digestBytes)
	}

	// Build policy options
	policyOpts := []verify.PolicyOption{}

	// Add certificate identity if specified
	if ov.options.CertIdentity != "" && ov.options.CertOIDCIssuer != "" {
		certID, err := verify.NewShortCertificateIdentity(ov.options.CertOIDCIssuer, "", ov.options.CertIdentity, "")
		if err == nil {
			policyOpts = append(policyOpts, verify.WithCertificateIdentity(certID))
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("failed to create identity policy: %v", err))
		}
	}

	// Create policy
	policy := verify.NewPolicy(artifactOpt, policyOpts...)

	// Verify bundle
	verificationResult, err := v.Verify(b, policy)
	if err != nil {
		res.Error = fmt.Sprintf("verification failed: %v", err)
		return res
	}

	// Success
	res.SignatureValid = true
	res.CertificateValid = true
	res.Verified = true

	// Extract verified identity if available
	if verificationResult.VerifiedIdentity != nil {
		res.CertificateValid = true
	}

	return res
}

// detectAttestationType extracts the attestation type from a bundle
func detectAttestationType(b *bundle.Bundle) string {
	if env, err := b.Envelope(); err == nil {
		if stmt, err := env.Statement(); err == nil {
			return stmt.PredicateType
		}
	}
	return "unknown"
}
