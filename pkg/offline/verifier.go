// Package offline provides functionality for offline attestation verification
// using pre-downloaded Sigstore bundles and trusted roots
package offline

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	bundleutils "github.com/liatrio/autogov-verify/pkg/bundle"
	"github.com/liatrio/autogov-verify/pkg/digest"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// offline attestation verification
type OfflineVerifier struct {
	trustedRoot *root.TrustedRoot
	bundles     []*bundle.Bundle
	options     VerifyOptions
}

// options for offline verification
type VerifyOptions struct {
	CertIdentity   string // expected certificate identity (workflow URL)
	CertOIDCIssuer string // expected OIDC issuer
	SkipTLogVerify bool   // skip transparency log verification (for compatibility)
	Quiet          bool   // suppress output messages
	SourceRef      string // expected source repository ref (e.g., refs/heads/main)
}

// attestation subject
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// result of offline verification
type VerificationResult struct {
	Verified            bool                `json:"verified"`
	Attestations        []AttestationResult `json:"attestations"`
	CertificateIdentity interface{}         `json:"certificateIdentity,omitempty"`
	PolicyCompliance    map[string]bool     `json:"policyCompliance,omitempty"`
	Errors              []string            `json:"errors,omitempty"`
	Warnings            []string            `json:"warnings,omitempty"`
}

// certificate identity information
type CertificateIdentity struct {
	SubjectAlternativeName string `json:"subjectAlternativeName"`
	Issuer                 string `json:"issuer"`
}

// result of verifying a single attestation
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

// loads trusted root from file or fetches default
func loadTrustedRoot(path string) (*root.TrustedRoot, error) {
	if path != "" {
		// load from file
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read trusted root file: %w", err)
			}
			return root.NewTrustedRootFromJSON(data)
		}
	}

	// embedded trusted root
	var data []byte
	data, err := os.ReadFile("pkg/root/github-trusted-root.json")
	if err != nil {
		// alternate path
		data, err = os.ReadFile("github-trusted-root.json")
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded trusted root: %w", err)
		}
	}
	return root.NewTrustedRootFromJSON(data)
}

// offline verifier with trusted root
func NewOfflineVerifier(trustedRootPath string, options VerifyOptions) (*OfflineVerifier, error) {
	tr, err := loadTrustedRoot(trustedRootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}

	return &OfflineVerifier{
		trustedRoot: tr,
		options:     options,
	}, nil
}

// loads bundles from a file
func (ov *OfflineVerifier) LoadBundlesFromFile(bundlePath string) error {
	bundles, err := LoadBundles(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load bundles: %w", err)
	}
	ov.bundles = bundles
	return nil
}

// verifies an artifact file against loaded bundles
func (ov *OfflineVerifier) VerifyArtifact(artifactPath string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	// calculates artifact digest if provided
	var expectedDigest string
	if artifactPath != "" {
		var err error
		expectedDigest, err = digest.CalculateFile(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate artifact digest: %w", err)
		}
	}

	return ov.verifyWithDigest(expectedDigest)
}

// verifies an artifact by its digest (useful for container images)
func (ov *OfflineVerifier) VerifyArtifactDigest(digest string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	return ov.verifyWithDigest(digest)
}

// performs verification with the given digest
func (ov *OfflineVerifier) verifyWithDigest(expectedDigest string) (*VerificationResult, error) {

	result := &VerificationResult{
		Attestations:     make([]AttestationResult, 0),
		PolicyCompliance: make(map[string]bool),
		Errors:           make([]string, 0),
		Warnings:         make([]string, 0),
	}

	// verifier
	verifierOpts := []verify.VerifierOption{
		verify.WithObserverTimestamps(1),
	}

	// skip tlog verification if requested
	if !ov.options.SkipTLogVerify {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	v, err := verify.NewVerifier(ov.trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// verify each bundle
	validAttestations := 0
	for i, b := range ov.bundles {
		// Show which attestation is being verified (like online mode)
		if !ov.options.Quiet {
			// Get attestation type for display
			attType := bundleutils.DetectType(b)
			fmt.Printf("Verifying attestation %d (%s)...\n", i+1, attType)
		}

		attestationResult := ov.verifyBundle(v, b, expectedDigest)
		result.Attestations = append(result.Attestations, attestationResult)

		if attestationResult.Verified {
			validAttestations++

			// Check for source ref in SLSA provenance attestations (inline like online mode)
			if !ov.options.Quiet && ov.options.SourceRef != "" && attestationResult.Type == "https://slsa.dev/provenance/v1" {
				if b.GetDsseEnvelope() != nil {
					payload := b.GetDsseEnvelope().GetPayload()
					var statement struct {
						PredicateType string `json:"predicateType"`
						Predicate     struct {
							BuildDefinition struct {
								ExternalParameters struct {
									Workflow struct {
										Ref string `json:"ref"`
									} `json:"workflow"`
								} `json:"externalParameters"`
							} `json:"buildDefinition"`
						} `json:"predicate"`
					}

					if err := json.Unmarshal(payload, &statement); err == nil {
						if statement.PredicateType == "https://slsa.dev/provenance/v1" {
							workflowRef := statement.Predicate.BuildDefinition.ExternalParameters.Workflow.Ref
							if workflowRef == ov.options.SourceRef {
								fmt.Printf("✓ Source repository ref verified: %s\n", ov.options.SourceRef)
							}
						}
					}
				}
			}

			if !ov.options.Quiet {
				fmt.Printf("✓ Attestation %d verified successfully\n", i+1)
				fmt.Println("---")
			}
		} else if !ov.options.Quiet {
			fmt.Printf("✗ Attestation %d verification failed: %s\n", i+1, attestationResult.Error)
			fmt.Println("---")
		}
	}

	// overall verification status
	result.Verified = validAttestations > 0

	// certificate identity from first valid attestation
	for _, att := range result.Attestations {
		if att.Verified && result.CertificateIdentity == nil {
			// identity will be set during verification
			break
		}
	}

	return result, nil
}

// verifies a single bundle using sigstore-go
func (ov *OfflineVerifier) verifyBundle(v *verify.Verifier, b *bundle.Bundle, expectedDigest string) AttestationResult {
	res := AttestationResult{
		Type:             "unknown",
		SignatureValid:   false,
		CertificateValid: false,
		TLogVerified:     false,
		Verified:         false,
	}

	// attestation type from envelope if available
	res.Type = bundleutils.DetectType(b)
	// subject
	if name, subjectDigest := bundleutils.ExtractSubject(b); name != "" {
		res.Subject = &Subject{
			Name:   name,
			Digest: subjectDigest,
		}
	}

	// artifact policy
	var artifactOpt verify.ArtifactPolicyOption
	if expectedDigest == "" {
		artifactOpt = verify.WithoutArtifactUnsafe()
	} else {
		// digest
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

	// policy options
	policyOpts := []verify.PolicyOption{}

	// certificate identity if specified
	if ov.options.CertIdentity != "" && ov.options.CertOIDCIssuer != "" {
		certID, err := verify.NewShortCertificateIdentity(ov.options.CertOIDCIssuer, "", ov.options.CertIdentity, "")
		if err == nil {
			policyOpts = append(policyOpts, verify.WithCertificateIdentity(certID))
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("failed to create identity policy: %v", err))
		}
	}

	policy := verify.NewPolicy(artifactOpt, policyOpts...)

	// verify bundle
	verificationResult, err := v.Verify(b, policy)
	if err != nil {
		res.Error = fmt.Sprintf("verification failed: %v", err)
		return res
	}

	// success
	res.SignatureValid = true
	res.CertificateValid = true
	res.Verified = true

	// verified identity if available
	if verificationResult.VerifiedIdentity != nil {
		res.CertificateValid = true
	}

	return res
}
