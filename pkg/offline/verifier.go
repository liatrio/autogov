// provides functionality for offline attestation verification
// using pre-downloaded Sigstore bundles and trusted roots
package offline

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/liatrio/autogov/pkg/attestations"
	bundleutils "github.com/liatrio/autogov/pkg/bundle"
	"github.com/liatrio/autogov/pkg/digest"
	localroot "github.com/liatrio/autogov/pkg/root"
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
	CertIdentity       string   // expected certificate identity (workflow URL)
	CertOIDCIssuer     string   // expected OIDC issuer
	SkipTLogVerify     bool     // skip transparency log verification (for compatibility)
	Quiet              bool     // suppress output messages
	SourceRef          string   // expected source repository ref (e.g., refs/heads/main)
	TrustedRootSource  string   // trusted root source: github, public, or auto
	AcceptedIdentities []string // resolved signer allowlist (union of --cert-identity and the list); each attestation must match at least one (OR semantics)
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

// loads trusted root from file, source selection, or embedded default
func loadTrustedRoot(path string, source string) (*root.TrustedRoot, error) {
	// custom file takes precedence
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read trusted root file: %w", err)
		}
		fmt.Println("✓ Using custom trusted root file")
		return root.NewTrustedRootFromJSON(data)
	}

	// use source selection if specified
	if source != "" {
		trustedRootSource := localroot.TrustedRootSource(source)
		rootData, _, err := localroot.SelectTrustedRoot(trustedRootSource, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to select trusted root: %w", err)
		}
		return root.NewTrustedRootFromJSON(rootData)
	}

	// default to embedded github root
	if len(localroot.GithubTrustedRoot) == 0 {
		return nil, fmt.Errorf("embedded trusted root is empty")
	}
	fmt.Println("✓ Using GitHub trusted root (default)")
	return root.NewTrustedRootFromJSON(localroot.GithubTrustedRoot)
}

// offline verifier with trusted root
func NewOfflineVerifier(trustedRootPath string, options VerifyOptions) (*OfflineVerifier, error) {
	tr, err := loadTrustedRoot(trustedRootPath, options.TrustedRootSource)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}

	return &OfflineVerifier{
		trustedRoot: tr,
		options:     options,
	}, nil
}

// returns the loaded bundles (avoids reloading from file)
func (ov *OfflineVerifier) Bundles() []*bundle.Bundle {
	return ov.bundles
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

// verifies an artifact file or directory against loaded bundles
func (ov *OfflineVerifier) VerifyArtifact(artifactPath string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	// checks if path is a dir
	if artifactPath != "" {
		fileInfo, err := os.Stat(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat artifact path: %w", err)
		}

		if fileInfo.IsDir() {
			// handles directory of artifacts
			return ov.verifyDirectory(artifactPath)
		}

		// single file / calculate digest
		expectedDigest, err := digest.CalculateFile(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate artifact digest: %w", err)
		}
		return ov.verifyWithDigest(expectedDigest)
	}

	// No artifact path provided, verify attestations only
	return ov.verifyWithDigest("")
}

// verifies an artifact by its digest (useful for container images)
func (ov *OfflineVerifier) VerifyArtifactDigest(digest string) (*VerificationResult, error) {
	if len(ov.bundles) == 0 {
		return nil, fmt.Errorf("no bundles loaded for verification")
	}

	return ov.verifyWithDigest(digest)
}

// verifies all artifacts in a directory
func (ov *OfflineVerifier) verifyDirectory(dirPath string) (*VerificationResult, error) {
	// reads all files in the dir
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	// filters out directories and gets only files
	var artifactFiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			artifactFiles = append(artifactFiles, filepath.Join(dirPath, entry.Name()))
		}
	}

	if len(artifactFiles) == 0 {
		return nil, fmt.Errorf("no files found in directory %s", dirPath)
	}

	// for multiple artifacts, verify attestations without specific digest matching
	// the attestations themselves contain the subject digests
	if !ov.options.Quiet {
		fmt.Printf("Verifying %d artifact(s) in directory: %s\n", len(artifactFiles), dirPath)
		for _, file := range artifactFiles {
			fmt.Printf("  - %s\n", filepath.Base(file))
		}
	}

	// verify attestations without a specific artifact digest
	// validates the attestations are properly signed and match their internal subjects
	return ov.verifyWithDigest("")
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
		// show which attestation is being verified
		if !ov.options.Quiet {
			// get attestation type for display
			attType := bundleutils.DetectType(b)

			// lookup predicate type metadata for display
			var predicateInfo string
			if info, exists := attestations.LookupPredicateType(attType); exists {
				predicateInfo = fmt.Sprintf("%s: %s", info.ShortName, attType)
			} else {
				predicateInfo = fmt.Sprintf("Unknown: %s", attType)

				// log warning for unknown predicate types (already in !Quiet block)
				fmt.Fprintf(os.Stderr, "⚠ warning: unknown predicate type: %s\n", attType)
				fmt.Fprintf(os.Stderr, "  consider updating PredicateTypeRegistry if this is a standard type\n")
			}

			fmt.Printf("Verifying attestation %d (%s)...\n", i+1, predicateInfo)
		}

		attestationResult := ov.verifyBundle(v, b, expectedDigest)
		result.Attestations = append(result.Attestations, attestationResult)

		if !attestationResult.Verified {
			// if any attestation fails verification (bad signature, digest mismatch, etc.)
			// we should fail the entire verification process
			// error already printed in the per-attestation output if not quiet mode
			// continue to check all attestations to show all errors
		} else {
			validAttestations++

			// checks for source ref in SLSA provenance attestations
			if ov.options.SourceRef != "" && attestationResult.Type == "https://slsa.dev/provenance/v1" {
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
							if workflowRef != ov.options.SourceRef {
								// source ref mismatch / mark attestation as failed
								attestationResult.Verified = false
								attestationResult.Error = fmt.Sprintf("source ref mismatch: expected %s, found %s", ov.options.SourceRef, workflowRef)
								result.Attestations[i] = attestationResult
								validAttestations--
								if !ov.options.Quiet {
									fmt.Printf("✗ Source ref mismatch: expected %s, found %s\n", ov.options.SourceRef, workflowRef)
								}
							} else if !ov.options.Quiet {
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
		}

		if !attestationResult.Verified && !ov.options.Quiet {
			fmt.Printf("✗ Attestation %d verification failed: %s\n", i+1, attestationResult.Error)
			fmt.Println("---")
		}
	}

	// checks if any attestations had verification failures (not just cert-identity mismatches)
	hasVerificationFailures := false
	for _, att := range result.Attestations {
		if !att.Verified && att.Error != "" {
			// checks if it's a real verification failure vs just cert-identity mismatch
			if strings.Contains(att.Error, "digest does not match") ||
				strings.Contains(att.Error, "failed to verify signature") ||
				strings.Contains(att.Error, "transparency log") ||
				strings.Contains(att.Error, "source ref mismatch") {
				hasVerificationFailures = true
				break
			}
		}
	}

	// overall verification status - fail if there are real verification failures
	if hasVerificationFailures {
		result.Verified = false
	} else {
		result.Verified = validAttestations > 0
	}

	// certificate identity from first valid attestation
	for _, att := range result.Attestations {
		if att.Verified && result.CertificateIdentity == nil {
			// identity will be set during verification
			break
		}
	}

	return result, nil
}

// verifies a single bundle
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

	// build the accepted-identity set: --cert-identity (as-typed) unioned with any
	// pre-resolved allowlist SANs. each identity becomes one repeatable
	// WithCertificateIdentity, giving native OR semantics (match at least one).
	accepted := ov.options.AcceptedIdentities
	if ov.options.CertIdentity != "" && !slices.Contains(accepted, ov.options.CertIdentity) {
		accepted = append([]string{ov.options.CertIdentity}, accepted...)
	}

	if len(accepted) > 0 {
		// use a local issuer rather than mutating shared ov.options, so the
		// default-issuer warning fires per bundle and there is no cross-bundle state.
		issuer := ov.options.CertOIDCIssuer
		if issuer == "" {
			// identities specified but no issuer - use default GitHub Actions issuer
			issuer = "https://token.actions.githubusercontent.com"
			res.Warnings = append(res.Warnings, "no OIDC issuer specified, defaulting to GitHub Actions issuer")
		}
		for _, sub := range accepted {
			certID, err := verify.NewShortCertificateIdentity(issuer, "", sub, "")
			if err != nil {
				// fail closed: a malformed accepted identity must not fall through to accept-any
				res.Error = fmt.Sprintf("failed to create identity policy for %q: %v", sub, err)
				return res
			}
			policyOpts = append(policyOpts, verify.WithCertificateIdentity(certID))
		}
	} else {
		// no cert identity specified / verify signature but not identity
		// allows verification of attestation integrity without identity checks
		policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
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
