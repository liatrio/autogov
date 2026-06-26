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
	SkipTLogVerify     bool     // force-skip transparency-log verification even when a bundle carries an entry (programmatic only; no CLI flag)
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
	ov := &OfflineVerifier{options: options}

	// an explicit root file or an explicit github/public source pins one trusted
	// root for every bundle. otherwise (the "auto" default, or unset) the root is
	// resolved per bundle from its signing cert, so a mixed set of public-good and
	// GitHub-internal attestations each verify against the right anchor.
	if trustedRootPath != "" || isExplicitSource(options.TrustedRootSource) {
		tr, err := loadTrustedRoot(trustedRootPath, options.TrustedRootSource)
		if err != nil {
			return nil, fmt.Errorf("failed to load trusted root: %w", err)
		}
		ov.trustedRoot = tr
	}

	return ov, nil
}

// isExplicitSource reports whether the source pins a specific root (github or
// public) rather than auto-selecting per bundle.
func isExplicitSource(source string) bool {
	return source == string(localroot.TrustedRootSourceGitHub) || source == string(localroot.TrustedRootSourcePublic)
}

// trustedRootForBundle returns the pinned root when one was selected, otherwise
// the root able to chain this bundle's signing cert (public-good for sigstore.dev
// certs, else GitHub).
func (ov *OfflineVerifier) trustedRootForBundle(b *bundle.Bundle) (*root.TrustedRoot, error) {
	if ov.trustedRoot != nil {
		return ov.trustedRoot, nil
	}
	rootData := localroot.GetGitHubTrustedRoot()
	if der := bundleutils.LeafCertDER(b); len(der) > 0 {
		if src, err := localroot.DetectTrustedRootFromCert(der); err == nil && src == localroot.TrustedRootSourcePublic {
			rootData = localroot.GetPublicTrustedRoot()
		}
	}
	if len(rootData) == 0 {
		return nil, fmt.Errorf("no trusted root available")
	}
	return root.NewTrustedRootFromJSON(rootData)
}

// verifierOpts returns the timestamp options for a bundle: always observer
// timestamps, plus a required transparency-log entry when the bundle carries one
// (so its integrated timestamp counts). The log entry is verified from the
// bundle's embedded inclusion proof, so this stays fully offline. SkipTLogVerify
// forces the log check off even when an entry is present.
func (ov *OfflineVerifier) verifierOpts(b *bundle.Bundle) []verify.VerifierOption {
	opts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if !ov.options.SkipTLogVerify && len(b.GetVerificationMaterial().GetTlogEntries()) > 0 {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	return opts
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

// verifies all artifacts in a directory.
//
// each file's sha256 is computed and bound to an attestation subject digest via
// WithArtifactDigest — the directory path never falls back to WithoutArtifactUnsafe,
// which would accept a validly-signed-but-unrelated bundle without matching any
// on-disk bytes (the asymmetric hole the single-file path never had).
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

	if !ov.options.Quiet {
		fmt.Printf("Verifying %d artifact(s) in directory: %s\n", len(artifactFiles), dirPath)
		for _, file := range artifactFiles {
			fmt.Printf("  - %s\n", filepath.Base(file))
		}
	}

	// single-file directory: identical to the single-file path. CalculateFile
	// returns sha256:<hex>, which verifyWithDigest parses and binds via
	// WithArtifactDigest. the production offline path pre-expands directories into
	// single files (cli.ExpandBlobPaths), so this is the common case.
	if len(artifactFiles) == 1 {
		expectedDigest, err := digest.CalculateFile(artifactFiles[0])
		if err != nil {
			return nil, fmt.Errorf("failed to calculate artifact digest: %w", err)
		}
		return ov.verifyWithDigest(expectedDigest)
	}

	// genuine multi-file directory: bind each file to its own digest, scoping each
	// per-file pass to only the bundle(s) whose subject digest matches that file so
	// non-matching siblings (file A's bundle vs file B) are not counted as failures.
	// require every file to bind to at least one verified, in-allowlist bundle.
	return ov.verifyDirectoryMultiFile(artifactFiles)
}

// verifyDirectoryMultiFile binds each file in a multi-file directory to its own
// digest. For each file it verifies only the bundles whose subject digest matches
// that file (so sibling files' bundles do not count as mismatches), and requires
// every file to bind to at least one verified bundle. Any file that matches no
// verified bundle fails the whole directory.
func (ov *OfflineVerifier) verifyDirectoryMultiFile(artifactFiles []string) (*VerificationResult, error) {
	result := &VerificationResult{
		Attestations:     make([]AttestationResult, 0),
		PolicyCompliance: make(map[string]bool),
		Errors:           make([]string, 0),
		Warnings:         make([]string, 0),
	}

	allFilesBound := true
	for _, file := range artifactFiles {
		fileDigest, err := digest.CalculateFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate digest for %s: %w", file, err)
		}

		// select only the bundles whose attested subject digest matches this file.
		matchingBundles := ov.bundlesMatchingDigest(fileDigest)
		if len(matchingBundles) == 0 {
			allFilesBound = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("no attestation subject matches file %s (%s)", filepath.Base(file), fileDigest))
			if !ov.options.Quiet {
				fmt.Printf("✗ No attestation subject matches %s\n", filepath.Base(file))
			}
			continue
		}

		// verify the matching bundles against this file's digest.
		fileResult, err := ov.verifyBundles(matchingBundles, fileDigest)
		if err != nil {
			return nil, err
		}
		result.Attestations = append(result.Attestations, fileResult.Attestations...)
		if !fileResult.Verified {
			allFilesBound = false
		}
	}

	result.Verified = allFilesBound && len(result.Attestations) > 0
	return result, nil
}

// bundlesMatchingDigest returns the loaded bundles whose attested subject digest
// equals the given digest (in sha256:<hex> or bare <hex> form).
func (ov *OfflineVerifier) bundlesMatchingDigest(expectedDigest string) []*bundle.Bundle {
	alg, hexDigest := splitDigest(expectedDigest)

	var matching []*bundle.Bundle
	for _, b := range ov.bundles {
		_, subjectDigest := bundleutils.ExtractSubject(b)
		if subjectDigest == nil {
			continue
		}
		if got, ok := subjectDigest[alg]; ok && strings.EqualFold(got, hexDigest) {
			matching = append(matching, b)
		}
	}
	return matching
}

// splitDigest parses a sha256:<hex> or bare <hex> digest into (alg, hex).
func splitDigest(d string) (alg, hexDigest string) {
	parts := strings.SplitN(d, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "sha256", d
}

// performs verification of all loaded bundles with the given digest
func (ov *OfflineVerifier) verifyWithDigest(expectedDigest string) (*VerificationResult, error) {
	return ov.verifyBundles(ov.bundles, expectedDigest)
}

// verifyBundles verifies the given bundles against expectedDigest and aggregates
// the per-bundle results into a single VerificationResult. An empty expectedDigest
// uses WithoutArtifactUnsafe (attestations-only path); a non-empty digest binds via
// WithArtifactDigest. Returns an error only for infrastructure failures (trusted
// root / verifier construction).
func (ov *OfflineVerifier) verifyBundles(bundles []*bundle.Bundle, expectedDigest string) (*VerificationResult, error) {
	result := &VerificationResult{
		Attestations:     make([]AttestationResult, 0),
		PolicyCompliance: make(map[string]bool),
		Errors:           make([]string, 0),
		Warnings:         make([]string, 0),
	}

	// verify each bundle
	validAttestations := 0
	for i, b := range bundles {
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

		// select the trusted root and timestamp options for this bundle so a mixed
		// set of public-good and GitHub-internal attestations each verify correctly.
		tr, err := ov.trustedRootForBundle(b)
		if err != nil {
			return nil, fmt.Errorf("failed to load trusted root: %w", err)
		}
		v, err := verify.NewVerifier(tr, ov.verifierOpts(b)...)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
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

	// when a signer allowlist is enforced, ANY unverified bundle is a hard failure
	// (including one whose signer is not in the allowlist — sigstore reports "no matching
	// CertificateIdentity"), matching the online path. Without an allowlist, only integrity
	// failures count, preserving the prior accept-any-signer behavior.
	enforcingAllowlist := ov.options.CertIdentity != "" || len(ov.options.AcceptedIdentities) > 0
	hasVerificationFailures := aggregateHasFailures(enforcingAllowlist, result.Attestations)

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

// aggregateHasFailures reports whether the per-bundle results should fail the overall
// offline verification. When a signer allowlist is enforced, ANY unverified bundle counts
// (a non-allowlisted signer must fail closed — sigstore reports "no matching
// CertificateIdentity", which is not one of the integrity-failure substrings below); this
// matches the online path and delivers offline parity. When no allowlist is enforced, only
// integrity failures (bad digest/signature/tlog/timestamp/source-ref) count, preserving the
// prior accept-any-signer behavior for unauthenticated runs.
func aggregateHasFailures(enforcingAllowlist bool, atts []AttestationResult) bool {
	for _, att := range atts {
		if att.Verified || att.Error == "" {
			continue
		}
		if enforcingAllowlist {
			return true
		}
		if strings.Contains(att.Error, "digest does not match") ||
			strings.Contains(att.Error, "failed to verify signature") ||
			strings.Contains(att.Error, "transparency log") ||
			strings.Contains(att.Error, "verify timestamps") ||
			strings.Contains(att.Error, "observer timestamp") ||
			strings.Contains(att.Error, "source ref mismatch") {
			return true
		}
	}
	return false
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
			if sub == "" {
				// defense-in-depth: an empty SAN makes sigstore's identity matcher match
				// ANY cert from the issuer (accept-any). The resolver never produces "",
				// but a direct caller could — fail closed.
				res.Error = "empty certificate identity in accepted allowlist"
				return res
			}
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
