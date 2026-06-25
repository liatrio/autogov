// Package source provides verification of SLSA source provenance attestations.
// It validates Sigstore bundles containing source provenance predicates,
// checking repository URI, commit SHA, and computing SLSA Source Track levels.
package source

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	bundleutils "github.com/liatrio/autogov/pkg/bundle"
	localroot "github.com/liatrio/autogov/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyOptions configures source provenance verification.
type VerifyOptions struct {
	// RepoURI is the expected source repository URI.
	RepoURI string
	// Commit is the expected source commit SHA.
	Commit string
	// SourceRef is the expected source ref (e.g., refs/heads/main). Optional.
	SourceRef string
	// CertIdentity is the expected OIDC subject in the signing certificate.
	CertIdentity string
	// CertIssuer is the expected OIDC issuer URL.
	CertIssuer string
}

// VerificationResult holds the outcome of source provenance verification.
type VerificationResult struct {
	Verified        bool              `json:"verified"`
	RepoURI         string            `json:"repo_uri,omitempty"`
	Commit          string            `json:"commit,omitempty"`
	SourceRef       string            `json:"source_ref,omitempty"`
	SLSASourceLevel string            `json:"slsa_source_level,omitempty"`
	BuilderID       string            `json:"builder_id,omitempty"`
	Claims          map[string]string `json:"claims,omitempty"`
	ErrorMsg        string            `json:"error,omitempty"`
	Warnings        []string          `json:"warnings,omitempty"`
}

// inTotoStatement represents the relevant fields of an in-toto v1 statement.
type inTotoStatement struct {
	Type          string             `json:"_type"`
	PredicateType string             `json:"predicateType"`
	Subject       []statementSubject `json:"subject"`
	Predicate     json.RawMessage    `json:"predicate"`
}

// statementSubject represents a subject in an in-toto statement.
type statementSubject struct {
	URI    string            `json:"uri,omitempty"`
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// SourceProvenancePredicate represents relevant fields from a SLSA provenance predicate
// used for source provenance verification.
type SourceProvenancePredicate struct {
	BuildDefinition struct {
		BuildType          string `json:"buildType"`
		ExternalParameters struct {
			Repository string `json:"repository"`
			Ref        string `json:"ref"`
			Workflow   struct {
				Repository string `json:"repository"`
				Ref        string `json:"ref"`
				Path       string `json:"path"`
			} `json:"workflow"`
		} `json:"externalParameters"`
		ResolvedDependencies []struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata struct {
			InvocationID string `json:"invocationId"`
			StartedOn    string `json:"startedOn"`
		} `json:"metadata"`
	} `json:"runDetails"`
}

// Accepted predicate types for source provenance verification.
var acceptedPredicateTypes = []string{
	"https://slsa.dev/provenance/v1",
	"https://slsa.dev/source-provenance/v0.1",
}

// VerifySourceProvenance verifies a Sigstore bundle containing source provenance.
// It validates the bundle signature, extracts the in-toto statement, and checks
// that the repo URI and commit SHA match the expected values.
func VerifySourceProvenance(bundlePath string, opts VerifyOptions) (*VerificationResult, error) {
	result := &VerificationResult{
		Claims: make(map[string]string),
	}

	// Load the Sigstore bundle from file.
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("verify source: load bundle: %w", err)
	}

	// Load the trusted root able to chain this bundle's signing cert.
	trustedRoot, err := selectTrustedRootForBundle(b)
	if err != nil {
		return nil, fmt.Errorf("verify source: load trusted root: %w", err)
	}

	// Require the transparency-log entry when present so its integrated timestamp
	// counts toward the observer-timestamp threshold (public-good bundles carry no
	// TSA); GitHub-internal bundles instead use a TSA and carry no log entry.
	verifierOpts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if len(b.GetVerificationMaterial().GetTlogEntries()) > 0 {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}
	v, err := verify.NewVerifier(trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("verify source: create verifier: %w", err)
	}

	// Build verification policy.
	policyOpts := []verify.PolicyOption{}
	if opts.CertIdentity != "" {
		certIssuer := opts.CertIssuer
		if certIssuer == "" {
			certIssuer = "https://token.actions.githubusercontent.com"
		}
		certID, err := verify.NewShortCertificateIdentity(certIssuer, "", opts.CertIdentity, "")
		if err != nil {
			return nil, fmt.Errorf("verify source: create identity policy: %w", err)
		}
		policyOpts = append(policyOpts, verify.WithCertificateIdentity(certID))
	} else {
		policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
		result.Warnings = append(result.Warnings,
			"no --cert-identity provided; signer identity is not verified (any valid Sigstore signature accepted)")
	}
	policy := verify.NewPolicy(verify.WithoutArtifactUnsafe(), policyOpts...)

	// Verify the bundle.
	_, err = v.Verify(b, policy)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("signature verification failed: %v", err)
		return result, nil
	}

	// Extract the in-toto statement from the DSSE envelope.
	envelope := b.GetDsseEnvelope()
	if envelope == nil {
		result.ErrorMsg = "bundle does not contain a DSSE envelope"
		return result, nil
	}

	payload := envelope.GetPayload()
	if len(payload) == 0 {
		result.ErrorMsg = "DSSE envelope has no payload"
		return result, nil
	}

	// Parse the in-toto statement.
	var statement inTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse in-toto statement: %v", err)
		return result, nil
	}

	// Check predicate type.
	if !isAcceptedPredicateType(statement.PredicateType) {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("unexpected predicate type %q; attempting parse anyway", statement.PredicateType))
	}

	// Parse the source provenance predicate.
	var pred SourceProvenancePredicate
	if err := json.Unmarshal(statement.Predicate, &pred); err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse source provenance predicate: %v", err)
		return result, nil
	}

	// Extract claims from the predicate.
	repoURI := extractRepoURI(statement, pred)
	commitSHA := extractCommitSHA(statement, pred)
	sourceRef := extractSourceRef(pred)
	builderID := pred.RunDetails.Builder.ID

	result.RepoURI = repoURI
	result.Commit = commitSHA
	result.SourceRef = sourceRef
	result.BuilderID = builderID
	result.Claims["predicate_type"] = statement.PredicateType
	if pred.BuildDefinition.BuildType != "" {
		result.Claims["build_type"] = pred.BuildDefinition.BuildType
	}

	// Validate repo URI.
	if opts.RepoURI != "" {
		if !matchRepoURI(repoURI, opts.RepoURI) {
			result.ErrorMsg = fmt.Sprintf("repo URI mismatch: attestation has %q, expected %q", repoURI, opts.RepoURI)
			return result, nil
		}
	}

	// Validate commit SHA.
	if opts.Commit != "" {
		if !matchCommitSHA(commitSHA, opts.Commit) {
			result.ErrorMsg = fmt.Sprintf("commit SHA mismatch: attestation has %q, expected %q", commitSHA, opts.Commit)
			return result, nil
		}
	}

	// Validate source ref.
	if opts.SourceRef != "" {
		if sourceRef == "" {
			result.Warnings = append(result.Warnings,
				"source ref not found in predicate; --source-ref check skipped")
		} else if sourceRef != opts.SourceRef {
			result.ErrorMsg = fmt.Sprintf("source ref mismatch: attestation has %q, expected %q", sourceRef, opts.SourceRef)
			return result, nil
		}
	}

	// Compute SLSA source level.
	result.SLSASourceLevel = ComputeSLSASourceLevel(true, pred)
	result.Verified = true

	return result, nil
}

// ComputeSLSASourceLevel evaluates the SLSA Source Track level based on the predicate.
//
// L1: Version controlled + provenance exists
// L2: Provenance is cryptographically verified (signatureVerified must be true)
// L3: Verified provenance from two-party review (branch protection claims)
func ComputeSLSASourceLevel(signatureVerified bool, pred SourceProvenancePredicate) string {
	// L1: version controlled source with provenance attestation exists.
	if !signatureVerified {
		return "SLSA_SOURCE_L1"
	}

	// L2: signature is cryptographically verified.
	// Check for L3 evidence (branch protection / two-party review).
	// L3 requires evidence of two-party review, which can come from:
	// - Builder ID from a trusted CI system (e.g., GitHub Actions with required reviews)
	// - Build type indicating controlled environment
	builderID := pred.RunDetails.Builder.ID
	normalizedBuilder := strings.TrimPrefix(strings.TrimPrefix(builderID, "https://"), "http://")
	hasControlledBuilder := strings.HasPrefix(normalizedBuilder, "github.com/slsa-framework/") ||
		strings.HasPrefix(normalizedBuilder, "github.com/actions/") ||
		strings.HasPrefix(normalizedBuilder, "cloudbuild.googleapis.com")

	buildType := pred.BuildDefinition.BuildType
	hasControlledBuildType := strings.HasPrefix(buildType, "https://slsa.dev") ||
		strings.HasPrefix(buildType, "https://github.com/")

	if hasControlledBuilder && hasControlledBuildType {
		return "SLSA_SOURCE_L3"
	}

	return "SLSA_SOURCE_L2"
}

// Canonical SLSA source-track levels (https://slsa.dev/spec/v1.2/source-requirements).
const (
	SLSASourceLevel0 = "SLSA_SOURCE_LEVEL_0"
	SLSASourceLevel1 = "SLSA_SOURCE_LEVEL_1"
	SLSASourceLevel2 = "SLSA_SOURCE_LEVEL_2"
	SLSASourceLevel3 = "SLSA_SOURCE_LEVEL_3"
)

// ControlledBuilderAnnotation is the non-numbered verifiedLevels entry asserting
// that the provenance was produced by a recognized, controlled CI builder (a
// builder-ID prefix the verifier trusts, plus a recognized build type). It
// proves a recognized controlled builder — NOT that two parties reviewed the
// change; review is a separate source-track control this heuristic does not
// observe. It is recorded alongside — not as — the numbered SLSA_SOURCE_LEVEL_n.
const ControlledBuilderAnnotation = "ORG_SOURCE_CONTROLLED_BUILDER"

// MapToCanonicalSourceLevel maps the verification evidence to the canonical SLSA
// source-track level the evidence actually proves, staying deliberately
// conservative to avoid overclaiming.
//
// The SLSA source track (v1.2) grants:
//   - L1: source is in a modern VCS and a Source VSA/provenance is issued.
//   - L2: continuous, immutable, retained branch history.
//   - L3: org technical controls (branch protection, required reviews, status
//     checks) are continuously enforced and attested.
//
// A verified source-provenance signature proves L1: the revision is version
// controlled and provenance exists. It does NOT by itself prove the continuity
// (L2) or continuous-enforcement (L3) controls. So provenance evidence alone
// maps to L1 here; a recognized controlled builder, when detected, is surfaced
// separately via ControlledBuilderAnnotation.
func MapToCanonicalSourceLevel(signatureVerified bool) string {
	if !signatureVerified {
		return SLSASourceLevel0
	}
	return SLSASourceLevel1
}

// loadTrustedRoot loads the Sigstore trusted root for signature verification.
// selectTrustedRootForBundle returns the trusted root able to chain b's signing
// cert: the public-good Sigstore root for sigstore.dev-issued certs, otherwise
// the GitHub root.
func selectTrustedRootForBundle(b *bundle.Bundle) (*root.TrustedRoot, error) {
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

// isAcceptedPredicateType checks if the predicate type is one of the accepted types.
func isAcceptedPredicateType(predicateType string) bool {
	return slices.Contains(acceptedPredicateTypes, predicateType)
}

// extractRepoURI extracts the repository URI from the statement and predicate.
func extractRepoURI(statement inTotoStatement, pred SourceProvenancePredicate) string {
	// Try externalParameters.repository first.
	if repo := pred.BuildDefinition.ExternalParameters.Repository; repo != "" {
		return repo
	}

	// Try externalParameters.workflow.repository.
	if repo := pred.BuildDefinition.ExternalParameters.Workflow.Repository; repo != "" {
		return repo
	}

	// Try resolved dependencies.
	for _, dep := range pred.BuildDefinition.ResolvedDependencies {
		if dep.URI != "" {
			return normalizeRepoURI(dep.URI)
		}
	}

	// Try statement subjects.
	for _, subj := range statement.Subject {
		uri := subj.URI
		if uri == "" {
			uri = subj.Name
		}
		if uri != "" {
			return normalizeRepoURI(uri)
		}
	}

	return ""
}

// extractCommitSHA extracts the commit SHA from the statement and predicate.
func extractCommitSHA(statement inTotoStatement, pred SourceProvenancePredicate) string {
	// Try resolved dependencies digest.
	for _, dep := range pred.BuildDefinition.ResolvedDependencies {
		if sha, ok := dep.Digest["gitCommit"]; ok {
			return sha
		}
		if sha, ok := dep.Digest["sha1"]; ok {
			return sha
		}
	}

	// Try statement subject digest.
	for _, subj := range statement.Subject {
		if sha, ok := subj.Digest["gitCommit"]; ok {
			return sha
		}
		if sha, ok := subj.Digest["sha1"]; ok {
			return sha
		}
	}

	return ""
}

// extractSourceRef extracts the source ref from the predicate.
func extractSourceRef(pred SourceProvenancePredicate) string {
	// Try externalParameters.ref.
	if ref := pred.BuildDefinition.ExternalParameters.Ref; ref != "" {
		return ref
	}

	// Try externalParameters.workflow.ref.
	if ref := pred.BuildDefinition.ExternalParameters.Workflow.Ref; ref != "" {
		return ref
	}

	// Try resolvedDependencies URI for ref hints.
	for _, dep := range pred.BuildDefinition.ResolvedDependencies {
		if ref := extractRefFromURI(dep.URI); ref != "" {
			return ref
		}
	}

	return ""
}

// matchRepoURI compares two repository URIs, normalizing common formats.
func matchRepoURI(attestationURI, expectedURI string) bool {
	a := normalizeRepoURI(attestationURI)
	b := normalizeRepoURI(expectedURI)
	return strings.EqualFold(a, b)
}

// normalizeRepoURI strips common prefixes and suffixes from repo URIs for comparison.
func normalizeRepoURI(uri string) string {
	uri = strings.TrimPrefix(uri, "git+")
	uri = strings.TrimPrefix(uri, "https://")
	uri = strings.TrimPrefix(uri, "http://")
	uri = strings.TrimSuffix(uri, ".git")

	// Strip ref suffixes like @refs/heads/main.
	if idx := strings.Index(uri, "@"); idx != -1 {
		uri = uri[:idx]
	}

	return strings.TrimRight(uri, "/")
}

// matchCommitSHA compares commit SHAs, supporting prefix matching.
// Requires at least 7 characters on the shorter side to prevent collision attacks.
func matchCommitSHA(attestationSHA, expectedSHA string) bool {
	a := strings.ToLower(strings.TrimSpace(attestationSHA))
	b := strings.ToLower(strings.TrimSpace(expectedSHA))

	if a == b {
		return true
	}

	// Require minimum 7 characters for prefix matching (git short hash standard).
	if min(len(a), len(b)) < 7 {
		return false
	}

	// Support prefix matching (short SHA).
	if len(a) > len(b) {
		return strings.HasPrefix(a, b)
	}
	return strings.HasPrefix(b, a)
}

// extractRefFromURI extracts a git ref from a URI like "git+https://...@refs/heads/main".
func extractRefFromURI(uri string) string {
	if idx := strings.Index(uri, "@refs/"); idx != -1 {
		return uri[idx+1:]
	}
	return ""
}
