package attestations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/go-github/v89/github"
	bundleutils "github.com/liatrio/autogov/pkg/bundle"
	"github.com/liatrio/autogov/pkg/certid"
	"github.com/liatrio/autogov/pkg/digest"
	ghclient "github.com/liatrio/autogov/pkg/github"
	"github.com/liatrio/autogov/pkg/root"

	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigstorego_root "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// non-fatal source ref mismatch that should be skipped (explicitly for blobs if it has not changed)
type SourceRefMismatchError struct {
	Found    string
	Expected string
}

func (e *SourceRefMismatchError) Error() string {
	return fmt.Sprintf("source repository ref %s does not match expected %s", e.Found, e.Expected)
}

// default gha oidc token issuer
const DefaultCertIssuer = "https://token.actions.githubusercontent.com"

// timeout for fetching attestations from github api
const attestationFetchTimeout = 2 * time.Minute

// represents a SHA-256 digest of an artifact
type Digest struct {
	value string
}

// creates a new Digest from a string and returns an error if the digest format is invalid
func NewDigest(value string) (*Digest, error) {
	// Allow empty digest for blob verification (will be calculated later)
	if value == "" {
		return &Digest{value: ""}, nil
	}

	// Validate digest format (sha256:hash)
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] != "sha256" || len(parts[1]) != 64 {
		return nil, fmt.Errorf("invalid digest format, expected 'sha256:<64-char-hex>', got %s", value)
	}

	return &Digest{value: value}, nil
}

// returns the string representation of the digest
func (d *Digest) String() string {
	return d.value
}

// config for verify
type Options struct {
	// path to blob file to verify against
	// if given, verification performed against blob instead of image
	// example: "/path/to/my/file.txt"
	BlobPath string
	// repository to fetch attestations from (format: owner/repo)
	// required for blob verification, optional for image verification
	Repository string
	// expected repository ref (e.g., refs/heads/main)
	// verifies that the source repo ref in the build provenance attestation matches this value (e.g., ${{ github.ref }})
	SourceRef string
	// expected certificate identity (e.g., gha workflow url)
	// format: https://github.com/OWNER/REPO/.github/workflows/WORKFLOW.yml@REF
	// example: https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main
	CertIdentity string
	// expected certificate issuer (e.g., gha oidc issuer)
	// default: https://token.actions.githubusercontent.com
	CertIssuer string
	// reduces output verbosity
	Quiet bool
	// options for cert-identity validation
	CertIdentityValidation *certid.Options
	// resolved signer allowlist (union of --cert-identity + valid list SANs);
	// when set, each attestation must match at least one entry (OR semantics).
	// resolved once upstream (orchestrate) to avoid reloading the list per blob.
	AcceptedIdentities []string
}

// parses a full OCI ref into components
// format: [registry/]org/repo[:tag]@digest
func ParseImageRef(ref string) (org, repo, digest string, err error) {
	parts := strings.Split(ref, "@")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid reference format, expected [registry/]org/repo[:tag]@digest")
	}

	// get digest
	digest = parts[1]

	// get repo
	repoPath := parts[0]
	// remove registry if present
	if strings.Contains(repoPath, "/") {
		repoParts := strings.Split(repoPath, "/")
		if strings.Contains(repoParts[0], ".") { // likely a registry
			repoPath = strings.Join(repoParts[1:], "/")
		}
	}

	// remove tag if present
	if strings.Contains(repoPath, ":") {
		repoPath = strings.Split(repoPath, ":")[0]
	}

	// get org and repo
	repoParts := strings.Split(repoPath, "/")
	if len(repoParts) != 2 {
		return "", "", "", fmt.Errorf("invalid repository format, expected org/repo")
	}

	return repoParts[0], repoParts[1], digest, nil
}

// parseorg and repo from a GitHub Actions workflow URL
// format: https://github.com/OWNER/REPO/.github/workflows/...
func parseOrgRepoFromWorkflowURL(certIdentity string) (string, string, error) {
	// removes https://github.com/ prefix
	parts := strings.Split(certIdentity, "github.com/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid certificate identity format, expected GitHub Actions workflow URL")
	}

	// split path components
	pathParts := strings.Split(parts[1], "/")
	if len(pathParts) < 2 {
		return "", "", fmt.Errorf("invalid certificate identity format, could not extract org/repo")
	}

	return pathParts[0], pathParts[1], nil
}

// retrieves and verifies attestations for a gh container image or blob
func GetFromGitHub(ctx context.Context, imageRef string, client *github.Client, opts Options) ([]oci.Signature, error) {
	// resolve the accepted signer allowlist (union: --cert-identity as-typed ∪
	// revocation-checked list SANs) when not pre-resolved upstream. orchestrate
	// resolves once per invocation; this fallback covers direct callers. fail-closed.
	resolvedOpts, err := resolveAcceptedIdentities(ctx, opts)
	if err != nil {
		return nil, err
	}
	opts = resolvedOpts

	org, repo, artifactRef, err := resolveOrgRepoArtifact(imageRef, opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, attestationFetchTimeout)
	defer cancel()

	// validate inputs first
	if err := validateInputs(client, org, artifactRef); err != nil {
		return nil, err
	}

	// set default options
	opts = setDefaultOptions(opts)

	// create temp directory with cleanup function
	cacheDir, cleanup, err := digest.CreateTempDir("attestations-")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if opts.BlobPath != "" {
		return handleBlobVerification(ctx, artifactRef, org, client, opts, cacheDir)
	}

	// get trusted root with fallback
	trust, err := writeTrustedRoot(cacheDir)
	if err != nil {
		return nil, err
	}

	if err := fetchAndWriteManifest(ctx, org, repo, artifactRef, cacheDir); err != nil {
		return nil, err
	}

	// get gh attestations
	atts, _, err := client.Organizations.ListAttestations(ctx, org, artifactRef.String(), &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
	}

	return verifyAttestations(ctx, atts.Attestations, artifactRef.String(), trust, opts)
}

// resolveAcceptedIdentities populates opts.AcceptedIdentities from the cert-identity
// validation config when no allowlist was pre-resolved upstream, returning the
// (possibly updated) options. fail-closed: a resolution error aborts verification.
func resolveAcceptedIdentities(ctx context.Context, opts Options) (Options, error) {
	if len(opts.AcceptedIdentities) == 0 && opts.CertIdentityValidation != nil {
		accepted, err := certid.ResolveAcceptedIdentities(ctx, opts.CertIdentity, opts.CertIdentityValidation)
		if err != nil {
			return opts, err
		}
		opts.AcceptedIdentities = accepted

		if !opts.Quiet {
			fmt.Printf("✓ Enforcing signer allowlist (%d accepted identities)\n", len(accepted))
		}
	}
	return opts, nil
}

// resolveOrgRepoArtifact determines the org, repo, and artifact digest for the
// verification target. for blobs it derives org/repo from --repo or cert-identity
// and defers digest calculation; for images it parses them from the OCI ref.
func resolveOrgRepoArtifact(imageRef string, opts Options) (org, repo string, artifactRef *Digest, err error) {
	if opts.BlobPath != "" {
		// need to know which repo the blob came from to fetch attestations from
		// via --repo flag or cert-identity
		if opts.Repository != "" {
			// parse org/repo from repository flag
			parts := strings.Split(opts.Repository, "/")
			if len(parts) != 2 {
				return "", "", nil, fmt.Errorf("invalid repository format, expected owner/repo")
			}
			org = parts[0]
			repo = parts[1]
		} else if opts.CertIdentity != "" {
			// fall back to extracting from cert-identity if repo not specified
			org, repo, err = parseOrgRepoFromWorkflowURL(opts.CertIdentity)
			if err != nil {
				return "", "", nil, fmt.Errorf("failed to extract org/repo from certificate identity: %w", err)
			}
		} else {
			// without repo or cert-identity, we can't determine where to fetch attestations
			return "", "", nil, fmt.Errorf("for blob verification, provide --repo, --cert-identity, or use offline mode with --attestations-path")
		}
		// if empty digest for blob, calculated later
		artifactRef, _ = NewDigest("")
		return org, repo, artifactRef, nil
	}

	// container verification parses from image/oci ref
	if imageRef == "" {
		return "", "", nil, fmt.Errorf("artifact digest is required for container verification")
	}
	var digestStr string
	org, repo, digestStr, err = ParseImageRef(imageRef)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to parse image reference: %w", err)
	}
	artifactRef, err = NewDigest(digestStr)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid digest format: %w", err)
	}
	return org, repo, artifactRef, nil
}

// writeTrustedRoot fetches the trusted root (with fallback) and writes it into
// cacheDir with restrictive permissions, returning the path to the written file.
func writeTrustedRoot(cacheDir string) (string, error) {
	// get trusted root with fallback
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		return "", fmt.Errorf("failed to get trusted root: %w", err)
	}

	// write trusted root with restrictive permissions (security-sensitive file)
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, trustedRootData, 0600); err != nil {
		return "", fmt.Errorf("failed to write trusted root: %w", err)
	}
	return trust, nil
}

// fetchAndWriteManifest fetches the image manifest from ghcr.io for the artifact
// digest and writes it into cacheDir with restrictive permissions.
func fetchAndWriteManifest(ctx context.Context, org, repo string, artifactRef *Digest, cacheDir string) error {
	// fetch manifest
	repoRef := fmt.Sprintf("ghcr.io/%s/%s", org, repo)
	remoteRepo, err := remote.NewRepository(repoRef)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// get token from centralized github client
	token := ghclient.GetToken()
	if token == "" {
		return fmt.Errorf("no token found in github client transport or environment")
	}

	// auth config
	remoteRepo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential("ghcr.io", auth.Credential{
			Username: org,
			Password: token,
		}),
	}

	// fetch manifest
	_, manifestReader, err := remoteRepo.Manifests().FetchReference(ctx, artifactRef.String())
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer func() {
		if closeErr := manifestReader.Close(); closeErr != nil {
			log.Printf("warning: failed to close manifest reader: %v", closeErr)
		}
	}()

	manifest, err := io.ReadAll(manifestReader)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	manifestPath := filepath.Join(cacheDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifest, 0600); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}
	return nil
}

// verifyAttestations verifies each attestation against artifactTarget, collecting
// the resulting signatures. source-ref mismatches are non-fatal and skipped;
// any other error aborts. an empty signature set is an error.
func verifyAttestations(ctx context.Context, attestations []*github.Attestation, artifactTarget, trust string, opts Options) ([]oci.Signature, error) {
	var sigs []oci.Signature
	for i, att := range attestations {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			sig, err := verifyAttestation(att, artifactTarget, trust, i, opts)
			if err != nil {
				// check if it's a source ref mismatch error (non-fatal)
				var sourceRefErr *SourceRefMismatchError
				if errors.As(err, &sourceRefErr) {
					if !opts.Quiet {
						fmt.Printf("⚠ warning: %s (skipping attestation %d)\n", sourceRefErr.Error(), i+1)
					}
					continue // skip this attestation and continue with the next one
				}
				return nil, err
			}
			sigs = append(sigs, sig)
		}
	}

	if len(sigs) == 0 {
		return nil, fmt.Errorf("no valid signatures found")
	}

	return sigs, nil
}

func validateInputs(client *github.Client, org string, artifactRef *Digest) error {
	switch {
	case client == nil:
		return fmt.Errorf("github client is required")
	case org == "":
		return fmt.Errorf("github organization name is required")
	case artifactRef == nil:
		return fmt.Errorf("artifact reference is required")
	default:
		return nil
	}
}

func setDefaultOptions(opts Options) Options {
	if opts.CertIssuer == "" {
		opts.CertIssuer = DefaultCertIssuer
	}
	return opts
}

// timestampVerifierOpts returns the timestamp verification options for a bundle:
// always observer timestamps, plus a required transparency-log entry when the
// bundle carries one. public-good GitHub bundles carry a Rekor integrated
// timestamp and no TSA, so the log entry must be required for that timestamp to
// count; GitHub-internal bundles carry an RFC3161 TSA timestamp and no log entry.
func timestampVerifierOpts(b *bundle.Bundle) []verify.VerifierOption {
	opts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if len(b.GetVerificationMaterial().GetTlogEntries()) > 0 {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	return opts
}

// selectOnlineTrustedRoot returns the trusted root able to chain leafDER: the
// embedded public-good Sigstore root for sigstore.dev-issued certs, otherwise the
// dynamically fetched GitHub root written to githubTrustPath.
func selectOnlineTrustedRoot(leafDER []byte, githubTrustPath string) (*sigstorego_root.TrustedRoot, error) {
	if len(leafDER) > 0 {
		if src, err := root.DetectTrustedRootFromCert(leafDER); err == nil && src == root.TrustedRootSourcePublic {
			tr, err := sigstorego_root.NewTrustedRootFromJSON(root.GetPublicTrustedRoot())
			if err != nil {
				return nil, fmt.Errorf("failed to load public sigstore trusted root: %w", err)
			}
			return tr, nil
		}
	}
	tr, err := sigstorego_root.NewTrustedRootFromPath(githubTrustPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root: %w", err)
	}
	return tr, nil
}

// attestationStatement is the subset of the in-toto statement needed for
// predicate-type display and source-ref verification.
type attestationStatement struct {
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

// parseAttestationBundle marshals the GitHub attestation bundle, parses it, and
// extracts the envelope, raw payload, and decoded in-toto statement.
func parseAttestationBundle(att *github.Attestation) (b *bundle.Bundle, rawPayload string, sigBytes []byte, statement attestationStatement, err error) {
	// GitHub attestation bundle
	bundleData, err := att.Bundle.MarshalJSON()
	if err != nil {
		return nil, "", nil, statement, fmt.Errorf("failed to marshal attestation bundle: %w", err)
	}

	// parse bundle
	b = &bundle.Bundle{}
	if err := b.UnmarshalJSON(bundleData); err != nil {
		return nil, "", nil, statement, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	// envelope from the bundle
	envelope, err := b.Envelope()
	if err != nil {
		return nil, "", nil, statement, fmt.Errorf("failed to get envelope from bundle: %w", err)
	}

	// payload from the envelope
	rawPayload = envelope.RawEnvelope().Payload

	// decode base64 payload
	decodedPayload, err := base64.StdEncoding.DecodeString(rawPayload)
	if err != nil {
		return nil, "", nil, statement, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	if err := json.Unmarshal(decodedPayload, &statement); err != nil {
		return nil, "", nil, statement, fmt.Errorf("failed to parse statement: %w", err)
	}

	return b, rawPayload, envelope.Signature(), statement, nil
}

// predicateDisplayInfo returns the human-readable predicate descriptor, emitting
// a warning to stderr for unknown predicate types when not in quiet mode.
func predicateDisplayInfo(predicateType string, quiet bool) string {
	// lookup predicate type metadata for display
	if info, exists := LookupPredicateType(predicateType); exists {
		return fmt.Sprintf("%s: %s", info.ShortName, predicateType)
	}

	// log warning for unknown predicate types (if not in quiet mode)
	if !quiet {
		fmt.Fprintf(os.Stderr, "⚠ warning: unknown predicate type: %s\n", predicateType)
		fmt.Fprintf(os.Stderr, "  consider updating PredicateTypeRegistry if this is a standard type\n")
	}
	return fmt.Sprintf("Unknown: %s", predicateType)
}

// verifySourceRef checks the build provenance source ref against the expected ref
// when one is configured. non-provenance attestations carry no source ref and are
// a no-op; a mismatch returns a (non-fatal) SourceRefMismatchError.
func verifySourceRef(statement attestationStatement, opts Options) error {
	// verify source repository ref if expected ref is set
	if opts.SourceRef == "" {
		return nil
	}
	// check if build provenance attestation
	if statement.PredicateType != PredicateTypeSLSAProvenance {
		// non-provenance attestations don't contain source ref information
		return nil
	}
	sourceRef := statement.Predicate.BuildDefinition.ExternalParameters.Workflow.Ref
	if sourceRef == "" {
		return fmt.Errorf("no source repository ref found in verification result")
	}

	// verify source repository ref matches expected ref
	if sourceRef != opts.SourceRef {
		return &SourceRefMismatchError{Found: sourceRef, Expected: opts.SourceRef}
	}

	if !opts.Quiet {
		fmt.Printf("✓ Source repository ref verified: %s\n", sourceRef)
	}
	return nil
}

// buildArtifactPolicy builds the artifact policy option: for blobs it reads the
// blob content; for container images it verifies against the decoded digest.
func buildArtifactPolicy(artifactDigest string, opts Options) (verify.ArtifactPolicyOption, error) {
	// artifact policy - for container images we verify against the digest
	if opts.BlobPath != "" {
		// for blobs, read the blob content and verify against it
		blobData, err := os.ReadFile(opts.BlobPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read blob: %w", err)
		}
		return verify.WithArtifact(bytes.NewReader(blobData)), nil
	}
	// for container images, verify against the digest
	// remove "sha256:" prefix if present
	digestValue := strings.TrimPrefix(artifactDigest, "sha256:")
	digestBytes, err := hex.DecodeString(digestValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest: %w", err)
	}
	return verify.WithArtifactDigest("sha256", digestBytes), nil
}

// buildVerifyPolicy builds the verification policy from the artifact policy and the
// accepted-identity allowlist: --cert-identity (as-typed) unioned with any
// pre-resolved allowlist SANs, each a repeatable identity (native OR semantics).
// with no accepted identities it accepts any valid signature.
func buildVerifyPolicy(artifactPolicy verify.ArtifactPolicyOption, opts Options) (verify.PolicyBuilder, error) {
	// build the accepted-identity set: --cert-identity (as-typed) unioned with any
	// pre-resolved allowlist SANs. each identity becomes one repeatable
	// WithCertificateIdentity, giving native OR semantics (match at least one).
	accepted := opts.AcceptedIdentities
	if opts.CertIdentity != "" && !slices.Contains(accepted, opts.CertIdentity) {
		accepted = append([]string{opts.CertIdentity}, accepted...)
	}

	// verify policy
	if len(accepted) == 0 {
		// no certificate identity verification / accept any valid signature
		return verify.NewPolicy(artifactPolicy, verify.WithoutIdentitiesUnsafe()), nil
	}

	policyOpts := make([]verify.PolicyOption, 0, len(accepted))
	for _, sub := range accepted {
		if sub == "" {
			// defense-in-depth: an empty SAN makes sigstore's identity matcher
			// match ANY cert from the issuer (accept-any). The resolver never
			// produces "", but a direct caller could — fail closed.
			return verify.PolicyBuilder{}, fmt.Errorf("empty certificate identity in accepted allowlist")
		}
		certIdentity, err := verify.NewShortCertificateIdentity(opts.CertIssuer, "", sub, "")
		if err != nil {
			return verify.PolicyBuilder{}, fmt.Errorf("failed to create certificate identity %q: %w", sub, err)
		}
		policyOpts = append(policyOpts, verify.WithCertificateIdentity(certIdentity))
	}
	return verify.NewPolicy(artifactPolicy, policyOpts...), nil
}

func verifyAttestation(att *github.Attestation, artifactDigest, trust string, index int, opts Options) (oci.Signature, error) {
	if att == nil {
		return nil, fmt.Errorf("attestation is nil")
	}

	b, rawPayload, sigBytes, statement, err := parseAttestationBundle(att)
	if err != nil {
		return nil, err
	}

	predicateInfo := predicateDisplayInfo(statement.PredicateType, opts.Quiet)

	// create signature from attestation
	sig, err := static.NewSignature(
		[]byte(rawPayload),
		string(sigBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	if !opts.Quiet {
		fmt.Printf("Verifying attestation %d (%s)...\n", index+1, predicateInfo)
	}

	if err := verifySourceRef(statement, opts); err != nil {
		return nil, err
	}

	// select the trusted root that can chain this bundle's signing cert: public
	// repos sign against public-good Sigstore (Fulcio sigstore.dev), while the
	// GitHub-internal flow uses fulcio.githubapp.com.
	trustedRoot, err := selectOnlineTrustedRoot(bundleutils.LeafCertDER(b), trust)
	if err != nil {
		return nil, err
	}

	verifier, err := verify.NewVerifier(trustedRoot, timestampVerifierOpts(b)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	artifactPolicy, err := buildArtifactPolicy(artifactDigest, opts)
	if err != nil {
		return nil, err
	}

	policy, err := buildVerifyPolicy(artifactPolicy, opts)
	if err != nil {
		return nil, err
	}

	// verify bundle
	_, err = verifier.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation: %w", err)
	}

	if !opts.Quiet {
		fmt.Printf("✓ Attestation %d verified successfully\n", index+1)
		fmt.Println("---")
	}

	return sig, nil
}

func handleBlobVerification(ctx context.Context, artifactRef *Digest, org string, client *github.Client, opts Options, cacheDir string) ([]oci.Signature, error) {
	if !opts.Quiet {
		fmt.Println("Verifying blob attestations...")
	}

	// validate inputs
	if err := validateInputs(client, org, artifactRef); err != nil {
		return nil, err
	}

	if opts.BlobPath == "" {
		return nil, fmt.Errorf("blob path is required")
	}

	// read blob file
	blobData, err := os.ReadFile(opts.BlobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}

	// if no blob digest, calculate from blobpath
	if artifactRef.String() == "" {
		h := sha256.New()
		h.Write(blobData)
		artifactRef, _ = NewDigest(fmt.Sprintf("sha256:%x", h.Sum(nil)))
		if !opts.Quiet {
			fmt.Printf("Using calculated blob digest: %s\n", artifactRef)
		}
	}

	// get trusted root with fallback
	trust, err := writeTrustedRoot(cacheDir)
	if err != nil {
		return nil, err
	}

	// get gh attestations
	atts, _, err := client.Organizations.ListAttestations(ctx, org, artifactRef.String(), &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
	}

	return verifyAttestations(ctx, atts.Attestations, opts.BlobPath, trust, opts)
}
