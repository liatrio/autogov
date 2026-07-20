package verify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v89/github"
	"github.com/liatrio/autogov/pkg/certid"
	"github.com/liatrio/autogov/pkg/cli"
	ghclient "github.com/liatrio/autogov/pkg/github"
	"github.com/liatrio/autogov/pkg/offline"
	"github.com/liatrio/autogov/pkg/orchestrate"
	"github.com/liatrio/autogov/pkg/root"
	"github.com/liatrio/autogov/pkg/vsa"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Verify GitHub artifact attestations",
		Long: `Verify GitHub artifact attestations using Sigstore.

Verifies attestations for container images or blob files, checking certificate
identity, issuer, and optionally validating against OPA policies.

Examples:
  # Verify a container image
  autogov verify attestation --image-digest ghcr.io/org/repo@sha256:abc123 --repo org/repo

  # Verify a blob file
  autogov verify attestation --blob-path artifact.tar.gz --repo org/repo

  # Verify with OPA policy evaluation
  autogov verify attestation --blob-path artifact.tar.gz --repo org/repo --policy-bundle-path policies/

  # Pull the policy bundle from a GitHub release asset (latest release)
  autogov verify attestation --blob-path artifact.tar.gz --repo org/repo \
    --policy-bundle-path ghrel://org/policy-library --policy-bundle-digest sha256:...`,
		RunE:    runAttestation,
		PreRunE: preRunAttestation,
	}

	cmd.Flags().StringP(flagImageDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	cmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	cmd.Flags().String(flagRepo, "", "Repository to fetch attestations from (format: owner/repo) - required for blob verification")
	cmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against (optional - if not provided, any valid signature will be accepted)")
	cmd.Flags().StringP(flagCertIssuer, "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	cmd.Flags().StringP(flagSourceRef, "r", "", "Source repository ref to verify against (e.g., refs/heads/main)")
	cmd.Flags().String(flagAttestationsPath, "", "Path to directory containing attestation files for offline verification")
	cmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")
	cmd.Flags().String(flagCertIdentityList, "", "Signer allowlist: URL or file path to a certificate identity list. Accepted identities are enforced as a signer allowlist; usable with or without --cert-identity (their union is accepted)")
	cmd.Flags().Bool(flagRefreshTrustedRoot, false, "Fetch the public-good Sigstore trusted root live from the Sigstore TUF repo instead of the embedded snapshot. Fail-closed: if the live fetch fails, verification errors out (no fallback). Off by default (uses the embedded snapshot, hermetic)")
	cmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")
	cmd.Flags().String(flagPolicyBundlePath, "", "Policy bundle source: local dir, .tar.gz, http(s):// URL, oci://registry/repo:tag, or ghrel://owner/repo[@tag][?asset=bundle.tar.gz]. Without @tag, ghrel:// uses the latest release (GitHub's most recent non-prerelease, non-draft, which may differ from an OCI :latest tag)")
	cmd.Flags().String(flagPolicySchemasPath, "", "JSON schemas source for OPA validation: local dir, .tar.gz, http(s):// URL, oci://, or ghrel://owner/repo[@tag][?asset=schemas.tar.gz] (default asset schemas.tar.gz)")
	cmd.Flags().String(flagPolicyDataPath, "", "Path to JSON file containing additional OPA data")
	cmd.Flags().String(flagPolicyBundleDigest, "", "Expected SHA-256 of the downloaded policy bundle asset (sha256:...); enforced for ghrel:// bundle paths. Distinct from --image-digest")
	cmd.Flags().Bool(flagFailOnPolicyError, false, "Exit with error when policy evaluation fails (default: false)")
	cmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	cmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	cmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")

	return cmd
}

func preRunAttestation(cmd *cobra.Command, args []string) error {
	blobPath, _ := cmd.Flags().GetString(flagBlobPath)
	imageDigest, _ := cmd.Flags().GetString(flagImageDigest)
	repo, _ := cmd.Flags().GetString(flagRepo)

	if blobPath == "" && imageDigest == "" && len(args) == 0 {
		return fmt.Errorf("either --%s, --%s, or a positional argument must be provided", flagImageDigest, flagBlobPath)
	}

	if (blobPath != "" || imageDigest != "") && repo == "" {
		return fmt.Errorf("--%s is required for blob and image verification", flagRepo)
	}

	if token := ghclient.GetToken(); token == "" {
		return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
	}

	return nil
}

// applyBoolFlagToViper resolves a bool flag into viper without clobbering an
// env binding. the key is bound to viper in cmd/root.go via BindEnv, so the env
// value is already present. only overwrite it when the flag was explicitly
// passed, otherwise an unconditional viper.Set with the flag default would
// clobber the env binding. an explicit flag therefore wins over the env var.
func applyBoolFlagToViper(cmd *cobra.Command, flag string) {
	if cmd.Flags().Changed(flag) {
		v, _ := cmd.Flags().GetBool(flag)
		viper.Set(flag, v)
	}
}

// applyFailOnPolicyError resolves the fail-on-policy-error setting into viper.
func applyFailOnPolicyError(cmd *cobra.Command) {
	applyBoolFlagToViper(cmd, flagFailOnPolicyError)
}

// validatePolicyFlagsRequireVSA fails closed when policy/gating flags are set
// without --generate-vsa. policy (OPA) evaluation only runs during VSA
// generation, so without this guard those flags are silently inert — a CI gate
// built on --fail-on-policy-error would "pass" without ever evaluating policy.
//
// Several of these options are also env-bound (initConfig BindEnv), so the guard
// checks the EFFECTIVE value (CLI flag or env, resolved via viper) rather than
// just Flags().Changed(): otherwise FAIL_ON_POLICY_ERROR=true / POLICY_BUNDLE_PATH=…
// set via env would slip past and leave policy inert.
func validatePolicyFlagsRequireVSA(cmd *cobra.Command) error {
	if generateVSA, _ := cmd.Flags().GetBool(flagGenerateVSA); generateVSA {
		return nil
	}
	var set []string

	// env-bound string options: requested via the CLI flag or its env var.
	for _, f := range []string{flagPolicyBundlePath, flagPolicySchemasPath, flagPolicyDataPath} {
		v, _ := cmd.Flags().GetString(f)
		if v == "" {
			v = viper.GetString(f) // env value (BindEnv), else ""
		}
		if v != "" {
			set = append(set, "--"+f)
		}
	}
	// not env-bound: the CLI flag is the only source.
	for _, f := range []string{flagPolicyBundleDigest, flagPolicyURI} {
		if v, _ := cmd.Flags().GetString(f); v != "" {
			set = append(set, "--"+f)
		}
	}
	// fail-on-policy-error (bool) is resolved from flag/env into viper by
	// applyFailOnPolicyError; also read the flag directly so the guard holds even
	// when called without that pre-step.
	if failOn, _ := cmd.Flags().GetBool(flagFailOnPolicyError); failOn || viper.GetBool(flagFailOnPolicyError) {
		set = append(set, "--"+flagFailOnPolicyError)
	}

	if len(set) > 0 {
		return fmt.Errorf("%s require --%s; policy evaluation only runs during VSA generation", strings.Join(set, ", "), flagGenerateVSA)
	}
	return nil
}

func runAttestation(cmd *cobra.Command, args []string) error {
	// resolve quiet without clobbering QUIET env (same class as fail-on-policy-error):
	// only write the flag value when it was explicitly passed, then read the effective
	// value back from viper so local control flow honors the env binding too.
	applyBoolFlagToViper(cmd, flagQuiet)
	applyFailOnPolicyError(cmd)
	quiet := viper.GetBool(flagQuiet)

	// fail closed before doing any verification work if policy flags were passed
	// without --generate-vsa (they would otherwise be silently inert).
	if err := validatePolicyFlagsRequireVSA(cmd); err != nil {
		return err
	}

	policyBundleDigest, _ := cmd.Flags().GetString(flagPolicyBundleDigest)
	viper.Set("policy-bundle-digest", policyBundleDigest)

	if !quiet {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Starting verification process...")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "---")
	}

	imageDigest, _ := cmd.Flags().GetString(flagImageDigest)
	if imageDigest == "" && len(args) > 0 {
		imageDigest = args[0]
	}
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	// read the identity-list flags here (not only in the online branch) so both
	// online and offline modes enforce the allowlist and share the unsafe-mode warning.
	certIdentityList, _ := cmd.Flags().GetString(flagCertIdentityList)
	noCache, _ := cmd.Flags().GetBool(flagNoCache)
	certIssuer, _ := cmd.Flags().GetString(flagCertIssuer)
	sourceRef, _ := cmd.Flags().GetString(flagSourceRef)
	blobPath, _ := cmd.Flags().GetString(flagBlobPath)
	attestationsPath, _ := cmd.Flags().GetString(flagAttestationsPath)

	if err := refreshTrustedRootIfRequested(cmd, quiet); err != nil {
		return err
	}

	client, err := ghclient.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	blobPaths, err := cli.ExpandBlobPaths(blobPath)
	if err != nil {
		return fmt.Errorf("failed to expand blob paths: %w", err)
	}

	warnIfNoIdentityEnforced(certIdentity, certIdentityList)

	// dispatch returns the possibly-normalized image digest so the later VSA
	// subject/URI derivation sees the same value the online path verified.
	sigs, imageDigest, err := verifyAttestations(cmd, quiet, client, verifyInputs{
		imageDigest:      imageDigest,
		certIdentity:     certIdentity,
		certIdentityList: certIdentityList,
		certIssuer:       certIssuer,
		sourceRef:        sourceRef,
		blobPath:         blobPath,
		blobPaths:        blobPaths,
		attestationsPath: attestationsPath,
		noCache:          noCache,
	})
	if err != nil {
		return err
	}

	vsaArtifactRef, vsaSubjects, err := buildVSASubjects(cmd, imageDigest, blobPaths)
	if err != nil {
		return err
	}

	if !quiet {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nSummary:")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "✓ Successfully verified %d attestations\n", len(sigs))
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nAttestation Types:")
	}

	attestationTypes, inputAttestations := collectAttestationInputs(cmd, quiet, sigs, imageDigest)

	return maybeGenerateVSA(cmd, quiet, vsaArtifactRef, vsaSubjects, inputAttestations, attestationTypes, sigs)
}

// warnIfNoIdentityEnforced emits the unsafe-mode warning when neither a single
// identity nor a list is enforced (verification then accepts any valid Fulcio
// signature). the warning goes to stderr, ungated by --quiet and off the stdout
// summary, so it survives quiet CI runs and stdout capture.
func warnIfNoIdentityEnforced(certIdentity, certIdentityList string) {
	if certIdentity == "" && certIdentityList == "" {
		fmt.Fprintf(os.Stderr, "warning: no certificate identity enforced — accepting any valid Fulcio signature (unsafe); set --%s and/or --%s to enforce a signer allowlist\n", flagCertIdentity, flagCertIdentityList)
	}
}

// verifyInputs bundles the resolved inputs for verifyAttestations.
type verifyInputs struct {
	imageDigest      string
	certIdentity     string
	certIdentityList string
	certIssuer       string
	sourceRef        string
	blobPath         string
	blobPaths        []string
	attestationsPath string
	noCache          bool
}

// verifyAttestations dispatches to the offline or online verification path and
// returns the verified signatures alongside the (possibly normalized) image digest.
func verifyAttestations(cmd *cobra.Command, quiet bool, client *github.Client, in verifyInputs) ([]oci.Signature, string, error) {
	if in.attestationsPath != "" && in.blobPath != "" {
		sigs, err := verifyOffline(cmd, quiet, in.attestationsPath, in.blobPath, in.certIdentity, in.certIdentityList, in.certIssuer, in.noCache)
		return sigs, in.imageDigest, err
	}

	imageDigest := in.imageDigest
	repo, _ := cmd.Flags().GetString(flagRepo)
	if repo != "" && imageDigest != "" && !strings.Contains(imageDigest, "/") {
		imageDigest = fmt.Sprintf("ghcr.io/%s@%s", repo, imageDigest)
	}
	sigs, err := verifyOnline(cmd, quiet, client, onlineVerifyInputs{
		imageDigest:      imageDigest,
		repo:             repo,
		certIdentity:     in.certIdentity,
		certIdentityList: in.certIdentityList,
		certIssuer:       in.certIssuer,
		sourceRef:        in.sourceRef,
		blobPaths:        in.blobPaths,
		noCache:          in.noCache,
	})
	return sigs, imageDigest, err
}

// refreshTrustedRootIfRequested is opt-in: refresh the public-good trusted root
// live from the Sigstore TUF repo before verifying anything. fail-closed — on any
// error we abort instead of falling back to the embedded snapshot. off by default
// keeps verify hermetic.
func refreshTrustedRootIfRequested(cmd *cobra.Command, quiet bool) error {
	if refresh, _ := cmd.Flags().GetBool(flagRefreshTrustedRoot); refresh {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Refreshing public-good trusted root from the Sigstore TUF repo...")
		}
		if err := root.RefreshPublicTrustedRoot(); err != nil {
			return fmt.Errorf("--%s requested but live refresh failed: %w", flagRefreshTrustedRoot, err)
		}
	}
	return nil
}

// verifyOffline performs offline attestation verification against a local set of
// attestation bundles. it returns an empty signature slice on success (the offline
// path verifies bundles directly rather than producing oci signatures).
func verifyOffline(cmd *cobra.Command, quiet bool, attestationsPath, blobPath, certIdentity, certIdentityList, certIssuer string, noCache bool) ([]oci.Signature, error) {
	if !quiet {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Using offline verification mode")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Attestations path: %s\n", attestationsPath)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Blob path: %s\n", blobPath)
	}

	// resolve the signer allowlist once (union) and enforce it on the offline
	// path too — previously the offline branch ignored --cert-identity-list entirely.
	certOpts := orchestrate.SetupCertIdentityValidation(certIdentityList, noCache, quiet)
	accepted, err := certid.ResolveAcceptedIdentities(cmd.Context(), certIdentity, certOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve accepted certificate identities: %w", err)
	}

	verifyOpts := offline.VerifyOptions{
		CertIdentity:       certIdentity,
		CertOIDCIssuer:     certIssuer,
		AcceptedIdentities: accepted,
	}

	verifier, err := offline.NewOfflineVerifier("", verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create offline verifier: %w", err)
	}

	if err := verifier.LoadBundlesFromFile(attestationsPath); err != nil {
		return nil, fmt.Errorf("failed to load attestation bundles: %w", err)
	}

	result, err := verifier.VerifyArtifact(blobPath)
	if err != nil {
		return nil, fmt.Errorf("offline verification failed: %w", err)
	}

	if !result.Verified {
		return nil, fmt.Errorf("offline verification failed: attestations could not be verified")
	}

	return []oci.Signature{}, nil
}

// onlineVerifyInputs bundles the resolved inputs for verifyOnline.
type onlineVerifyInputs struct {
	imageDigest      string
	repo             string
	certIdentity     string
	certIdentityList string
	certIssuer       string
	sourceRef        string
	blobPaths        []string
	noCache          bool
}

// verifyOnline performs online attestation verification by fetching attestations
// from GitHub and verifying their signatures.
func verifyOnline(cmd *cobra.Command, quiet bool, client *github.Client, in onlineVerifyInputs) ([]oci.Signature, error) {
	if !quiet {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Using online verification mode")
	}

	certOpts := orchestrate.SetupCertIdentityValidation(in.certIdentityList, in.noCache, quiet)

	sigs, err := orchestrate.VerifyBlobs(cmd.Context(), client, orchestrate.Options{
		ArtifactDigest:         in.imageDigest,
		Repository:             in.repo,
		CertIdentity:           in.certIdentity,
		CertIssuer:             in.certIssuer,
		SourceRef:              in.sourceRef,
		BlobPaths:              in.blobPaths,
		Quiet:                  quiet,
		CertIdentityValidation: certOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	return sigs, nil
}

// buildVSASubjects derives the VSA artifact reference and subject descriptors from
// the verified blob paths or image digest.
func buildVSASubjects(cmd *cobra.Command, imageDigest string, blobPaths []string) (string, []vsa.VSASubject, error) {
	vsaArtifactRef := imageDigest
	var vsaSubjects []vsa.VSASubject

	if len(blobPaths) > 0 {
		for _, path := range blobPaths {
			blobData, err := os.ReadFile(path)
			if err != nil {
				return "", nil, fmt.Errorf("failed to read blob file %s for VSA: %w", path, err)
			}
			h := sha256.New()
			h.Write(blobData)
			vsaSubjects = append(vsaSubjects, vsa.VSASubject{
				URI: filepath.Base(path),
				Digest: map[string]string{
					"sha256": fmt.Sprintf("%x", h.Sum(nil)),
				},
			})
		}
		if vsaArtifactRef == "" {
			repo, _ := cmd.Flags().GetString(flagRepo)
			if repo != "" {
				vsaArtifactRef = fmt.Sprintf("https://github.com/%s", repo)
			}
		}
	} else if imageDigest != "" {
		digestValue := imageDigest
		if idx := strings.Index(imageDigest, "@sha256:"); idx != -1 {
			digestValue = imageDigest[idx+8:]
		} else if strings.HasPrefix(imageDigest, "sha256:") {
			digestValue = strings.TrimPrefix(imageDigest, "sha256:")
		}
		vsaSubjects = append(vsaSubjects, vsa.VSASubject{
			URI: imageDigest,
			Digest: map[string]string{
				"sha256": digestValue,
			},
		})
		vsaArtifactRef = imageDigest
	}

	return vsaArtifactRef, vsaSubjects, nil
}

// collectAttestationInputs decodes each verified signature's statement to gather
// the predicate types and the input-attestation resource descriptors used for VSA
// generation. malformed entries are skipped with a warning, preserving original
// behavior.
func collectAttestationInputs(cmd *cobra.Command, quiet bool, sigs []oci.Signature, imageDigest string) ([]string, []vsa.ResourceDescriptor) {
	var attestationTypes []string
	var inputAttestations []vsa.ResourceDescriptor

	for i, sig := range sigs {
		payload, err := sig.Payload()
		if err != nil {
			log.Printf("warning: failed to get payload for attestation %d: %v", i, err)
			continue
		}

		decodedPayload, err := base64.StdEncoding.DecodeString(string(payload))
		if err != nil {
			log.Printf("warning: failed to decode payload for attestation %d: %v", i, err)
			continue
		}

		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(decodedPayload, &statement); err != nil {
			log.Printf("warning: failed to parse statement for attestation %d: %v", i, err)
			continue
		}

		attestationTypes = append(attestationTypes, statement.PredicateType)
		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d. %s\n", i+1, statement.PredicateType)
		}

		h := sha256.New()
		h.Write(decodedPayload)
		attestationDigest := fmt.Sprintf("%x", h.Sum(nil))

		inputAttestations = append(inputAttestations, vsa.ResourceDescriptor{
			URI: attestationURIFor(imageDigest, attestationDigest),
			Digest: map[string]string{
				"sha256": attestationDigest,
			},
		})
	}

	return attestationTypes, inputAttestations
}

// attestationURIFor builds the input-attestation URI for the given image digest.
// when the image digest encodes an org-scoped registry reference, it points at the
// GitHub attestations API; otherwise it falls back to the URN format.
func attestationURIFor(imageDigest, attestationDigest string) string {
	if imageDigest == "" {
		return fmt.Sprintf(attestationURNFormat, attestationDigest)
	}

	digestParts := strings.Split(imageDigest, "@")
	if len(digestParts) < 2 {
		return fmt.Sprintf(attestationURNFormat, attestationDigest)
	}

	imagePart := digestParts[0]
	if !strings.Contains(imagePart, "/") {
		return fmt.Sprintf(attestationURNFormat, attestationDigest)
	}

	parts := strings.Split(imagePart, "/")
	if len(parts) < 2 {
		return fmt.Sprintf(attestationURNFormat, attestationDigest)
	}

	org := parts[len(parts)-2]
	digestValue := strings.TrimPrefix(digestParts[1], "sha256:")
	return fmt.Sprintf("https://api.github.com/orgs/%s/attestations/%s#%s",
		org, digestValue, attestationDigest)
}

// maybeGenerateVSA generates a Verification Summary Attestation when --generate-vsa
// is set, validating that the required output path and policy URI are provided.
func maybeGenerateVSA(cmd *cobra.Command, quiet bool, vsaArtifactRef string, vsaSubjects []vsa.VSASubject, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, sigs []oci.Signature) error {
	generateVSA, _ := cmd.Flags().GetBool(flagGenerateVSA)
	if !generateVSA {
		return nil
	}

	vsaOutput, _ := cmd.Flags().GetString(flagVSAOutput)
	policyURI, _ := cmd.Flags().GetString(flagPolicyURI)

	if vsaOutput == "" {
		return fmt.Errorf("VSA output path is required when --generate-vsa is used")
	}
	if policyURI == "" {
		return fmt.Errorf("policy URI is required when --generate-vsa is used")
	}

	policyBundlePath, _ := cmd.Flags().GetString(flagPolicyBundlePath)
	policySchemasPath, _ := cmd.Flags().GetString(flagPolicySchemasPath)
	policyDataPath, _ := cmd.Flags().GetString(flagPolicyDataPath)

	// the build-provenance signer identity is enforced when a cert-identity or
	// signer allowlist was supplied; this gates the SLSA Build L3 claim in the VSA
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	certIdentityList, _ := cmd.Flags().GetString(flagCertIdentityList)
	identityEnforced := certIdentity != "" || certIdentityList != ""
	if err := generateVSAWithOptions(context.Background(), vsaArtifactRef, vsaSubjects, inputAttestations, attestationTypes, sigs, quiet, vsaOutput, policyURI, policyBundlePath, policySchemasPath, policyDataPath, identityEnforced); err != nil {
		return fmt.Errorf("failed to generate VSA: %w", err)
	}

	return nil
}

func generateVSAWithOptions(ctx context.Context, artifactDigest string, vsaSubjects []vsa.VSASubject, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, sigs []oci.Signature, quiet bool, vsaOutput, policyURI, policyBundlePath, policySchemasPath, policyDataPath string, identityEnforced bool) error {
	return vsa.Generate(ctx, vsa.GenerateOptions{
		ArtifactDigest:    artifactDigest,
		VSASubjects:       vsaSubjects,
		InputAttestations: inputAttestations,
		AttestationTypes:  attestationTypes,
		Signatures:        sigs,
		IdentityEnforced:  identityEnforced,
		PolicyURI:         policyURI,
		PolicyBundlePath:  policyBundlePath,
		PolicySchemasPath: policySchemasPath,
		PolicyDataPath:    policyDataPath,
		VSAOutput:         vsaOutput,
		Quiet:             quiet,
		Version:           version,
		OpaVersion:        opaVersion,
	})
}
