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

// applyFailOnPolicyError resolves the fail-on-policy-error setting into viper.
// the env var (FAIL_ON_POLICY_ERROR) is bound to viper in cmd/root.go via BindEnv,
// so it is already present. only overwrite it when the flag was explicitly passed,
// otherwise an unconditional viper.Set with the flag default (false) would clobber
// the env binding. an explicit flag therefore wins over the env var.
func applyFailOnPolicyError(cmd *cobra.Command) {
	if cmd.Flags().Changed(flagFailOnPolicyError) {
		failOnPolicyError, _ := cmd.Flags().GetBool(flagFailOnPolicyError)
		viper.Set("fail-on-policy-error", failOnPolicyError)
	}
}

func runAttestation(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool(flagQuiet)

	viper.Set("quiet", quiet)
	applyFailOnPolicyError(cmd)
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

	// opt-in: refresh the public-good trusted root live from the Sigstore TUF repo
	// before verifying anything. fail-closed — on any error we abort instead of
	// falling back to the embedded snapshot. off by default keeps verify hermetic.
	if refresh, _ := cmd.Flags().GetBool(flagRefreshTrustedRoot); refresh {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Refreshing public-good trusted root from the Sigstore TUF repo...")
		}
		if err := root.RefreshPublicTrustedRoot(); err != nil {
			return fmt.Errorf("--%s requested but live refresh failed: %w", flagRefreshTrustedRoot, err)
		}
	}

	client, err := ghclient.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	blobPaths, err := cli.ExpandBlobPaths(blobPath)
	if err != nil {
		return fmt.Errorf("failed to expand blob paths: %w", err)
	}

	// when neither a single identity nor a list is enforced, verification accepts
	// any valid Fulcio signature (unsafe). warn exactly once on stderr, ungated by
	// --quiet and off the stdout summary, so it survives quiet CI runs and stdout capture.
	if certIdentity == "" && certIdentityList == "" {
		fmt.Fprintf(os.Stderr, "warning: no certificate identity enforced — accepting any valid Fulcio signature (unsafe); set --%s and/or --%s to enforce a signer allowlist\n", flagCertIdentity, flagCertIdentityList)
	}

	var sigs []oci.Signature

	if attestationsPath != "" && blobPath != "" {
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
			return fmt.Errorf("failed to resolve accepted certificate identities: %w", err)
		}

		verifyOpts := offline.VerifyOptions{
			CertIdentity:       certIdentity,
			CertOIDCIssuer:     certIssuer,
			AcceptedIdentities: accepted,
		}

		verifier, err := offline.NewOfflineVerifier("", verifyOpts)
		if err != nil {
			return fmt.Errorf("failed to create offline verifier: %w", err)
		}

		if err := verifier.LoadBundlesFromFile(attestationsPath); err != nil {
			return fmt.Errorf("failed to load attestation bundles: %w", err)
		}

		result, err := verifier.VerifyArtifact(blobPath)
		if err != nil {
			return fmt.Errorf("offline verification failed: %w", err)
		}

		if !result.Verified {
			return fmt.Errorf("offline verification failed: attestations could not be verified")
		}

		sigs = []oci.Signature{}
	} else {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Using online verification mode")
		}

		certOpts := orchestrate.SetupCertIdentityValidation(certIdentityList, noCache, quiet)

		repo, _ := cmd.Flags().GetString(flagRepo)
		if repo != "" && imageDigest != "" && !strings.Contains(imageDigest, "/") {
			imageDigest = fmt.Sprintf("ghcr.io/%s@%s", repo, imageDigest)
		}
		sigs, err = orchestrate.VerifyBlobs(cmd.Context(), client, orchestrate.Options{
			ArtifactDigest:         imageDigest,
			Repository:             repo,
			CertIdentity:           certIdentity,
			CertIssuer:             certIssuer,
			SourceRef:              sourceRef,
			BlobPaths:              blobPaths,
			Quiet:                  quiet,
			CertIdentityValidation: certOpts,
		})
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	vsaArtifactRef := imageDigest
	var vsaSubjects []vsa.VSASubject

	if len(blobPaths) > 0 {
		for _, path := range blobPaths {
			blobData, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read blob file %s for VSA: %w", path, err)
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

	if !quiet {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nSummary:")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "✓ Successfully verified %d attestations\n", len(sigs))
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nAttestation Types:")
	}

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

		var attestationURI string
		if imageDigest != "" {
			digestParts := strings.Split(imageDigest, "@")
			if len(digestParts) >= 2 {
				imagePart := digestParts[0]
				if strings.Contains(imagePart, "/") {
					parts := strings.Split(imagePart, "/")
					if len(parts) >= 2 {
						org := parts[len(parts)-2]
						digestValue := strings.TrimPrefix(digestParts[1], "sha256:")
						attestationURI = fmt.Sprintf("https://api.github.com/orgs/%s/attestations/%s#%s",
							org, digestValue, attestationDigest)
					} else {
						attestationURI = fmt.Sprintf(attestationURNFormat, attestationDigest)
					}
				} else {
					attestationURI = fmt.Sprintf(attestationURNFormat, attestationDigest)
				}
			} else {
				attestationURI = fmt.Sprintf(attestationURNFormat, attestationDigest)
			}
		} else {
			attestationURI = fmt.Sprintf(attestationURNFormat, attestationDigest)
		}

		inputAttestations = append(inputAttestations, vsa.ResourceDescriptor{
			URI: attestationURI,
			Digest: map[string]string{
				"sha256": attestationDigest,
			},
		})
	}

	generateVSA, _ := cmd.Flags().GetBool(flagGenerateVSA)
	if generateVSA {
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
		if err := generateVSAWithOptions(context.Background(), vsaArtifactRef, vsaSubjects, inputAttestations, attestationTypes, sigs, quiet, vsaOutput, policyURI, policyBundlePath, policySchemasPath, policyDataPath); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}
	}

	return nil
}

func generateVSAWithOptions(ctx context.Context, artifactDigest string, vsaSubjects []vsa.VSASubject, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, sigs []oci.Signature, quiet bool, vsaOutput, policyURI, policyBundlePath, policySchemasPath, policyDataPath string) error {
	return vsa.Generate(ctx, vsa.GenerateOptions{
		ArtifactDigest:    artifactDigest,
		VSASubjects:       vsaSubjects,
		InputAttestations: inputAttestations,
		AttestationTypes:  attestationTypes,
		Signatures:        sigs,
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
