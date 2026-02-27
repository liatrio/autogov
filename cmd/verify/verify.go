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

	"github.com/liatrio/autogov-verify/pkg/cli"
	ghclient "github.com/liatrio/autogov-verify/pkg/github"
	"github.com/liatrio/autogov-verify/pkg/offline"
	"github.com/liatrio/autogov-verify/pkg/orchestrate"
	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// flag constants shared across verify subcommands
const (
	flagImageDigest       = "image-digest"
	flagBlobPath          = "blob-path"
	flagRepo              = "repo"
	flagCertIdentity      = "cert-identity"
	flagCertIssuer        = "cert-issuer"
	flagSourceRef         = "source-ref"
	flagQuiet             = "quiet"
	flagAttestationsPath  = "attestations-path"
	flagCertIdentityList  = "cert-identity-list"
	flagNoCache           = "no-cache"
	flagPolicyBundlePath  = "policy-bundle-path"
	flagPolicySchemasPath = "policy-schemas-path"
	flagPolicyDataPath    = "policy-data-path"
	flagFailOnPolicyError = "fail-on-policy-error"
	flagGenerateVSA       = "generate-vsa"
	flagVSAOutput         = "vsa-output"
	flagPolicyURI         = "policy-uri"
	attestationURNFormat  = "urn:attestation:sha256:%s"
)

// build-time vars — set via SetBuildInfo from cmd/root.go
var (
	version    = "dev"
	opaVersion = "v1.8.0"
)

// SetBuildInfo sets build-time version information for VSA generation.
func SetBuildInfo(v, opa string) {
	version = v
	opaVersion = opa
}

// NewVerifyCmdForTesting creates a fresh VerifyCmd instance for use in tests.
// Unlike the package-level VerifyCmd, this does not carry state between tests.
func NewVerifyCmdForTesting() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "verify",
		Short:   "Verify GitHub artifact attestations",
		RunE:    runVerify,
		PreRunE: preRunVerify,
	}

	cmd.Flags().StringP(flagImageDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	cmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	cmd.Flags().String(flagRepo, "", "Repository to fetch attestations from (format: owner/repo)")
	cmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against")
	cmd.Flags().StringP(flagCertIssuer, "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	cmd.Flags().StringP(flagSourceRef, "r", "", "Source repository ref to verify against")
	cmd.Flags().String(flagAttestationsPath, "", "Path to directory containing attestation files")
	cmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")
	cmd.Flags().String(flagCertIdentityList, "", "URL or file path to the certificate identity list")
	cmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")
	cmd.Flags().String(flagPolicyBundlePath, "", "Path to OPA policy bundle")
	cmd.Flags().String(flagPolicySchemasPath, "", "Path to JSON schemas")
	cmd.Flags().String(flagPolicyDataPath, "", "Path to JSON data file")
	cmd.Flags().Bool(flagFailOnPolicyError, false, "Exit with error when policy evaluation fails")
	cmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation")
	cmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA")
	cmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation")

	cmd.AddCommand(newGitCmd())

	return cmd
}

// VerifyCmd is the parent command for verify operations.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify GitHub artifact attestations",
	Long: `Verify GitHub artifact attestations using Sigstore.

This command verifies attestations for container images or blob files,
checking certificate identity, issuer, and optionally validating against
OPA policies.

Examples:
  # Verify a container image
  autogov verify --image-digest ghcr.io/org/repo@sha256:abc123 --repo org/repo

  # Verify a blob file
  autogov verify --blob-path artifact.tar.gz --repo org/repo --cert-identity "workflow@ref"

  # Verify with OPA policy evaluation
  autogov verify --blob-path artifact.tar.gz --repo org/repo --policy-bundle-path policies/

  # Verify gitsign commit signatures
  autogov verify git HEAD`,
	RunE: runVerify,
}

func init() {
	VerifyCmd.Flags().StringP(flagImageDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	VerifyCmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	VerifyCmd.Flags().String(flagRepo, "", "Repository to fetch attestations from (format: owner/repo) - required for blob verification")
	VerifyCmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against (optional - if not provided, any valid signature will be accepted)")
	VerifyCmd.Flags().StringP(flagCertIssuer, "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	VerifyCmd.Flags().StringP(flagSourceRef, "r", "", "Source repository ref to verify against (e.g., refs/heads/main)")
	VerifyCmd.Flags().String(flagAttestationsPath, "", "Path to directory containing attestation files for offline verification")
	VerifyCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")

	VerifyCmd.Flags().String(flagCertIdentityList, "", "URL or file path to the certificate identity list. If provided, enables cert-identity validation against this source (optional)")
	VerifyCmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")

	VerifyCmd.Flags().String(flagPolicyBundlePath, "", "Path to OPA policy bundle directory or .tar.gz file for policy evaluation")
	VerifyCmd.Flags().String(flagPolicySchemasPath, "", "Path to directory or .tar.gz file containing JSON schemas for OPA policy validation")
	VerifyCmd.Flags().String(flagPolicyDataPath, "", "Path to JSON file containing additional OPA data (e.g., vulnerability_thresholds)")
	VerifyCmd.Flags().Bool(flagFailOnPolicyError, false, "Exit with error when policy evaluation fails (default: false)")

	VerifyCmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	VerifyCmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	VerifyCmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")

	VerifyCmd.PreRunE = preRunVerify

	// register git subcommand
	VerifyCmd.AddCommand(newGitCmd())
}

// preRunVerify validates verify command flags.
func preRunVerify(cmd *cobra.Command, args []string) error {
	blobPath, _ := cmd.Flags().GetString(flagBlobPath)
	imageDigest, _ := cmd.Flags().GetString(flagImageDigest)
	repo, _ := cmd.Flags().GetString(flagRepo)

	if blobPath == "" && imageDigest == "" && len(args) == 0 {
		return fmt.Errorf("either --%s, --%s, or a positional argument must be provided", flagImageDigest, flagBlobPath)
	}

	if (blobPath != "" || imageDigest != "") && repo == "" {
		return fmt.Errorf("--%s is required for blob and image verification", flagRepo)
	}

	token := ghclient.GetToken()
	if token == "" {
		return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
	}

	return nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool(flagQuiet)

	viper.Set("quiet", quiet)
	failOnPolicyError, _ := cmd.Flags().GetBool(flagFailOnPolicyError)
	viper.Set("fail-on-policy-error", failOnPolicyError)

	if !quiet {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Starting verification process...")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "---")
	}

	imageDigest, _ := cmd.Flags().GetString(flagImageDigest)
	if imageDigest == "" && len(args) > 0 {
		imageDigest = args[0]
	}
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	certIssuer, _ := cmd.Flags().GetString(flagCertIssuer)
	sourceRef, _ := cmd.Flags().GetString(flagSourceRef)
	blobPath, _ := cmd.Flags().GetString(flagBlobPath)
	attestationsPath, _ := cmd.Flags().GetString(flagAttestationsPath)
	client := ghclient.NewClient()

	blobPaths, err := cli.ExpandBlobPaths(blobPath)
	if err != nil {
		return fmt.Errorf("failed to expand blob paths: %w", err)
	}

	var sigs []oci.Signature

	if attestationsPath != "" && blobPath != "" {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Using offline verification mode")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Attestations path: %s\n", attestationsPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Blob path: %s\n", blobPath)
		}

		verifyOpts := offline.VerifyOptions{
			CertIdentity:   certIdentity,
			CertOIDCIssuer: certIssuer,
			SkipTLogVerify: true,
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

		certIdentityList, _ := cmd.Flags().GetString(flagCertIdentityList)
		noCache, _ := cmd.Flags().GetBool(flagNoCache)
		certOpts := orchestrate.SetupCertIdentityValidation(
			certIdentityList,
			noCache,
			quiet,
		)

		repo, _ := cmd.Flags().GetString("repo")
		if repo != "" && imageDigest != "" && !strings.Contains(imageDigest, "/") {
			imageDigest = fmt.Sprintf("ghcr.io/%s@%s", repo, imageDigest)
		}
		sigs, err = orchestrate.VerifyBlobs(context.Background(), client, orchestrate.Options{
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
			digest := fmt.Sprintf("%x", h.Sum(nil))

			vsaSubjects = append(vsaSubjects, vsa.VSASubject{
				URI: filepath.Base(path),
				Digest: map[string]string{
					"sha256": digest,
				},
			})
		}

		if vsaArtifactRef == "" && len(blobPaths) > 0 {
			repo, _ := cmd.Flags().GetString("repo")
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
