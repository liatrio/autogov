package main

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
	"github.com/liatrio/autogov-verify/pkg/download"
	ghclient "github.com/liatrio/autogov-verify/pkg/github"
	"github.com/liatrio/autogov-verify/pkg/offline"
	"github.com/liatrio/autogov-verify/pkg/orchestrate"
	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// build-time variables set via ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	// can be overridden at build time
	OpaVersion = "v1.8.0"
)

var (
	rootCmd = &cobra.Command{
		Use:   "autogov-verify",
		Short: "Verify GitHub Artifact Attestation",
		Long: `A tool for verifying GitHub Artifact Attestations using cosign.
It supports verifying attestations from GitHub Actions workflows with configurable
certificate identity and issuer.`,
		RunE: run,
	}

	downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "Download attestations for offline verification",
		Long: `Download GitHub artifact attestations and save them as Sigstore bundles
for later offline verification. This allows verification in air-gapped environments
or when GitHub API access is unavailable.`,
		RunE: runDownload,
	}

	offlineCmd = &cobra.Command{
		Use:   "offline",
		Short: "Verify attestations offline using pre-downloaded bundles",
		Long: `Verify GitHub artifact attestations using pre-downloaded Sigstore bundles
and trusted roots. This enables verification in air-gapped environments without
requiring GitHub API access or online Sigstore infrastructure.`,
		RunE: runOffline,
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("autogov-verify version %s\n", version)
			fmt.Printf("  commit: %s\n", commit)
			fmt.Printf("  built:  %s\n", date)
		},
	}
)

const (
	flagCertIdentity        = "cert-identity"
	flagCertIssuer          = "cert-issuer"
	flagSourceRef           = "source-ref"
	flagQuiet               = "quiet"
	flagImageDigest         = "image-digest"
	flagBlobPath            = "blob-path"
	flagAttestationsPath    = "attestations-path"
	flagCertIdentityList    = "cert-identity-list"
	flagGenerateVSA         = "generate-vsa"
	flagVSAOutput           = "vsa-output"
	flagPolicyURI           = "policy-uri"
	flagPolicyBundlePath    = "policy-bundle-path"
	flagPolicySchemasPath   = "policy-schemas-path"
	flagNoCache             = "no-cache"
	flagOfflineAttestations = "attestations"
	flagOfflineTrustedRoot  = "trusted-root"
	flagDownloadOutput      = "output"
	flagDownloadFormat      = "format"
	flagRepo                = "repo"
	attestationURNFormat    = "urn:attestation:sha256:%s"
)

func init() {
	// flags
	rootCmd.Flags().StringP(flagImageDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	rootCmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	rootCmd.Flags().String(flagRepo, "", "Repository to fetch attestations from (format: owner/repo) - required for blob verification")
	rootCmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against (optional - if not provided, any valid signature will be accepted)")
	rootCmd.Flags().StringP(flagCertIssuer, "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	rootCmd.Flags().StringP(flagSourceRef, "r", "", "Source repository ref to verify against (e.g., refs/heads/main)")
	rootCmd.Flags().String(flagAttestationsPath, "", "Path to directory containing attestation files for offline verification")
	rootCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")

	// certificate identity validation flags
	rootCmd.Flags().String(flagCertIdentityList, "", "URL or file path to the certificate identity list. If provided, enables cert-identity validation against this source (optional)")
	rootCmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")

	// OPA policy flags
	rootCmd.Flags().String(flagPolicyBundlePath, "", "Path to OPA policy bundle directory or .tar.gz file for policy evaluation")
	rootCmd.Flags().String(flagPolicySchemasPath, "", "Path to directory or .tar.gz file containing JSON schemas for OPA policy validation")

	// VSA generation flags
	rootCmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	rootCmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	rootCmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		blobPath, _ := cmd.Flags().GetString(flagBlobPath)
		imageDigest, _ := cmd.Flags().GetString(flagImageDigest)
		repo, _ := cmd.Flags().GetString(flagRepo)

		if blobPath == "" && imageDigest == "" && len(args) == 0 {
			return fmt.Errorf("either --%s, --%s, or a positional argument must be provided", flagImageDigest, flagBlobPath)
		}

		// blob and image verification requires --repo
		if (blobPath != "" || imageDigest != "") && repo == "" {
			return fmt.Errorf("--%s is required for blob and image verification", flagRepo)
		}

		// token validation
		token := ghclient.GetToken()
		if token == "" {
			return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
		}

		return nil
	}

	// download flags
	downloadCmd.Flags().String(flagBlobPath, "", "Path to artifact file to download attestations for")
	downloadCmd.Flags().String("image-digest", "", "Container image digest (e.g., sha256:...)")
	downloadCmd.Flags().StringP(flagDownloadOutput, "o", "", "Output file path for attestation bundles (required)")
	downloadCmd.Flags().String(flagDownloadFormat, "jsonl", "Output format: json or jsonl")
	downloadCmd.Flags().StringP("repo", "R", "", "Repository to download attestations from (format: owner/repo)")
	downloadCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")

	downloadCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		blobPath, _ := cmd.Flags().GetString(flagBlobPath)
		imageDigest, _ := cmd.Flags().GetString("image-digest")

		if blobPath == "" && imageDigest == "" && len(args) == 0 {
			return fmt.Errorf("must specify --%s, --%s, or provide artifact digest as argument", flagBlobPath, "image-digest")
		}

		return nil
	}

	// offline flags
	offlineCmd.Flags().String(flagBlobPath, "", "Path to artifact file to verify (optional - if not provided, verifies attestations only)")
	offlineCmd.Flags().String(flagImageDigest, "", "Artifact digest to verify (e.g., sha256:abc123... for container images)")
	offlineCmd.Flags().String(flagOfflineAttestations, "", "Path to attestation bundles file (required)")
	offlineCmd.Flags().String(flagCertIdentity, "", "Expected certificate identity (required)")
	offlineCmd.Flags().String(flagCertIssuer, "https://token.actions.githubusercontent.com", "Expected certificate issuer")
	offlineCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")
	offlineCmd.Flags().String(flagOfflineTrustedRoot, "", "Path to trusted root file (optional)")

	// VSA generation flags for offline mode
	offlineCmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	offlineCmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	offlineCmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")
	offlineCmd.Flags().String(flagPolicyBundlePath, "", "Path to OPA policy bundle directory or .tar.gz file for policy evaluation")
	offlineCmd.Flags().String(flagPolicySchemasPath, "", "Path to directory or .tar.gz file containing JSON schemas for OPA policy validation")
	offlineCmd.Flags().String(flagSourceRef, "", "Source repository ref to verify against (e.g., refs/heads/main)")

	offlineCmd.PreRunE = func(cmd *cobra.Command, args []string) error {

		blobPath, _ := cmd.Flags().GetString(flagBlobPath)
		imageDigest, _ := cmd.Flags().GetString(flagImageDigest)

		if blobPath == "" && imageDigest == "" && len(args) == 0 {
			return fmt.Errorf("must specify --%s, --%s, or provide artifact digest as argument", flagBlobPath, flagImageDigest)
		}

		return nil
	}

	if err := offlineCmd.MarkFlagRequired(flagOfflineAttestations); err != nil {
		panic(fmt.Sprintf("failed to bind download flags: %v", err))
	}
	if err := downloadCmd.MarkFlagRequired(flagDownloadOutput); err != nil {
		panic(fmt.Sprintf("failed to mark download output flag as required: %v", err))
	}
	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}
	if err := viper.BindPFlags(downloadCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind download flags: %v", err))
	}
	if err := viper.BindPFlags(offlineCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind offline flags: %v", err))
	}

	// bind env vars
	envBinds := map[string]string{
		flagImageDigest:       "IMAGE_DIGEST",
		flagBlobPath:          "BLOB_PATH",
		flagRepo:              "REPO",
		flagCertIdentity:      "CERT_IDENTITY",
		flagCertIssuer:        "CERT_ISSUER",
		flagQuiet:             "QUIET",
		flagSourceRef:         "SOURCE_REF",
		flagAttestationsPath:  "ATTESTATIONS_PATH",
		flagCertIdentityList:  "CERT_IDENTITY_LIST",
		flagNoCache:           "NO_CACHE",
		flagPolicyBundlePath:  "POLICY_BUNDLE_PATH",
		flagPolicySchemasPath: "POLICY_SCHEMAS_PATH",
	}

	for key, env := range envBinds {
		if err := viper.BindEnv(key, env); err != nil {
			panic(fmt.Sprintf("failed to bind environment variables: %v", err))
		}
	}

	// add subcommands
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(offlineCmd)
	rootCmd.AddCommand(versionCmd)
}

func run(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool(flagQuiet)
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
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

	// multiple blob paths handled separated by commas or a directory
	blobPaths, err := cli.ExpandBlobPaths(blobPath)
	if err != nil {
		return fmt.Errorf("failed to expand blob paths: %w", err)
	}

	// check for offline vs online verification
	var sigs []oci.Signature

	if attestationsPath != "" && blobPath != "" {
		// offline verification mode using pre-downloaded attestations
		if !quiet {
			fmt.Println("Using offline verification mode")
			fmt.Printf("Attestations path: %s\n", attestationsPath)
			fmt.Printf("Blob path: %s\n", blobPath)
		}

		// offline verification
		verifyOpts := offline.VerifyOptions{
			CertIdentity:   certIdentity,
			CertOIDCIssuer: certIssuer,
			SkipTLogVerify: true, // skip tlog verification in offline mode
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

		// converts offline results to oci.Signature format for VSA generation
		sigs = []oci.Signature{}
	} else {
		// online verification mode using GitHub API
		if !quiet {
			fmt.Println("Using online verification mode")
		}

		// setup cert identity validation if requested
		certIdentityList, _ := cmd.Flags().GetString(flagCertIdentityList)
		noCache, _ := cmd.Flags().GetBool(flagNoCache)
		certOpts := orchestrate.SetupCertIdentityValidation(
			certIdentityList,
			noCache,
			quiet,
		)

		// verifies all blobs or image
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

	// use correct digest format based on verification type
	vsaArtifactRef := imageDigest
	var vsaSubjects []vsa.VSASubject

	if len(blobPaths) > 0 {
		// blob verification - handle multiple blobs
		for _, path := range blobPaths {
			blobData, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read blob file %s for VSA: %w", path, err)
			}
			h := sha256.New()
			h.Write(blobData)
			digest := fmt.Sprintf("%x", h.Sum(nil))

			// subject added for blob
			vsaSubjects = append(vsaSubjects, vsa.VSASubject{
				URI: filepath.Base(path),
				Digest: map[string]string{
					"sha256": digest,
				},
			})

		}

		// repo URI as resourceUri for all blob verifications
		if vsaArtifactRef == "" && len(blobPaths) > 0 {
			repo, _ := cmd.Flags().GetString("repo")
			if repo != "" {
				vsaArtifactRef = fmt.Sprintf("https://github.com/%s", repo)
			}
		}
	} else if imageDigest != "" {
		// create VSA subject for the container image
		digestValue := imageDigest
		// use SHA256 from image reference (format: registry/repo@sha256:hash)
		if idx := strings.Index(imageDigest, "@sha256:"); idx != -1 {
			digestValue = imageDigest[idx+8:] // Skip "@sha256:"
		} else if strings.HasPrefix(imageDigest, "sha256:") {
			digestValue = strings.TrimPrefix(imageDigest, "sha256:")
		}

		vsaSubjects = append(vsaSubjects, vsa.VSASubject{
			URI: imageDigest, // image ref with digest
			Digest: map[string]string{
				"sha256": digestValue,
			},
		})
		// use image reference as resourceUri
		vsaArtifactRef = imageDigest
	}

	if !quiet {
		fmt.Println("\nSummary:")
		fmt.Printf("✓ Successfully verified %d attestations\n", len(sigs))
		fmt.Println("\nAttestation Types:")
	}

	// collect attestation types / prepare for VSA generation
	var attestationTypes []string
	var inputAttestations []vsa.ResourceDescriptor

	for i, sig := range sigs {
		payload, err := sig.Payload()
		if err != nil {
			log.Printf("Warning: failed to get payload for attestation %d: %v", i, err)
			continue
		}

		// decode base64 payload
		decodedPayload, err := base64.StdEncoding.DecodeString(string(payload))
		if err != nil {
			log.Printf("Warning: failed to decode payload for attestation %d: %v", i, err)
			continue
		}

		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(decodedPayload, &statement); err != nil {
			log.Printf("Warning: failed to parse statement for attestation %d: %v", i, err)
			continue
		}

		attestationTypes = append(attestationTypes, statement.PredicateType)
		fmt.Printf("%d. %s\n", i+1, statement.PredicateType)

		// prep input attestation for VSA generation
		// calculate actual SHA256 digest of the attestation payload
		h := sha256.New()
		h.Write(decodedPayload)
		attestationDigest := fmt.Sprintf("%x", h.Sum(nil))

		// create proper URI pointing to where attestation can be retrieved
		var attestationURI string
		if imageDigest != "" {
			// extract org from artifact digest for GitHub API endpoint
			// format: [registry/]org/repo@digest
			digestParts := strings.Split(imageDigest, "@")
			if len(digestParts) >= 2 {
				imagePart := digestParts[0]
				// remove registry prefix if present (e.g., ghcr.io/)
				if strings.Contains(imagePart, "/") {
					parts := strings.Split(imagePart, "/")
					if len(parts) >= 2 {
						// get org
						org := parts[len(parts)-2]
						// create GitHub API endpoint URI with attestation digest as identifier
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
			// use URN format for blob attestations
			attestationURI = fmt.Sprintf(attestationURNFormat, attestationDigest)
		}

		inputAttestations = append(inputAttestations, vsa.ResourceDescriptor{
			URI: attestationURI,
			Digest: map[string]string{
				"sha256": attestationDigest,
			},
		})
	}

	// generate VSA if requested
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
		if err := generateVSAWithOptions(context.Background(), vsaArtifactRef, vsaSubjects, inputAttestations, attestationTypes, sigs, quiet, vsaOutput, policyURI, policyBundlePath); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}
	}

	return nil
}

// creates a VSA after successful attestation verification with additional options
func generateVSAWithOptions(ctx context.Context, artifactDigest string, vsaSubjects []vsa.VSASubject, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, sigs []oci.Signature, quiet bool, vsaOutput, policyURI, policyBundlePath string) error {
	return vsa.Generate(ctx, vsa.GenerateOptions{
		ArtifactDigest:    artifactDigest,
		VSASubjects:       vsaSubjects,
		InputAttestations: inputAttestations,
		AttestationTypes:  attestationTypes,
		Signatures:        sigs,
		PolicyURI:         policyURI,
		PolicyBundlePath:  policyBundlePath,
		VSAOutput:         vsaOutput,
		Quiet:             quiet,
		Version:           version,
		OpaVersion:        OpaVersion,
	})
}

// handles download command execution
func runDownload(cmd *cobra.Command, args []string) error {
	return download.RunCommand(cmd, args)
}

// handles offline command execution
func runOffline(cmd *cobra.Command, args []string) error {
	return offline.RunCommand(cmd, args)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
