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

	"github.com/liatrio/autogov-verify/pkg/download"
	ghclient "github.com/liatrio/autogov-verify/pkg/github"
	"github.com/liatrio/autogov-verify/pkg/offline"
	"github.com/liatrio/autogov-verify/pkg/paths"
	"github.com/liatrio/autogov-verify/pkg/verify"
	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// build-time variables set via ldflags
var (
	version    = "dev"
	commit     = "none"
	date       = "unknown"
	opaVersion = "v1.8.0" // can be overridden at build time
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
	flagArtifactDigest      = "artifact-digest"
	flagBlobPath            = "blob-path"
	flagAttestationsPath    = "attestations-path"
	flagCertIdentityList    = "cert-identity-list"
	flagGenerateVSA         = "generate-vsa"
	flagVSAOutput           = "vsa-output"
	flagPolicyURI           = "policy-uri"
	flagPolicyBundlePath    = "policy-bundle-path"
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
	rootCmd.Flags().StringP(flagArtifactDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
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

	// VSA generation flags
	rootCmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	rootCmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	rootCmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		// Re-bind flags to ensure all values are captured
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("failed to bind flags: %w", err)
		}
		
		blobPath, _ := cmd.Flags().GetString(flagBlobPath)
		artifactDigest, _ := cmd.Flags().GetString(flagArtifactDigest)
		repo, _ := cmd.Flags().GetString(flagRepo)

		if blobPath == "" && artifactDigest == "" {
			return fmt.Errorf("either --%s or --%s must be provided", flagArtifactDigest, flagBlobPath)
		}

		// For blob verification, --repo is required
		if blobPath != "" && repo == "" {
			return fmt.Errorf("--%s is required for blob verification", flagRepo)
		}

		// token validation is handled by github.GetToken() and github.NewClient()
		token := ghclient.GetToken()
		if token == "" {
			return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
		}

		return nil
	}

	// download flags
	downloadCmd.Flags().String(flagBlobPath, "", "Path to artifact file to download attestations for")
	downloadCmd.Flags().StringP(flagDownloadOutput, "o", "", "Output file path for attestation bundles (required)")
	downloadCmd.Flags().String(flagDownloadFormat, "jsonl", "Output format: json or jsonl")
	downloadCmd.Flags().StringP("repo", "R", "", "Repository to download attestations from (format: owner/repo)")

	// offline flags
	offlineCmd.Flags().String(flagBlobPath, "", "Path to artifact file to verify (optional - if not provided, verifies attestations only)")
	offlineCmd.Flags().String(flagArtifactDigest, "", "Artifact digest to verify (e.g., sha256:abc123... for container images)")
	offlineCmd.Flags().String(flagOfflineAttestations, "", "Path to attestation bundles file (required)")
	offlineCmd.Flags().String(flagCertIdentity, "", "Expected certificate identity (required)")
	offlineCmd.Flags().String(flagCertIssuer, "https://token.actions.githubusercontent.com", "Expected certificate issuer")
	offlineCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")
	offlineCmd.Flags().String(flagOfflineTrustedRoot, "", "Path to trusted root file (optional)")

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
		flagArtifactDigest:   "ARTIFACT_DIGEST",
		flagBlobPath:         "BLOB_PATH",
		flagRepo:             "REPO",
		flagCertIdentity:     "CERT_IDENTITY",
		flagCertIssuer:       "CERT_ISSUER",
		flagQuiet:            "QUIET",
		flagSourceRef:        "SOURCE_REF",
		flagAttestationsPath: "ATTESTATIONS_PATH",
		flagCertIdentityList: "CERT_IDENTITY_LIST",
		flagNoCache:          "NO_CACHE",
		flagPolicyBundlePath: "POLICY_BUNDLE_PATH",
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
	quiet := viper.GetBool(flagQuiet)
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
	}

	artifactDigest, _ := cmd.Flags().GetString(flagArtifactDigest)
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	certIssuer, _ := cmd.Flags().GetString(flagCertIssuer)
	sourceRef, _ := cmd.Flags().GetString(flagSourceRef)
	blobPath, _ := cmd.Flags().GetString(flagBlobPath)
	attestationsPath := viper.GetString(flagAttestationsPath)
	client := ghclient.NewClient()

	// Handle multiple blob paths separated by commas or a directory
	blobPaths, err := paths.ExpandPaths(blobPath)
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

		// set up certificate identity validation
		certIdentityOpts := verify.SetupCertIdentityValidation(
			viper.GetString(flagCertIdentityList),
			viper.GetBool(flagNoCache),
			quiet,
		)

		// Verify all blobs or image
		repo := viper.GetString(flagRepo)
		sigs, err = verify.VerifyBlobs(
			context.Background(),
			client,
			verify.Options{
				ArtifactDigest:         artifactDigest,
				Repository:             repo,
				CertIdentity:           certIdentity,
				CertIssuer:             certIssuer,
				SourceRef:              sourceRef,
				BlobPaths:              blobPaths,
				Quiet:                  quiet,
				CertIdentityValidation: certIdentityOpts,
			},
		)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	// use correct digest format based on verification type
	vsaArtifactRef := artifactDigest
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

			// Add subject for this blob
			vsaSubjects = append(vsaSubjects, vsa.VSASubject{
				URI: filepath.Base(path),
				Digest: map[string]string{
					"sha256": digest,
				},
			})

			// Use first blob's digest as the artifact ref (for backward compatibility)
			if vsaArtifactRef == "" {
				vsaArtifactRef = fmt.Sprintf("sha256:%s", digest)
			}
		}
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
		if artifactDigest != "" {
			// extract org from artifact digest for GitHub API endpoint
			// format: [registry/]org/repo@digest
			digestParts := strings.Split(artifactDigest, "@")
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
	if viper.GetBool(flagGenerateVSA) {
		if err := generateVSA(context.Background(), vsaArtifactRef, vsaSubjects, inputAttestations, attestationTypes, sigs, quiet); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}
	}

	return nil
}

// creates a VSA after successful attestation verification
func generateVSA(ctx context.Context, artifactDigest string, vsaSubjects []vsa.VSASubject, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, sigs []oci.Signature, quiet bool) error {
	return vsa.Generate(ctx, vsa.GenerateOptions{
		ArtifactDigest:    artifactDigest,
		VSASubjects:       vsaSubjects,
		InputAttestations: inputAttestations,
		AttestationTypes:  attestationTypes,
		Signatures:        sigs,
		Quiet:             quiet,
		Version:           version,
	})
}

// handles the download command execution
func runDownload(cmd *cobra.Command, args []string) error {
	return download.RunCommand(cmd, args)
}

// handles the offline command execution
func runOffline(cmd *cobra.Command, args []string) error {
	return offline.RunCommand(cmd, args)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
