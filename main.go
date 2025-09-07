package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liatrio/autogov-verify/pkg/attestations"
	"github.com/liatrio/autogov-verify/pkg/certid"
	"github.com/liatrio/autogov-verify/pkg/download"
	ghclient "github.com/liatrio/autogov-verify/pkg/github"
	"github.com/liatrio/autogov-verify/pkg/offline"
	"github.com/liatrio/autogov-verify/pkg/policy"
	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
)

const (
	flagCertIdentity        = "cert-identity"
	flagCertIssuer          = "cert-issuer"
	flagSourceRef           = "source-ref"
	flagQuiet               = "quiet"
	flagToken               = "token"
	flagArtifactDigest      = "artifact-digest"
	flagBlobPath            = "blob-path"
	flagAttestationsPath    = "attestations-path"
	flagCertIdentityList    = "cert-identity-list"
	flagGenerateVSA         = "generate-vsa"
	flagVSAOutput           = "vsa-output"
	flagPolicyBundlePath    = "policy-bundle-path"
	flagPolicyURI           = "policy-uri"
	flagNoCache             = "no-cache"
	flagOfflineAttestations = "attestations"
	flagOfflineTrustedRoot  = "trusted-root"
	flagDownloadOutput      = "output"
	flagDownloadFormat      = "format"
	attestationURNFormat    = "urn:attestation:sha256:%s"
	autogovVersion          = "v1.1.0"
	opaVersion              = "v1.8.0"
)

func init() {
	// flags
	rootCmd.Flags().StringP(flagArtifactDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	rootCmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	rootCmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against (required)")
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
		blobPath := viper.GetString(flagBlobPath)
		artifactDigest := viper.GetString(flagArtifactDigest)

		if blobPath == "" && artifactDigest == "" {
			return fmt.Errorf("either --%s or --%s must be provided", flagArtifactDigest, flagBlobPath)
		}

		// token validation is handled by github.GetToken() and github.NewClient()
		if token := ghclient.GetToken(); token == "" {
			return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
		}

		return nil
	}

	// download flags
	downloadCmd.Flags().String(flagBlobPath, "", "Path to artifact file to download attestations for")
	downloadCmd.Flags().StringP(flagDownloadOutput, "o", "", "Output file path for attestation bundles (required)")
	downloadCmd.Flags().String(flagDownloadFormat, "jsonl", "Output format: json or jsonl")
	downloadCmd.Flags().StringP("repo", "R", "", "Repository to download attestations from (format: owner/repo)")

	// Offline command flags
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
}

func run(cmd *cobra.Command, args []string) error {
	quiet := viper.GetBool(flagQuiet)
	if !quiet {
		fmt.Println("Starting verification process...")
		fmt.Println("---")
	}

	artifactDigest := viper.GetString(flagArtifactDigest)
	certIdentity := viper.GetString(flagCertIdentity)
	certIssuer := viper.GetString(flagCertIssuer)
	sourceRef := viper.GetString(flagSourceRef)
	blobPath := viper.GetString(flagBlobPath)
	attestationsPath := viper.GetString(flagAttestationsPath)
	client := ghclient.NewClient()

	// check for offline vs online verification
	var sigs []oci.Signature
	var err error

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

		// set up certificate identity validation options if cert-identity-list is provided
		var certIdentityOpts *certid.Options
		if certIdentityListURL := viper.GetString(flagCertIdentityList); certIdentityListURL != "" {
			opts := certid.DefaultOptions()
			opts.DisableCache = viper.GetBool(flagNoCache)

			opts.URL = certIdentityListURL

			certIdentityOpts = &opts

			if !quiet {
				fmt.Println("Certificate identity validation enabled")
				fmt.Printf("Using identity list: %s\n", opts.URL)
				if opts.DisableCache {
					fmt.Println("Cache disabled")
				}
				fmt.Println("---")
			}
		}

		sigs, err = attestations.GetFromGitHub(
			context.Background(),
			artifactDigest,
			client,
			attestations.Options{
				CertIdentity:           certIdentity,
				CertIssuer:             certIssuer,
				BlobPath:               blobPath,
				SourceRef:              sourceRef,
				Quiet:                  quiet,
				CertIdentityValidation: certIdentityOpts,
			},
		)
		if err != nil {
			return fmt.Errorf("error getting attestations: %w", err)
		}
	}

	// use correct digest format based on verification type
	vsaArtifactRef := artifactDigest
	if blobPath != "" {
		// blob verification, calculates the sha256 digest
		blobData, err := os.ReadFile(blobPath)
		if err != nil {
			return fmt.Errorf("failed to read blob file for VSA: %w", err)
		}
		h := sha256.New()
		h.Write(blobData)
		// pass direct digest format
		vsaArtifactRef = fmt.Sprintf("sha256:%x", h.Sum(nil))
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
		if err := generateVSA(context.Background(), vsaArtifactRef, inputAttestations, attestationTypes, sigs, quiet); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}
	}

	return nil
}

// creates a VSA after successful attestation verification
func generateVSA(ctx context.Context, artifactDigest string, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, sigs []oci.Signature, quiet bool) error {
	policyURI := viper.GetString(flagPolicyURI)
	vsaOutput := viper.GetString(flagVSAOutput)

	if policyURI == "" {
		return fmt.Errorf("policy URI is required for VSA generation (use --%s)", flagPolicyURI)
	}

	if vsaOutput == "" {
		return fmt.Errorf("VSA output path is required (use --%s)", flagVSAOutput)
	}

	if !quiet {
		fmt.Println("\n---")
		fmt.Println("Generating Verification Summary Attestation...")
	}

	// verification results based on successful attestation verification
	verificationResults := map[string]bool{
		"attestation.verification": true,
		"attestation.signature":    true,
	}

	// specific results for each attestation type
	for _, attType := range attestationTypes {
		switch attType {
		case "https://slsa.dev/provenance/v1":
			verificationResults["attestation.slsa_provenance"] = true
		case "https://cyclonedx.org/bom":
			verificationResults["attestation.sbom"] = true
		case "https://in-toto.io/attestation/vuln/v0.1":
			verificationResults["attestation.vulnerability"] = true
		default:
			verificationResults["attestation."+attType] = true
		}
	}

	// OPA policy evaluation
	if !quiet {
		fmt.Println("Evaluating OPA policy...")
	}

	// get policy bundle path from flag or use policy URI for download
	policyBundlePath := viper.GetString(flagPolicyBundlePath)
	policyURI = viper.GetString(flagPolicyURI)

	// require policy source for evaluation
	if policyBundlePath == "" && policyURI == "" {
		return fmt.Errorf("policy evaluation requires either --policy-bundle-path or --policy-uri")
	}

	// conditional blocks for proper scoping
	var policyResult *policy.PolicyResult

	// OPA evaluator, use bundle path if provided, otherwise download from URI
	var evaluatorPath string
	if policyBundlePath != "" {
		evaluatorPath = policyBundlePath
	} else {
		evaluatorPath = policyURI
	}

	evaluator, err := policy.NewOPAEvaluator(ctx, evaluatorPath)
	if err != nil {
		return fmt.Errorf("failed to create OPA evaluator: %w", err)
	}
	defer evaluator.Stop(ctx)

	// eval policy against attestations
	policyResult, err = evaluator.EvaluatePolicy(ctx, sigs)
	if err != nil {
		return fmt.Errorf("failed to evaluate OPA policy: %w", err)
	}

	// policy evaluation results
	verificationResults["policy.compliance"] = (policyResult.Result == "PASSED")

	if !quiet {
		fmt.Printf("✓ Policy evaluation completed: %s\n", policyResult.Result)
		if len(policyResult.Violations) > 0 {
			fmt.Printf("  Policy violations: %d\n", len(policyResult.Violations))
			for _, violation := range policyResult.Violations {
				fmt.Printf("    - %s: %s\n", violation.Policy, violation.Message)
			}
		}
	}

	// calculate policy digest from the actual policy content
	policyDigest, err := calculatePolicyDigest(evaluatorPath)
	if err != nil {
		return fmt.Errorf("failed to calculate policy digest: %w", err)
	}

	// create VSA options with input attestations
	opts := vsa.VSAOptions{
		InputAttestations: inputAttestations,
		AutoGovVersion:    autogovVersion,
		PolicyDigest: map[string]string{
			"sha256": policyDigest,
		},
		AdditionalVerifiers: map[string]string{
			"opa": opaVersion,
		},
	}

	// generate VSA
	generatedVSA, err := vsa.GenerateVSAWithOptions(artifactDigest, policyURI, verificationResults, opts)
	if err != nil {
		return fmt.Errorf("failed to generate VSA: %w", err)
	}

	// VSA metadata
	if policyResult != nil {
		if generatedVSA.Metadata == nil {
			generatedVSA.Metadata = make(map[string]interface{})
		}

		// policy evaluation metadata
		generatedVSA.Metadata["autogov.policy.evaluation"] = map[string]interface{}{
			"result":           policyResult.Result,
			"violations":       policyResult.Violations,
			"evaluation_time":  policyResult.Timestamp,
			"policy_bundle":    evaluatorPath,
			"opa_version":      opaVersion,
			"governance_rules": []string{"governance.allow", "governance.violations"},
			"details":          policyResult.Details,
		}

		// violation summary
		if len(policyResult.Violations) > 0 {
			violationSummary := make(map[string][]string)
			for _, violation := range policyResult.Violations {
				violationSummary[violation.Policy] = append(violationSummary[violation.Policy], violation.Message)
			}
			generatedVSA.Metadata["autogov.policy.violation_summary"] = violationSummary
		}

		// policy compliance metrics
		generatedVSA.Metadata["autogov.policy.metrics"] = map[string]interface{}{
			"total_violations":    len(policyResult.Violations),
			"compliance_status":   policyResult.Result,
			"input_attestations":  len(sigs),
			"evaluation_duration": time.Since(policyResult.Timestamp).Milliseconds(),
		}
	}

	// serializes VSA
	vsaBytes, err := generatedVSA.SerializeVSA()
	if err != nil {
		return fmt.Errorf("failed to serialize VSA: %w", err)
	}

	// write VSA to file
	if err := os.WriteFile(vsaOutput, vsaBytes, 0644); err != nil {
		return fmt.Errorf("failed to write VSA to file: %w", err)
	}

	if !quiet {
		fmt.Printf("✓ VSA generated successfully: %s\n", vsaOutput)
		fmt.Printf("  SLSA Version: %s\n", generatedVSA.Predicate.SlsaVersion)
		fmt.Printf("  Verification Result: %s\n", generatedVSA.Predicate.VerificationResult)
		fmt.Printf("  Input Attestations: %d\n", len(generatedVSA.Predicate.InputAttestations))
		fmt.Printf("  Verified Levels: %v\n", generatedVSA.Predicate.VerifiedLevels)
		if policyResult != nil {
			fmt.Printf("  Policy Evaluation: %s\n", policyResult.Result)
		}
		fmt.Println()
	}

	return nil
}

// handles the download command execution
func runDownload(cmd *cobra.Command, args []string) error {
	// get config values directly from the command flags
	artifactPath, _ := cmd.Flags().GetString(flagBlobPath)
	outputPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	repo, _ := cmd.Flags().GetString("repo")
	quiet, _ := cmd.Flags().GetBool("quiet")

	if artifactPath == "" && len(args) == 0 {
		return fmt.Errorf("%s is required or provide artifact digest as argument", flagBlobPath)
	}

	if outputPath == "" {
		return fmt.Errorf("output path is required")
	}

	if repo == "" {
		return fmt.Errorf("repository is required (format: owner/repo)")
	}

	// attestation downloader with options
	downloadOpts := download.DownloadOptions{
		ArtifactPath: artifactPath,
		OutputPath:   outputPath,
		OutputFormat: format,
		Repository:   repo,
		GitHubToken:  ghclient.GetToken(),
	}

	// if argument provided, use it as digest
	if len(args) > 0 {
		downloadOpts.ArtifactDigest = args[0]
	}

	if !quiet {
		if downloadOpts.ArtifactDigest != "" {
			fmt.Printf("Downloading attestations for digest: %s\n", downloadOpts.ArtifactDigest)
		} else {
			fmt.Printf("Downloading attestations for artifact: %s\n", artifactPath)
		}
	}

	downloader, err := download.NewAttestationDownloader(downloadOpts)
	if err != nil {
		return fmt.Errorf("failed to create downloader: %w", err)
	}

	// downloads attestations
	if err := downloader.Download(context.Background()); err != nil {
		return fmt.Errorf("failed to download attestations: %w", err)
	}

	if !quiet {
		fmt.Printf("✓ Attestations saved to: %s\n", outputPath)
	}

	return nil
}

// handles the offline command execution
func runOffline(cmd *cobra.Command, args []string) error {
	// gets config values
	artifactPath := viper.GetString(flagBlobPath)
	artifactDigest := viper.GetString("artifact-digest")
	attestationsPath := viper.GetString("attestations")
	trustedRootPath := viper.GetString("trusted-root")
	certIdentity := viper.GetString("cert-identity")
	certIssuer := viper.GetString("cert-issuer")
	quiet := viper.GetBool("quiet")

	if attestationsPath == "" {
		return fmt.Errorf("attestations is required")
	}

	// verification options
	verifyOpts := offline.VerifyOptions{
		CertIdentity:   certIdentity,
		CertOIDCIssuer: certIssuer,
		SkipTLogVerify: true, // skip tlog verification in offline mode
	}

	if !quiet {
		if artifactPath != "" {
			fmt.Printf("Verifying artifact: %s\n", artifactPath)
		} else if artifactDigest != "" {
			fmt.Printf("Verifying artifact digest: %s\n", artifactDigest)
		} else {
			fmt.Println("No artifact provided - verifying attestations only")
		}
		fmt.Printf("Using attestations from: %s\n", attestationsPath)
		fmt.Println("Performing offline verification...")
		fmt.Println()
	}

	// creates offline verifier
	verifier, err := offline.NewOfflineVerifier(trustedRootPath, verifyOpts)
	if err != nil {
		return fmt.Errorf("failed to create offline verifier: %w", err)
	}

	// loads attestation bundles
	if err := verifier.LoadBundlesFromFile(attestationsPath); err != nil {
		return fmt.Errorf("failed to load attestation bundles: %w", err)
	}

	if !quiet {
		fmt.Println("Loaded attestation bundles successfully")
	}

	// verifies artifact - pass either path or digest
	var result *offline.VerificationResult
	if artifactPath != "" {
		result, err = verifier.VerifyArtifact(artifactPath)
	} else if artifactDigest != "" {
		result, err = verifier.VerifyArtifactDigest(artifactDigest)
	} else {
		result, err = verifier.VerifyArtifact("")
	}
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// outputs results
	if result.Verified {
		if !quiet {
			fmt.Println("✓ VERIFICATION SUCCESSFUL")
			fmt.Printf("Verified %d attestations\n", len(result.Attestations))
		} else {
			fmt.Println("VERIFICATION_SUCCESSFUL")
		}
	} else {
		if !quiet {
			fmt.Println("✗ VERIFICATION FAILED")
			for _, attestation := range result.Attestations {
				if !attestation.Verified {
					fmt.Printf("  - %s: %s\n", attestation.Type, attestation.Error)
				}
			}
		} else {
			fmt.Println("VERIFICATION_FAILED")
		}
		return fmt.Errorf("offline verification failed")
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

// computes SHA256 hash of policy bundle content
func calculatePolicyDigest(policyPath string) (string, error) {
	// check if it's a directory or file
	info, err := os.Stat(policyPath)
	if err != nil {
		// if path doesn't exist locally, it might be a URL - download and hash content
		if strings.HasPrefix(policyPath, "http") {
			return calculateRemotePolicyDigest(policyPath)
		}
		return "", fmt.Errorf("policy path not found: %w", err)
	}

	h := sha256.New()

	if info.IsDir() {
		// hash directory contents recursively
		err := filepath.Walk(policyPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// skip directories, only hash files
			if info.IsDir() {
				return nil
			}

			// only include .rego files and metadata
			if strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer func() {
					if closeErr := file.Close(); closeErr != nil {
						fmt.Printf("Warning: failed to close file %s: %v\n", path, closeErr)
					}
				}()

				// include relative path in hash for uniqueness
				relPath, _ := filepath.Rel(policyPath, path)
				h.Write([]byte(relPath))

				_, err = io.Copy(h, file)
				return err
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("failed to hash policy directory: %w", err)
		}
	} else {
		// single file - hash its contents
		file, err := os.Open(policyPath)
		if err != nil {
			return "", fmt.Errorf("failed to open policy file: %w", err)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				fmt.Printf("Warning: failed to close policy file: %v\n", closeErr)
			}
		}()

		_, err = io.Copy(h, file)
		if err != nil {
			return "", fmt.Errorf("failed to read policy file: %w", err)
		}
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// downloads policy content from URL and hashes it
func calculateRemotePolicyDigest(url string) (string, error) {
	// create HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download policy from %s: %w", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download policy: HTTP %d", resp.StatusCode)
	}

	// hash the response body (actual policy content)
	h := sha256.New()
	_, err = io.Copy(h, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read policy content: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
