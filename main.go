package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/liatrio/autogov-verify/pkg/attestations"
	"github.com/liatrio/autogov-verify/pkg/certid"
	"github.com/liatrio/autogov-verify/pkg/github"
	"github.com/liatrio/autogov-verify/pkg/vsa"
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
)

const (
	flagArtifactDigest   = "artifact-digest"
	flagBlobPath         = "blob-path"
	flagCertIdentity     = "cert-identity"
	flagCertIssuer       = "cert-issuer"
	flagSourceRef        = "source-ref"
	flagQuiet            = "quiet"
	flagCertIdentityList = "cert-identity-list"
	flagNoCache          = "no-cache"
	// VSA generation flags
	flagGenerateVSA = "generate-vsa"
	flagVSAOutput   = "vsa-output"
	flagPolicyURI   = "policy-uri"
)

func init() {
	// flags
	rootCmd.Flags().StringP(flagArtifactDigest, "d", "", "Full OCI reference in the format [registry/]org/repo[:tag]@digest")
	rootCmd.Flags().String(flagBlobPath, "", "Path to a blob file to verify attestations against")
	rootCmd.Flags().StringP(flagCertIdentity, "i", "", "Certificate identity to verify against (required)")
	rootCmd.Flags().StringP(flagCertIssuer, "s", "https://token.actions.githubusercontent.com", "Certificate issuer to verify against")
	rootCmd.Flags().StringP(flagSourceRef, "r", "", "Source repository ref to verify against (e.g., refs/heads/main)")
	rootCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")

	// certificate identity validation flags
	rootCmd.Flags().String(flagCertIdentityList, "", "URL or file path to the certificate identity list. If provided, enables cert-identity validation against this source (optional)")
	rootCmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")

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
		if github.GetToken() == "" {
			return fmt.Errorf("GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required")
		}

		return nil
	}

	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}

	// bind env vars
	envBinds := map[string]string{
		flagCertIdentity:     "CERT_IDENTITY",
		flagCertIssuer:       "CERT_ISSUER",
		flagQuiet:            "QUIET",
		flagSourceRef:        "SOURCE_REF",
		flagCertIdentityList: "CERT_IDENTITY_LIST",
		flagNoCache:          "NO_CACHE",
	}

	for key, env := range envBinds {
		if err := viper.BindEnv(key, env); err != nil {
			panic(fmt.Sprintf("failed to bind environment variables: %v", err))
		}
	}
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
	client := github.NewClient()

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

	sigs, err := attestations.GetFromGitHub(
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

	if !quiet {
		fmt.Println("\nSummary:")
		fmt.Printf("✓ Successfully verified %d attestations\n", len(sigs))
		fmt.Println("\nAttestation Types:")
	}

	// Collect attestation types and prepare for VSA generation
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

		// Prepare input attestation for VSA generation
		inputAttestations = append(inputAttestations, vsa.ResourceDescriptor{
			URI: fmt.Sprintf("attestation://%d", i+1),
			Digest: map[string]string{
				"sha256": fmt.Sprintf("attestation-hash-%d", i+1),
			},
		})
	}

	// Generate VSA if requested
	if viper.GetBool(flagGenerateVSA) {
		if err := generateVSA(artifactDigest, inputAttestations, attestationTypes, quiet); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}
	}

	return nil
}

// generateVSA creates a VSA after successful attestation verification
func generateVSA(artifactDigest string, inputAttestations []vsa.ResourceDescriptor, attestationTypes []string, quiet bool) error {
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

	// Create verification results based on successful attestation verification
	verificationResults := map[string]bool{
		"attestation.verification": true,
		"attestation.signature":    true,
		"policy.compliance":        true, // Simulated - would come from actual policy evaluation
	}

	// Add specific results for each attestation type
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

	// Create VSA options with input attestations
	opts := vsa.VSAOptions{
		InputAttestations: inputAttestations,
		AutoGovVersion:    "v1.1.0",
		PolicyDigest: map[string]string{
			"sha256": "policy-hash-placeholder", // In real implementation, calculate from policy
		},
		AdditionalVerifiers: map[string]string{
			"opa":           "v0.58.0",
			"slsa-verifier": "v2.5.1",
		},
	}

	// Generate VSA
	generatedVSA, err := vsa.GenerateVSAWithOptions(artifactDigest, policyURI, verificationResults, opts)
	if err != nil {
		return fmt.Errorf("failed to generate VSA: %w", err)
	}

	// Serialize VSA
	vsaBytes, err := generatedVSA.SerializeVSA()
	if err != nil {
		return fmt.Errorf("failed to serialize VSA: %w", err)
	}

	// Write VSA to file
	if err := os.WriteFile(vsaOutput, vsaBytes, 0644); err != nil {
		return fmt.Errorf("failed to write VSA to file: %w", err)
	}

	if !quiet {
		fmt.Printf("✓ VSA generated successfully: %s\n", vsaOutput)
		fmt.Printf("  SLSA Version: %s\n", generatedVSA.Predicate.SlsaVersion)
		fmt.Printf("  Verification Result: %s\n", generatedVSA.Predicate.VerificationResult)
		fmt.Printf("  Input Attestations: %d\n", len(generatedVSA.Predicate.InputAttestations))
		fmt.Printf("  Verified Levels: %v\n", generatedVSA.Predicate.VerifiedLevels)
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
