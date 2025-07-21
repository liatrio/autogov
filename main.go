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
	rootCmd.Flags().String(flagCertIdentityList, "", "URL to the certificate identity list. If provided, enables cert-identity validation against this source (optional)")
	rootCmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")

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

		fmt.Printf("%d. %s\n", i+1, statement.PredicateType)
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
