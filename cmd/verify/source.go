package verify

import (
	"encoding/json"
	"fmt"

	"github.com/liatrio/autogov/pkg/source"
	"github.com/spf13/cobra"
)

const (
	flagAttestationPath = "attestation-path"
)

// newSourceCmd creates the verify source subcommand.
func newSourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "source",
		Short: "Verify source provenance attestations",
		Long: `Verify source provenance attestations using Sigstore.

This command verifies that source provenance attestations match expected
repository URI and commit SHA, and reports SLSA Source Track levels.

Examples:
  # Verify source provenance
  autogov verify source --attestation-path bundle.json --repo-uri https://github.com/org/repo --commit abc123

  # Verify with expected source ref
  autogov verify source --attestation-path bundle.json --repo-uri https://github.com/org/repo --commit abc123 --source-ref refs/heads/main

  # JSON output
  autogov verify source --attestation-path bundle.json --repo-uri https://github.com/org/repo --commit abc123 --format json`,
		PreRunE: preRunSource,
		RunE:    runSource,
	}

	cmd.Flags().String(flagAttestationPath, "", "Path to Sigstore bundle file containing source provenance attestation (required)")
	cmd.Flags().String("repo-uri", "", "Expected source repository URI (required)")
	cmd.Flags().String("commit", "", "Expected source commit SHA (required)")
	cmd.Flags().String(flagSourceRef, "", "Expected source ref (e.g., refs/heads/main)")
	cmd.Flags().StringP(flagCertIdentity, "i", "", "Expected OIDC subject in certificate SAN")
	cmd.Flags().StringP(flagCertIssuer, "s", "", "Expected OIDC issuer URL")
	cmd.Flags().String(flagFormat, "text", "Output format: text, json")
	cmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final status")

	return cmd
}

func preRunSource(cmd *cobra.Command, _ []string) error {
	attestationPath, _ := cmd.Flags().GetString(flagAttestationPath)
	repoURI, _ := cmd.Flags().GetString("repo-uri")
	commit, _ := cmd.Flags().GetString("commit")

	if attestationPath == "" {
		return fmt.Errorf("--%s is required", flagAttestationPath)
	}
	if repoURI == "" {
		return fmt.Errorf("--repo-uri is required")
	}
	if commit == "" {
		return fmt.Errorf("--commit is required")
	}
	return nil
}

func runSource(cmd *cobra.Command, _ []string) error {
	attestationPath, _ := cmd.Flags().GetString(flagAttestationPath)
	repoURI, _ := cmd.Flags().GetString("repo-uri")
	commit, _ := cmd.Flags().GetString("commit")
	sourceRef, _ := cmd.Flags().GetString(flagSourceRef)
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	certIssuer, _ := cmd.Flags().GetString(flagCertIssuer)
	format, _ := cmd.Flags().GetString(flagFormat)
	quiet, _ := cmd.Flags().GetBool(flagQuiet)

	opts := source.VerifyOptions{
		RepoURI:      repoURI,
		Commit:       commit,
		SourceRef:    sourceRef,
		CertIdentity: certIdentity,
		CertIssuer:   certIssuer,
	}

	result, err := source.VerifySourceProvenance(attestationPath, opts)
	if err != nil {
		return err
	}

	switch format {
	case "json":
		return outputSourceJSON(cmd, result)
	case "text", "":
		return outputSourceText(cmd, result, quiet)
	default:
		return fmt.Errorf("unsupported format %q: use text or json", format)
	}
}

func outputSourceJSON(cmd *cobra.Command, result *source.VerificationResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("verify source: encode JSON: %w", err)
	}
	return nil
}

func outputSourceText(cmd *cobra.Command, result *source.VerificationResult, quiet bool) error {
	if quiet && result.Verified {
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Source Provenance Verification:\n")
	if result.RepoURI != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Repository: %s\n", result.RepoURI)
	}
	if result.Commit != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Commit:     %s\n", result.Commit)
	}
	if result.SourceRef != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Source Ref: %s\n", result.SourceRef)
	}
	if result.BuilderID != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Builder:    %s\n", result.BuilderID)
	}
	if result.SLSASourceLevel != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  SLSA Level: %s\n", result.SLSASourceLevel)
	}

	if result.Verified {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Status:     Verified\n")
	} else if result.ErrorMsg != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Status:     Failed (%s)\n", result.ErrorMsg)
	}

	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Warning:    %s\n", w)
	}

	if !result.Verified && result.ErrorMsg != "" {
		return fmt.Errorf("verify source: %s", result.ErrorMsg)
	}

	return nil
}
