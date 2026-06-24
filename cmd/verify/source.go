package verify

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/liatrio/autogov/pkg/source"
	"github.com/liatrio/autogov/pkg/vsa"
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
	cmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	cmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	cmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")

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
		if err := outputSourceJSON(cmd, result); err != nil {
			return err
		}
	case "text", "":
		if err := outputSourceText(cmd, result, quiet); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported format %q: use text or json", format)
	}

	// VSA generation.
	generateVSA, _ := cmd.Flags().GetBool(flagGenerateVSA)
	if generateVSA && result.Verified {
		vsaOutput, _ := cmd.Flags().GetString(flagVSAOutput)
		policyURI, _ := cmd.Flags().GetString(flagPolicyURI)

		if vsaOutput == "" {
			return fmt.Errorf("VSA output path is required when --generate-vsa is used")
		}
		if policyURI == "" {
			return fmt.Errorf("policy URI is required when --generate-vsa is used")
		}

		if err := generateSourceVSA(result, vsaOutput, policyURI); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}

		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  VSA saved to: %s\n", vsaOutput)
		}
	}

	return nil
}

// generateSourceVSA creates a Verification Summary Attestation for source provenance.
func generateSourceVSA(result *source.VerificationResult, vsaOutput, policyURI string) error {
	artifactRef := result.RepoURI
	if result.Commit != "" {
		artifactRef = fmt.Sprintf("%s@%s", result.RepoURI, result.Commit)
	}

	h := sha256.New()
	h.Write([]byte(artifactRef))
	digest := fmt.Sprintf("%x", h.Sum(nil))

	subjects := []vsa.VSASubject{
		{
			URI: artifactRef,
			Digest: map[string]string{
				"sha256": digest,
			},
		},
	}

	verificationResults := map[string]bool{
		"source.provenance": result.Verified,
		"source.signature":  result.Verified,
	}
	if result.SLSASourceLevel != "" {
		verificationResults["source.slsa_level"] = true
	}

	vsaOpts := vsa.VSAOptions{
		AdditionalVerifiers: map[string]string{
			"autogov": version,
		},
	}

	generatedVSA, err := vsa.GenerateVSAWithSubjects(artifactRef, subjects, policyURI, verificationResults, vsaOpts)
	if err != nil {
		return err
	}

	if generatedVSA.Metadata == nil {
		generatedVSA.Metadata = make(map[string]interface{})
	}
	generatedVSA.Metadata["autogov.source.verification"] = map[string]interface{}{
		"repo_uri":          result.RepoURI,
		"commit":            result.Commit,
		"source_ref":        result.SourceRef,
		"slsa_source_level": result.SLSASourceLevel,
		"builder_id":        result.BuilderID,
	}

	return vsa.WriteToFile(generatedVSA, vsaOutput)
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
