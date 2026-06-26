package verify

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/liatrio/autogov/pkg/gitpolicy"
	"github.com/liatrio/autogov/pkg/vsa"
	"github.com/spf13/cobra"
)

const (
	flagRef        = "ref"
	flagPolicyPath = "policy-path"
	flagMaxCommits = "max-commits"
)

// newPolicyCmd creates the verify policy subcommand.
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Verify repository policy enforcement",
		Long: `Verify gittuf-style repository policies including branch protection
and required signer enforcement.

This command checks the commit history for evidence that repository policies
(branch protection, required signatures) were enforced.

Examples:
  # Verify policy for main branch
  autogov verify policy --ref refs/heads/main

  # Verify with explicit policy file
  autogov verify policy --ref refs/heads/main --policy-path .gittuf/targets.json

  # Verify a local repo with JSON output
  autogov verify policy --repo-path ./my-repo --ref refs/heads/main --format json`,
		PreRunE: preRunPolicy,
		RunE:    runPolicy,
	}

	cmd.Flags().String(flagRepoPath, ".", "Path to git repository")
	cmd.Flags().String(flagRef, "", "Target ref to verify policy for (e.g., refs/heads/main) (required)")
	cmd.Flags().String(flagPolicyPath, "", "Path to gittuf policy file or directory (auto-discovers from repo if not set)")
	cmd.Flags().StringP(flagCertIdentity, "i", "", "Expected signer identity for commit signatures")
	cmd.Flags().StringP(flagCertIssuer, "s", "", "Expected OIDC issuer for commit signatures")
	cmd.Flags().String(flagFormat, "text", "Output format: text, json")
	cmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final status")
	cmd.Flags().Int(flagMaxCommits, 50, "Maximum number of commits to walk for verification")
	cmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	cmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	cmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")

	return cmd
}

func preRunPolicy(cmd *cobra.Command, _ []string) error {
	ref, _ := cmd.Flags().GetString(flagRef)
	if ref == "" {
		return fmt.Errorf("--%s is required", flagRef)
	}
	return nil
}

func runPolicy(cmd *cobra.Command, _ []string) error {
	repoPath, _ := cmd.Flags().GetString(flagRepoPath)
	ref, _ := cmd.Flags().GetString(flagRef)
	policyPath, _ := cmd.Flags().GetString(flagPolicyPath)
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	certIssuer, _ := cmd.Flags().GetString(flagCertIssuer)
	format, _ := cmd.Flags().GetString(flagFormat)
	quiet, _ := cmd.Flags().GetBool(flagQuiet)
	maxCommits, _ := cmd.Flags().GetInt(flagMaxCommits)

	opts := gitpolicy.VerifyOptions{
		RepoPath:     repoPath,
		TargetRef:    ref,
		PolicyPath:   policyPath,
		CertIdentity: certIdentity,
		CertIssuer:   certIssuer,
		MaxCommits:   maxCommits,
	}

	result, err := gitpolicy.VerifyPolicy(opts)
	if err != nil {
		return err
	}

	switch format {
	case "json":
		if err := outputPolicyJSON(cmd, result); err != nil {
			return err
		}
	case "text", "":
		if err := outputPolicyText(cmd, result, quiet); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported format %q: use text or json", format)
	}

	// fail closed regardless of format: the not-verified decision lives here (after
	// output is written), not in a formatter, so --format json exits nonzero on a
	// failed verification. keys on the same !Verified && ErrorMsg != "" condition
	// the text path used, so a "Partially Verified" result (empty ErrorMsg) is
	// unchanged.
	if !result.Verified && result.ErrorMsg != "" {
		return fmt.Errorf("verify policy: %s", result.ErrorMsg)
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

		if err := generatePolicyVSA(result, repoPath, vsaOutput, policyURI); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}

		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "VSA saved to: %s\n", vsaOutput)
		}
	}

	return nil
}

// generatePolicyVSA creates a Verification Summary Attestation for policy verification.
func generatePolicyVSA(result *gitpolicy.VerificationResult, repoPath, vsaOutput, policyURI string) error {
	artifactRef := fmt.Sprintf("%s@%s", repoPath, result.Ref)

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
		"policy.verification": result.Verified,
	}
	if result.BranchProtection != nil {
		verificationResults["policy.branch_protection"] = result.BranchProtection.Verified
	}
	if result.SignerPolicy != nil {
		verificationResults["policy.signer_policy"] = result.SignerPolicy.AllSigned
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

	policyMeta := map[string]interface{}{
		"ref":      result.Ref,
		"verified": result.Verified,
	}
	if result.BranchProtection != nil {
		policyMeta["branch_protection"] = result.BranchProtection
	}
	if result.SignerPolicy != nil {
		policyMeta["signer_policy"] = result.SignerPolicy
	}
	generatedVSA.Metadata["autogov.policy.verification"] = policyMeta

	return vsa.WriteToFile(generatedVSA, vsaOutput)
}

func outputPolicyJSON(cmd *cobra.Command, result *gitpolicy.VerificationResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("verify policy: encode JSON: %w", err)
	}
	return nil
}

func outputPolicyText(cmd *cobra.Command, result *gitpolicy.VerificationResult, quiet bool) error {
	if quiet && result.Verified {
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Policy Verification for %s:\n\n", result.Ref)

	// Branch protection.
	if bp := result.BranchProtection; bp != nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Branch Protection:\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Require PR:             %s\n", boolStatus(bp.RequirePR, bp.MergeCommitCount > 0))
		if bp.RequireReviews {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Require Reviews:        Yes (Min: %d) %s\n",
				bp.MinReviewers, verifiedTag(bp.MergeCommitCount > 0))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Require Signed Commits: %s\n",
			boolStatus(bp.RequireSignedCommits,
				bp.SignedCommitCount == bp.TotalCommitCount && bp.TotalCommitCount > 0))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Commits Examined:       %d (signed: %d, merge: %d)\n",
			bp.TotalCommitCount, bp.SignedCommitCount, bp.MergeCommitCount)
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	// Signer policy.
	if sp := result.SignerPolicy; sp != nil && len(sp.RequiredSigners) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Signer Policy:\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Required: %v\n", sp.RequiredSigners)
		if len(sp.VerifiedSigners) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Verified: %v\n", sp.VerifiedSigners)
		}
		if len(sp.MissingSigners) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Missing:  %v\n", sp.MissingSigners)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	// Overall status.
	if result.Verified {
		passed, total := countRules(result)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status: Verified (%d/%d rules passed)\n", passed, total)
	} else if result.ErrorMsg != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status: Failed (%s)\n", result.ErrorMsg)
	} else {
		passed, total := countRules(result)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status: Partially Verified (%d/%d rules passed)\n", passed, total)
	}

	// Warnings.
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Warning: %s\n", w)
	}

	// write-only: the not-verified decision is made in runPolicy so it is
	// format-independent (json fails closed too).
	return nil
}

func boolStatus(required, verified bool) string {
	if !required {
		return "No"
	}
	return "Yes " + verifiedTag(verified)
}

func verifiedTag(verified bool) string {
	if verified {
		return "(Verified)"
	}
	return "(Not Verified)"
}

func countRules(result *gitpolicy.VerificationResult) (passed, total int) {
	total = len(result.PolicyRules)
	for _, r := range result.PolicyRules {
		if r.Enforced {
			passed++
		}
	}
	return
}
