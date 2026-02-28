package verify

import (
	"encoding/json"
	"fmt"

	"github.com/liatrio/autogov/pkg/gitpolicy"
	"github.com/spf13/cobra"
)

const (
	flagRef        = "ref"
	flagPolicyPath = "policy-path"
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
	cmd.Flags().Int("max-commits", 50, "Maximum number of commits to walk for verification")

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
	maxCommits, _ := cmd.Flags().GetInt("max-commits")

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
		return outputPolicyJSON(cmd, result)
	case "text", "":
		return outputPolicyText(cmd, result, quiet)
	default:
		return fmt.Errorf("unsupported format %q: use text or json", format)
	}
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

	if !result.Verified && result.ErrorMsg != "" {
		return fmt.Errorf("verify policy: %s", result.ErrorMsg)
	}

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
