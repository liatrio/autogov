package verify

import (
	"encoding/json"
	"fmt"

	"github.com/liatrio/autogov/pkg/gitsign"
	"github.com/spf13/cobra"
)

const (
	flagRepoPath      = "repo-path"
	flagFormat        = "format"
	flagFrom          = "from"
	flagTo            = "to"
	flagAllowUnsigned = "allow-unsigned"
)

// newGitCmd creates a fresh git subcommand. Used internally and for testing.
func newGitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git [revision]",
		Short: "Verify gitsign commit signatures",
		Long: `Verify gitsign commit signatures using Sigstore.

This command verifies that commits are signed with gitsign, that the signing
identity matches the expected certificate identity and issuer, and that the
signature is anchored to a trusted timestamp: the cert chain is validated at the
trusted time (never the attacker-supplied CMS signingTime, never wall-clock now).

Transparency anchoring is per Sigstore backend:
  - GitHub-internal signing (fulcio.githubapp.com): verified against the RFC3161
    timestamp token from timestamp.githubapp.com.
  - public-good signing (sigstore.dev): verified against the Rekor transparency-log
    inclusion entry gitsign embeds in the commit signature, checked offline against
    the embedded trusted-root log key and pinned to the Rekor integrated time.
Both paths are transparency-anchored; a signature whose trusted timestamp cannot
be established (no embedded entry, bad inclusion proof, or an entry not bound to
the commit signature) fails closed (Not Verified).

The revision argument specifies a single commit (hash, tag, or ref).
Use --from and --to for a range of commits.

Examples:
  # Verify the HEAD commit
  autogov verify git

  # Verify a specific commit
  autogov verify git abc1234

  # Verify a commit range
  autogov verify git --from v1.0.0 --to HEAD

  # Verify with expected identity
  autogov verify git --cert-identity user@example.com --cert-issuer https://accounts.google.com

Unsigned commits fail verification by default ("no signature" is the easiest
forgery). Pass --allow-unsigned to treat unsigned commits as success.`,
		RunE: runVerifyGit,
	}

	cmd.Flags().String(flagRepoPath, ".", "Path to git repository")
	cmd.Flags().StringP(flagCertIdentity, "i", "", "Expected OIDC subject in certificate SAN (email or URI)")
	cmd.Flags().StringP(flagCertIssuer, "s", "", "Expected OIDC issuer URL")
	cmd.Flags().String(flagFormat, "text", "Output format: text, json")
	cmd.Flags().String(flagFrom, "", "Starting commit/ref for range verification")
	cmd.Flags().String(flagTo, "HEAD", "Ending commit/ref for range verification")
	cmd.Flags().Bool(flagAllowUnsigned, false, "Treat unsigned commits as success instead of failure")

	return cmd
}

func runVerifyGit(cmd *cobra.Command, args []string) error {
	repoPath, _ := cmd.Flags().GetString(flagRepoPath)
	certIdentity, _ := cmd.Flags().GetString(flagCertIdentity)
	certIssuer, _ := cmd.Flags().GetString(flagCertIssuer)
	format, _ := cmd.Flags().GetString(flagFormat)
	from, _ := cmd.Flags().GetString(flagFrom)
	to, _ := cmd.Flags().GetString(flagTo)
	allowUnsigned, _ := cmd.Flags().GetBool(flagAllowUnsigned)

	repo, err := gitsign.OpenRepository(repoPath)
	if err != nil {
		return err
	}

	opts := gitsign.VerifyOptions{
		CertIdentity: certIdentity,
		CertIssuer:   certIssuer,
	}

	var results []*gitsign.VerificationResult

	if from != "" {
		// range verification
		results, err = gitsign.VerifyCommitRange(repo, from, to, opts)
		if err != nil {
			return err
		}
	} else {
		// single commit verification
		revision := "HEAD"
		if len(args) > 0 {
			revision = args[0]
		}

		result, err := gitsign.VerifyCommit(repo, revision, opts)
		if err != nil {
			return err
		}
		results = []*gitsign.VerificationResult{result}
	}

	// write output first, then make the format-independent failure decision: an
	// unsigned commit (the easiest forgery) fails by default unless --allow-unsigned
	// is set, and any commit with an explicit error always fails.
	if err := outputResults(cmd, results, format); err != nil {
		return err
	}
	for _, r := range results {
		if r.ErrorMsg != "" {
			return fmt.Errorf("verify git: one or more commits failed verification")
		}
		if r.Unsigned && !allowUnsigned {
			return fmt.Errorf("verify git: commit %s is unsigned", r.CommitHash)
		}
	}
	return nil
}

// outputResults writes results to cmd.OutOrStdout() in the requested format.
func outputResults(cmd *cobra.Command, results []*gitsign.VerificationResult, format string) error {
	switch format {
	case "json":
		return outputJSON(cmd, results)
	case "text", "":
		return outputText(cmd, results)
	default:
		return fmt.Errorf("unsupported format %q: use text or json", format)
	}
}

func outputJSON(cmd *cobra.Command, results []*gitsign.VerificationResult) error {
	var out interface{}
	if len(results) == 1 {
		out = results[0]
	} else {
		out = results
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("verify git: encode JSON: %w", err)
	}
	return nil
}

func outputText(cmd *cobra.Command, results []*gitsign.VerificationResult) error {
	for _, r := range results {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Commit:   %s\n", r.CommitHash)

		switch {
		case r.Unsigned:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status:   Unsigned\n")
		case r.ErrorMsg != "":
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status:   Failed (%s)\n", r.ErrorMsg)
		case r.Verified:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Signer:   %s\n", r.Signer)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Issuer:   %s\n", r.Issuer)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status:   Verified\n")
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	// summary for range verification
	if len(results) > 1 {
		total, verified, unsigned, failed := 0, 0, 0, 0
		for _, r := range results {
			total++
			switch {
			case r.Unsigned:
				unsigned++
			case r.Verified:
				verified++
			default:
				failed++
			}
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Summary: %d commits — %d verified, %d unsigned, %d failed\n",
			total, verified, unsigned, failed)
	}

	// write-only: the overall failure decision (unsigned / errored commits) is made
	// in runVerifyGit so it is format-independent (json fails closed too).
	return nil
}
