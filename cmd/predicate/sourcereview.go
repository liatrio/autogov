package predicate

import (
	"fmt"
	"strings"

	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/spf13/cobra"
)

var sourceReviewCmd = &cobra.Command{
	Use:   "source-review",
	Short: "Generate source-review attestation predicate from GitHub PR review evidence",
	Long: `Generate an autogov source-review attestation predicate recording the human
PR-review/approval evidence for the source revision that produced an artifact —
which pull request merged it, who approved, how many distinct approvals, whether
self-approval was excluded, and whether any outstanding changes were requested.

This is the change-management/two-person-review evidence SLSA's source track
wants. Pass --commit-sha for the merge/squash commit that landed on the target
branch; the pull request is auto-discovered from it (or pinned with --pr-number).
Counts are always computed at the strictest filtering (author, stale, dismissed,
changes-requested, and bot reviewers excluded). Approver identities are embedded
by default — pass --include-approvers=false to emit summary counts only.

A GitHub token is read from --token / GITHUB_TOKEN / GH_TOKEN / GITHUB_AUTH_TOKEN
(needs pull-requests:read + contents:read; +Administration:read for thresholds).`,
	RunE: runSourceReview,
}

var (
	sourceReviewRepo            string
	sourceReviewCommitSHA       string
	sourceReviewRef             string
	sourceReviewPRNumber        int
	sourceReviewSubjectName     string
	sourceReviewSubjectPath     string
	sourceReviewSubjectDigest   string
	sourceReviewOutput          string
	sourceReviewType            string
	sourceReviewIncludeApprover bool
	sourceReviewConfigURI       string
)

func init() {
	flags := sourceReviewCmd.Flags()
	flags.StringVar(&sourceReviewRepo, "repo", "", "Repository in owner/repo form (required)")
	flags.StringVar(&sourceReviewCommitSHA, "commit-sha", "", "Source revision: the merge/squash commit that landed on the target branch (required)")
	flags.StringVar(&sourceReviewRef, "ref", "", "Optional target branch ref of the artifact build (e.g. main or refs/heads/main)")
	flags.IntVar(&sourceReviewPRNumber, "pr-number", 0, "Optional pull request number to disambiguate; the PR must still be the one whose merge produced --commit-sha (never an override)")
	flags.StringVar(&sourceReviewSubjectName, "subject-name", "", "Name of the subject being attested (required for image type)")
	flags.StringVar(&sourceReviewSubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&sourceReviewSubjectDigest, "subject-digest", "", "Digest of the subject (required for image type, auto-calculated for blobs)")
	flags.StringVar(&sourceReviewOutput, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&sourceReviewType, "type", "image", "Type of artifact (image or blob)")
	flags.BoolVar(&sourceReviewIncludeApprover, "include-approvers", true, "Embed the per-approver list (logins, associations); summary counts are emitted regardless")
	flags.StringVar(&sourceReviewConfigURI, "config-uri", "", "Optional URI of the workflow/config (populates the 'configuration' field)")
	cobra.CheckErr(sourceReviewCmd.MarkFlagRequired("repo"))
	cobra.CheckErr(sourceReviewCmd.MarkFlagRequired("commit-sha"))
}

func runSourceReview(_ *cobra.Command, _ []string) error {
	owner, repo, err := splitOwnerRepo(sourceReviewRepo)
	if err != nil {
		return err
	}

	opts := pred.SourceReviewOptions{
		Owner:            owner,
		Repo:             repo,
		CommitSHA:        sourceReviewCommitSHA,
		Ref:              sourceReviewRef,
		PRNumber:         sourceReviewPRNumber,
		SubjectName:      sourceReviewSubjectName,
		SubjectPath:      sourceReviewSubjectPath,
		Digest:           sourceReviewSubjectDigest,
		IncludeApprovers: sourceReviewIncludeApprover,
		ConfigURI:        sourceReviewConfigURI,
	}

	switch sourceReviewType {
	case "image":
		opts.Type = pred.ArtifactTypeContainerImage
		if opts.SubjectName == "" {
			return fmt.Errorf("--subject-name is required for image type")
		}
		if opts.Digest == "" {
			return fmt.Errorf("--subject-digest is required for image type")
		}
	case "blob":
		opts.Type = pred.ArtifactTypeBlob
		if opts.SubjectPath == "" {
			return fmt.Errorf("--subject-path is required for blob type")
		}
		// calculate digest for blob if not provided
		if opts.Digest == "" {
			digest, err := pred.CalculateDigest(opts.SubjectPath)
			if err != nil {
				return fmt.Errorf("failed to calculate digest: %w", err)
			}
			opts.Digest = digest
		}
	default:
		return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", sourceReviewType)
	}

	return pred.GenerateSourceReview(opts, sourceReviewOutput)
}

// splitOwnerRepo parses an "owner/repo" string into its parts.
func splitOwnerRepo(s string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid --repo %q, must be in owner/repo form", s)
	}
	return parts[0], parts[1], nil
}
