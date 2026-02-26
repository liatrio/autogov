package release

import (
	"fmt"
	"os"

	ghpkg "github.com/liatrio/autogov-verify/pkg/github"
	"github.com/liatrio/autogov-verify/pkg/release"
	"github.com/spf13/cobra"
)

var cutCmd = &cobra.Command{
	Use:   "cut",
	Short: "Execute a release (apply mutations, commit, tag, push, create draft release)",
	Long: `Execute a release by applying file mutations, creating a conventional commit,
tagging, pushing, and creating a draft GitHub release.

The command enforces immutability: it fails if the computed tag already exists
or if a published (non-draft) release exists for that tag.

Examples:
  # Cut a release (auto-determines version from commits)
  autogov release cut

  # Cut using a pre-generated plan file
  autogov release cut --plan-file release-plan.json

  # Dry-run to preview what would happen
  autogov release cut --dry-run

  # Cut with file mutations
  autogov release cut --mutations-config .autogov-release.yaml

  # Cut from a specific branch
  autogov release cut --branch main --remote origin`,
	RunE: runCut,
}

func init() {
	cutCmd.Flags().String("plan-file", "", "Path to pre-generated release plan (JSON/YAML)")
	cutCmd.Flags().String("branch", "main", "Expected branch to cut release from")
	cutCmd.Flags().String("remote", "origin", "Git remote to push to")
	cutCmd.Flags().String("mutations-config", "", "Path to mutations config file")
	cutCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	cutCmd.Flags().Bool("publish", false, "Publish release directly (skip draft state)")
	cutCmd.Flags().String("mode", "auto", "Git read mode: auto (default), api (require GitHub API), local (go-git only)")
	cutCmd.Flags().String("repo", ".", "Path to git repository")
	cutCmd.Flags().String("commit-author", "autogov[bot]", "Author name for release commit")
	cutCmd.Flags().String("commit-email", "autogov[bot]@users.noreply.github.com", "Author email for release commit")
	cutCmd.Flags().StringP("output", "o", "text", "Output format: text, json")
}

func runCut(cmd *cobra.Command, args []string) error {
	planFile, _ := cmd.Flags().GetString("plan-file")
	branch, _ := cmd.Flags().GetString("branch")
	remote, _ := cmd.Flags().GetString("remote")
	mutationsConfig, _ := cmd.Flags().GetString("mutations-config")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	publish, _ := cmd.Flags().GetBool("publish")
	modeStr, _ := cmd.Flags().GetString("mode")
	repoPath, _ := cmd.Flags().GetString("repo")
	commitAuthor, _ := cmd.Flags().GetString("commit-author")
	commitEmail, _ := cmd.Flags().GetString("commit-email")
	outputFormat, _ := cmd.Flags().GetString("output")

	token := ghpkg.GetToken()

	opts := &release.CutOptions{
		RepoPath:        repoPath,
		Branch:          branch,
		Remote:          remote,
		PlanFile:        planFile,
		MutationsConfig: mutationsConfig,
		DryRun:          dryRun,
		Publish:         publish,
		Mode:            release.ReleaseMode(modeStr),
		CommitAuthor:    commitAuthor,
		CommitEmail:     commitEmail,
		Token:           token,
	}

	result, err := release.ExecuteCut(opts)
	if err != nil {
		return fmt.Errorf("release cut failed: %w", err)
	}

	if result.NoRelease {
		switch outputFormat {
		case "json":
			data, err := result.ToJSON()
			if err != nil {
				return fmt.Errorf("failed to serialize result: %w", err)
			}
			_, _ = fmt.Fprintln(os.Stdout, string(data))
		default:
			_, _ = fmt.Fprintf(cmd.OutOrStderr(), "No release needed: %s\n", result.Reason)
		}
		return nil
	}

	switch outputFormat {
	case "json":
		data, err := result.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize result: %w", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(data))
	default:
		action := "draft"
		if result.Published {
			action = "published"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Release %s created successfully (%s)\n", result.TagName, action)
		if result.CommitSHA != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Commit: %s\n", result.CommitSHA)
		}
		if result.ReleaseURL != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Release: %s\n", result.ReleaseURL)
		}
		if len(result.FilesModified) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Files modified: %d\n", len(result.FilesModified))
			for _, f := range result.FilesModified {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    - %s\n", f)
			}
		}
		if result.DryRun {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  (dry-run: no changes were made)")
		}
	}

	return nil
}
