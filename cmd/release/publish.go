package release

import (
	"fmt"

	ghpkg "github.com/liatrio/autogov/pkg/github"
	"github.com/liatrio/autogov/pkg/release"
	"github.com/spf13/cobra"
)

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish a draft GitHub release (flip draft → published)",
	Long: `Publish a draft GitHub release by flipping the draft flag to false.

This command finds a draft release (by tag or latest) and publishes it.
It enforces immutability: once a release is published, it cannot be re-published.

Examples:
  # Publish a specific draft release by tag
  autogov release publish --tag v1.2.0

  # Publish the latest draft release
  autogov release publish --latest

  # Dry-run to preview what would happen
  autogov release publish --tag v1.2.0 --dry-run

  # JSON output for downstream tools
  autogov release publish --tag v1.2.0 -o json`,
	RunE: runPublish,
}

func init() {
	publishCmd.Flags().String("tag", "", "Specific tag to publish (requires user token; GitHub App tokens cannot discover drafts)")
	publishCmd.Flags().Bool("latest", false, "Publish latest draft release (requires user token; GitHub App tokens cannot discover drafts)")
	publishCmd.Flags().Int64("release-id", 0, "Publish by release ID — works with GitHub App tokens (octo-sts)")
	publishCmd.Flags().Bool("dry-run", false, "Show what would be done without publishing")
	publishCmd.Flags().String("repo", ".", "Path to git repository")
	publishCmd.Flags().StringP("output", "o", "text", "Output format: text, json")
}

func runPublish(cmd *cobra.Command, args []string) error {
	tag, _ := cmd.Flags().GetString("tag")
	latest, _ := cmd.Flags().GetBool("latest")
	releaseID, _ := cmd.Flags().GetInt64("release-id")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	repoPath, _ := cmd.Flags().GetString("repo")
	outputFormat, _ := cmd.Flags().GetString("output")

	token := ghpkg.GetToken()

	opts := &release.PublishOptions{
		RepoPath:  repoPath,
		Tag:       tag,
		Latest:    latest,
		ReleaseID: releaseID,
		Token:     token,
		DryRun:    dryRun,
	}

	result, err := release.ExecutePublish(opts)
	if err != nil {
		return fmt.Errorf("release publish failed: %w", err)
	}

	out := cmd.OutOrStdout()

	switch outputFormat {
	case "json":
		data, err := result.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize result: %w", err)
		}
		_, _ = fmt.Fprintln(out, string(data))
	default:
		if result.DryRun {
			_, _ = fmt.Fprintf(out, "dry-run: would publish release %s (ID: %d)\n", result.TagName, result.ReleaseID)
		} else {
			_, _ = fmt.Fprintf(out, "Release %s published successfully\n", result.TagName)
			if result.ReleaseURL != "" {
				_, _ = fmt.Fprintf(out, "  URL: %s\n", result.ReleaseURL)
			}
			_, _ = fmt.Fprintf(out, "  Release ID: %d\n", result.ReleaseID)
		}
	}

	return nil
}
