package release

import (
	"fmt"
	"os"

	"github.com/liatrio/autogov-verify/pkg/release"
	"github.com/spf13/cobra"
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Preview what would be included in a release",
	Long: `Preview the changes that would be included in the next release.

This command analyzes commits since the last release and generates
a preview of the changelog, version bump, and release notes.

Examples:
  # Preview the next release
  autogov release plan

  # Preview with a specific base ref
  autogov release plan --from v1.1.0

  # Preview in JSON format
  autogov release plan --output json

  # Only follow first parent commits (for merge-based workflows)
  autogov release plan --first-parent`,
	RunE: runPlan,
}

func init() {
	planCmd.Flags().String("from", "", "Base ref to compare from (default: latest tag)")
	planCmd.Flags().String("to", "HEAD", "Target ref to compare to")
	planCmd.Flags().Bool("first-parent", false, "Only follow first parent commits in merge history")
	planCmd.Flags().StringP("output", "o", "text", "Output format: text, json, yaml")
	planCmd.Flags().String("repo", ".", "Path to git repository")
	planCmd.Flags().String("mutations-config", "", "Path to mutations config file for file update preview")
}

// valid output formats
var validOutputFormats = map[string]bool{
	"text": true,
	"json": true,
	"yaml": true,
}

func runPlan(cmd *cobra.Command, args []string) error {
	fromRef, _ := cmd.Flags().GetString("from")
	toRef, _ := cmd.Flags().GetString("to")
	firstParent, _ := cmd.Flags().GetBool("first-parent")
	outputFormat, _ := cmd.Flags().GetString("output")
	repoPath, _ := cmd.Flags().GetString("repo")
	mutationsConfig, _ := cmd.Flags().GetString("mutations-config")

	// validate output format
	if !validOutputFormats[outputFormat] {
		return fmt.Errorf("invalid output format %q: must be one of text, json, yaml", outputFormat)
	}

	opts := &release.PlanOptions{
		FromRef:         fromRef,
		ToRef:           toRef,
		FirstParent:     firstParent,
		RepoPath:        repoPath,
		OutputFormat:    outputFormat,
		MutationsConfig: mutationsConfig,
	}

	plan, err := release.GeneratePlan(opts)
	if err != nil {
		return fmt.Errorf("failed to generate release plan: %w", err)
	}

	// output based on format
	switch outputFormat {
	case "json":
		data, err := plan.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to convert plan to JSON: %w", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(data))
	case "yaml":
		data, err := plan.ToYAML()
		if err != nil {
			return fmt.Errorf("failed to convert plan to YAML: %w", err)
		}
		_, _ = fmt.Fprint(os.Stdout, string(data))
	default:
		_, _ = fmt.Fprint(os.Stdout, plan.ToText())
	}

	return nil
}
