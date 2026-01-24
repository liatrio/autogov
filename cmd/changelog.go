package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var changelogCmd = &cobra.Command{
	Use:   "changelog",
	Short: "Generate changelog from conventional commits",
	Long: `Generate a changelog based on conventional commits.

This command analyzes git history and generates a changelog following
the Keep a Changelog format, organized by commit type (features, fixes, etc.).

Examples:
  # Generate changelog for all releases
  autogov changelog

  # Generate changelog since a specific tag
  autogov changelog --from v1.0.0

  # Output to a specific file
  autogov changelog --output CHANGELOG.md`,
	RunE: runChangelog,
}

func init() {
	changelogCmd.Flags().String("from", "", "Starting ref for changelog generation")
	changelogCmd.Flags().String("to", "HEAD", "Ending ref for changelog generation")
	changelogCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	changelogCmd.Flags().String("format", "markdown", "Output format: markdown, json")
}

func runChangelog(cmd *cobra.Command, args []string) error {
	fmt.Println("changelog: not yet implemented")
	fmt.Println("This command will generate a changelog from conventional commits.")
	return nil
}
