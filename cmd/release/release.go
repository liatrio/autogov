package release

import (
	"github.com/spf13/cobra"
)

// ReleaseCmd is the parent command for release operations
var ReleaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Release management commands",
	Long: `Commands for planning, cutting, and publishing releases.

The release command group provides tools for managing software releases
with attestation support:

  plan    - Preview what would be included in a release
  cut     - Execute a release (create tag, generate artifacts)
  publish - Publish a draft release

Examples:
  # Preview the next release
  autogov release plan

  # Create a new release
  autogov release cut --version v1.2.0

  # Publish a draft release
  autogov release publish --tag v1.2.0`,
}

func init() {
	ReleaseCmd.AddCommand(planCmd)
	ReleaseCmd.AddCommand(cutCmd)
	ReleaseCmd.AddCommand(publishCmd)
}
