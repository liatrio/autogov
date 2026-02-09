package release

import (
	"fmt"

	"github.com/spf13/cobra"
)

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish a draft release",
	Long: `Publish a previously created draft release.

This command publishes a draft release that was created with 'release cut --draft'.
It performs final validation and makes the release publicly available.

Examples:
  # Publish a specific release
  autogov release publish --tag v1.2.0

  # Publish the latest draft
  autogov release publish --latest`,
	RunE: runPublish,
}

func init() {
	publishCmd.Flags().String("tag", "", "Release tag to publish")
	publishCmd.Flags().Bool("latest", false, "Publish the most recent draft release")
}

func runPublish(cmd *cobra.Command, args []string) error {
	fmt.Println("release publish: not yet implemented")
	fmt.Println("This command will publish a draft release.")
	return nil
}
