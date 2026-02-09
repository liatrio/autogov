package cmd

import (
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/download"
	"github.com/spf13/cobra"
)

const (
	flagDownloadOutput = "output"
	flagDownloadFormat = "format"
)

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download attestations for offline verification",
	Long: `Download GitHub artifact attestations and save them as Sigstore bundles
for later offline verification. This allows verification in air-gapped environments
or when GitHub API access is unavailable.

Examples:
  # Download attestations for a blob file
  autogov download --blob-path artifact.tar.gz --repo org/repo --output attestations.jsonl

  # Download attestations for a container image digest
  autogov download --image-digest sha256:abc123... --repo org/repo --output attestations.jsonl`,
	RunE: runDownload,
}

func init() {
	downloadCmd.Flags().String(flagBlobPath, "", "Path to artifact file to download attestations for")
	downloadCmd.Flags().String(flagImageDigest, "", "Container image digest (e.g., sha256:...)")
	downloadCmd.Flags().StringP(flagDownloadOutput, "o", "", "Output file path for attestation bundles (required)")
	downloadCmd.Flags().String(flagDownloadFormat, "jsonl", "Output format: json or jsonl")
	downloadCmd.Flags().StringP(flagRepo, "R", "", "Repository to download attestations from (format: owner/repo)")
	downloadCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")

	downloadCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		blobPath, _ := cmd.Flags().GetString(flagBlobPath)
		imageDigest, _ := cmd.Flags().GetString(flagImageDigest)

		if blobPath == "" && imageDigest == "" && len(args) == 0 {
			return fmt.Errorf("must specify --%s, --%s, or provide artifact digest as argument", flagBlobPath, flagImageDigest)
		}

		return nil
	}

	if err := downloadCmd.MarkFlagRequired(flagDownloadOutput); err != nil {
		panic(fmt.Sprintf("failed to mark download output flag as required: %v", err))
	}
}

func runDownload(cmd *cobra.Command, args []string) error {
	return download.RunCommand(cmd, args)
}
