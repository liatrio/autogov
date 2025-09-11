package download

import (
	"context"
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/github"
	"github.com/spf13/cobra"
)

// RunCommand handles the download command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// get config values directly from the command flags
	artifactPath, _ := cmd.Flags().GetString("blob-path")
	imageDigest, _ := cmd.Flags().GetString("image-digest")
	outputPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	repo, _ := cmd.Flags().GetString("repo")
	quiet, _ := cmd.Flags().GetBool("quiet")

	if artifactPath == "" && imageDigest == "" && len(args) == 0 {
		return fmt.Errorf("must specify --blob-path, --image-digest, or provide artifact digest as argument")
	}

	if outputPath == "" {
		return fmt.Errorf("output path is required")
	}

	if repo == "" {
		return fmt.Errorf("repository is required (format: owner/repo)")
	}

	// attestation downloader with options
	downloadOpts := DownloadOptions{
		ArtifactPath: artifactPath,
		OutputPath:   outputPath,
		OutputFormat: format,
		Repository:   repo,
		GitHubToken:  github.GetToken(),
	}

	// handle image digest
	if imageDigest != "" {
		downloadOpts.ArtifactDigest = imageDigest
	} else if len(args) > 0 {
		// if argument provided, use it as digest
		downloadOpts.ArtifactDigest = args[0]
	}

	if !quiet {
		if imageDigest != "" {
			fmt.Printf("Downloading attestations for image digest: %s\n", imageDigest)
		} else if downloadOpts.ArtifactDigest != "" {
			fmt.Printf("Downloading attestations for digest: %s\n", downloadOpts.ArtifactDigest)
		} else {
			fmt.Printf("Downloading attestations for artifact: %s\n", artifactPath)
		}
	}

	downloader, err := NewAttestationDownloader(downloadOpts)
	if err != nil {
		return fmt.Errorf("failed to create downloader: %w", err)
	}

	// downloads attestations
	if err := downloader.Download(context.Background()); err != nil {
		return fmt.Errorf("failed to download attestations: %w", err)
	}

	if !quiet {
		fmt.Printf("✓ Attestations saved to: %s\n", outputPath)
	}

	return nil
}
