package download

import (
	"context"
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/cli"
	"github.com/liatrio/autogov-verify/pkg/github"
	"github.com/spf13/cobra"
)

// handles the download command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// gets config values
	quiet, _ := cmd.Flags().GetBool("quiet")
	blobPath, _ := cmd.Flags().GetString("blob-path")
	imageDigest, _ := cmd.Flags().GetString("image-digest")
	outputPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	repo, _ := cmd.Flags().GetString("repo")

	// handle positional argument for digest
	if imageDigest == "" && len(args) > 0 {
		imageDigest = args[0]
	}

	// validate required fields
	if outputPath == "" {
		return fmt.Errorf("output path is required")
	}

	if repo == "" {
		return fmt.Errorf("repository is required (format: owner/repo)")
	}

	// expand blob paths if provided
	var blobPaths []string
	if blobPath != "" {
		expandedPaths, err := cli.ExpandBlobPaths(blobPath)
		if err != nil {
			return fmt.Errorf("failed to expand blob paths: %w", err)
		}
		blobPaths = expandedPaths
	}

	// process each blob file
	for i, artifactPath := range blobPaths {
		if len(blobPaths) > 1 {
			fmt.Printf("Processing file %d/%d: %s\n", i+1, len(blobPaths), artifactPath)
		}

		// build download options
		downloaderOpts := DownloadOptions{
			ArtifactPath:   artifactPath,
			ArtifactDigest: imageDigest,
			OutputPath:     outputPath,
			OutputFormat:   format,
			Repository:     repo,
			GitHubToken:    github.GetToken(),
			Quiet:          quiet,
		}

		// log what we're downloading
		if !quiet {
			if imageDigest != "" {
				fmt.Printf("Downloading attestations for image digest: %s\n", imageDigest)
			} else if artifactPath != "" {
				fmt.Printf("Downloading attestations for artifact: %s\n", artifactPath)
			}
		}

		// create downloader
		downloader, err := NewAttestationDownloader(downloaderOpts)
		if err != nil {
			return fmt.Errorf("failed to create downloader for %s: %w", artifactPath, err)
		}

		// download attestations
		err = downloader.Download(context.Background())
		if err != nil {
			return fmt.Errorf("download failed for %s: %w", artifactPath, err)
		}

		if !quiet {
			fmt.Printf("\n✓ Attestations saved to: %s\n", outputPath)
		}
	}

	if len(blobPaths) == 0 {
		return fmt.Errorf("no files found to process")
	}

	return nil
}
