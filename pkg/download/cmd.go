package download

import (
	"context"
	"fmt"

	"github.com/liatrio/autogov/pkg/cli"
	"github.com/liatrio/autogov/pkg/github"
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
	blobPaths, err := resolveBlobPaths(blobPath, imageDigest)
	if err != nil {
		return err
	}

	// process each blob file (or digest-only download)
	for i, artifactPath := range blobPaths {
		if len(blobPaths) > 1 {
			fmt.Printf("Processing file %d/%d: %s\n", i+1, len(blobPaths), artifactPath)
		}

		if err := processArtifact(artifactPath, imageDigest, outputPath, format, repo, quiet); err != nil {
			return err
		}
	}

	return nil
}

// resolveBlobPaths expands the provided blob path glob into concrete paths,
// falling back to a single digest-only download when only an image digest is set.
func resolveBlobPaths(blobPath, imageDigest string) ([]string, error) {
	var blobPaths []string
	if blobPath != "" {
		expandedPaths, err := cli.ExpandBlobPaths(blobPath)
		if err != nil {
			return nil, fmt.Errorf("failed to expand blob paths: %w", err)
		}
		blobPaths = expandedPaths
	}

	// if no blob paths but image-digest is provided, download for digest directly
	if len(blobPaths) == 0 && imageDigest != "" {
		blobPaths = []string{""}
	}

	if len(blobPaths) == 0 {
		return nil, fmt.Errorf("no files found to process")
	}

	return blobPaths, nil
}

// processArtifact downloads attestations for a single artifact path (or digest-only download).
func processArtifact(artifactPath, imageDigest, outputPath, format, repo string, quiet bool) error {
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

	return nil
}
