package download

import (
	"context"
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/github"
	"github.com/spf13/cobra"
)

// handles the download command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// get config values from flags with error checking
	var (
		artifactPath string
		imageDigest  string
		outputPath   string
		format       string
		repo         string
		quiet        bool
	)
	var err error
	if artifactPath, err = cmd.Flags().GetString("blob-path"); err != nil {
		return fmt.Errorf("failed to read --blob-path flag: %w", err)
	}
	if imageDigest, err = cmd.Flags().GetString("image-digest"); err != nil {
		return fmt.Errorf("failed to read --image-digest flag: %w", err)
	}
	if outputPath, err = cmd.Flags().GetString("output"); err != nil {
		return fmt.Errorf("failed to read --output flag: %w", err)
	}
	if format, err = cmd.Flags().GetString("format"); err != nil {
		return fmt.Errorf("failed to read --format flag: %w", err)
	}
	if repo, err = cmd.Flags().GetString("repo"); err != nil {
		return fmt.Errorf("failed to read --repo flag: %w", err)
	}
	if quiet, err = cmd.Flags().GetBool("quiet"); err != nil {
		return fmt.Errorf("failed to read --quiet flag: %w", err)
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
		Quiet:        quiet,
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
