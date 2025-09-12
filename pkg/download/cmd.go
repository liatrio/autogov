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
	// parse flags using CLI helpers
	common, err := cli.ParseCommonOptions(cmd)
	if err != nil {
		return err
	}

	selector, err := cli.ParseArtifactSelector(cmd, args)
	if err != nil {
		return err
	}

	// download command requires repo for online verification
	if err := cli.RequireRepoIf(selector, true); err != nil {
		return err
	}

	downloadOpts, err := cli.ParseDownloadOptions(cmd)
	if err != nil {
		return err
	}

	// validate required fields
	if downloadOpts.Output == "" {
		return fmt.Errorf("output path is required")
	}

	if selector.Repo == "" {
		return fmt.Errorf("repository is required (format: owner/repo)")
	}

	// build download options for the downloader
	downloaderOpts := DownloadOptions{
		OutputPath:   downloadOpts.Output,
		OutputFormat: downloadOpts.Format,
		Repository:   selector.Repo,
		GitHubToken:  github.GetToken(),
		Quiet:        common.Quiet,
	}

	// set artifact path or digest based on selector
	if len(selector.BlobPaths) > 0 {
		downloaderOpts.ArtifactPath = selector.BlobPaths[0] // use first blob path
	}
	if selector.ImageDigest != "" {
		downloaderOpts.ArtifactDigest = selector.ImageDigest
	}

	// log what we're downloading
	if selector.ImageDigest != "" {
		cli.LogInfoln(common.Quiet, "Downloading attestations for image digest: %s", selector.ImageDigest)
	} else if len(selector.BlobPaths) > 0 {
		cli.LogInfoln(common.Quiet, "Downloading attestations for artifact: %s", selector.BlobPaths[0])
	}

	downloader, err := NewAttestationDownloader(downloaderOpts)
	if err != nil {
		return fmt.Errorf("failed to create downloader: %w", err)
	}

	// downloads attestations
	if err := downloader.Download(context.Background()); err != nil {
		return fmt.Errorf("failed to download attestations: %w", err)
	}

	cli.LogSuccessln(common.Quiet, "Attestations saved to: %s", downloadOpts.Output)

	return nil
}
