package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// reads common flags from the command
func ParseCommonOptions(cmd *cobra.Command) (*CommonOptions, error) {
	var opts CommonOptions
	var err error

	// quiet flag should be available on all commands
	if opts.Quiet, err = cmd.Flags().GetBool("quiet"); err != nil {
		return nil, fmt.Errorf("failed to read --quiet flag: %w", err)
	}

	// cert-identity, cert-issuer, and source-ref are optional depending on command
	if cmd.Flags().Lookup("cert-identity") != nil {
		if opts.CertIdentity, err = cmd.Flags().GetString("cert-identity"); err != nil {
			return nil, fmt.Errorf("failed to read --cert-identity flag: %w", err)
		}
	}
	if cmd.Flags().Lookup("cert-issuer") != nil {
		if opts.CertIssuer, err = cmd.Flags().GetString("cert-issuer"); err != nil {
			return nil, fmt.Errorf("failed to read --cert-issuer flag: %w", err)
		}
	}
	if cmd.Flags().Lookup("source-ref") != nil {
		if opts.SourceRef, err = cmd.Flags().GetString("source-ref"); err != nil {
			return nil, fmt.Errorf("failed to read --source-ref flag: %w", err)
		}
	}

	return &opts, nil
}

// reads artifact selection flags / handles positional digest
func ParseArtifactSelector(cmd *cobra.Command, args []string) (*ArtifactSelector, error) {
	var selector ArtifactSelector
	var err error

	// read flags
	var blobPath string
	if blobPath, err = cmd.Flags().GetString("blob-path"); err != nil {
		return nil, fmt.Errorf("failed to read --blob-path flag: %w", err)
	}
	if selector.ImageDigest, err = cmd.Flags().GetString("image-digest"); err != nil {
		return nil, fmt.Errorf("failed to read --image-digest flag: %w", err)
	}

	// repo flag is optional depending on command
	if cmd.Flags().Lookup("repo") != nil {
		if selector.Repo, err = cmd.Flags().GetString("repo"); err != nil {
			return nil, fmt.Errorf("failed to read --repo flag: %w", err)
		}
	}

	// handle positional digest
	if selector.ImageDigest == "" && blobPath == "" && len(args) > 0 {
		selector.PositionalDigest = args[0]
		// validate positional digest format
		if err := ValidateDigestFormat(selector.PositionalDigest); err != nil {
			return nil, fmt.Errorf("invalid positional digest: %w", err)
		}
		selector.ImageDigest = selector.PositionalDigest
	}

	// expand blob paths if provided
	if blobPath != "" {
		selector.BlobPaths, err = ExpandBlobPaths(blobPath)
		if err != nil {
			return nil, fmt.Errorf("failed to expand blob paths: %w", err)
		}
	}

	// validate digest format if provided
	if selector.ImageDigest != "" {
		if err := ValidateDigestFormat(selector.ImageDigest); err != nil {
			return nil, err
		}
	}

	// build full image reference if needed
	if selector.ImageDigest != "" && selector.Repo != "" {
		selector.FullImageRef = BuildFullImageRef(selector.Repo, selector.ImageDigest)
	}

	// apply validations
	if err := RequireAtLeastOne(&selector); err != nil {
		return nil, err
	}

	return &selector, nil
}

// reads offline-specific flags
func ParseOfflineOptions(cmd *cobra.Command) (*OfflineOptions, error) {
	var opts OfflineOptions
	var err error

	if opts.AttestationsPath, err = cmd.Flags().GetString("attestations"); err != nil {
		return nil, fmt.Errorf("failed to read --attestations flag: %w", err)
	}
	if opts.TrustedRoot, err = cmd.Flags().GetString("trusted-root"); err != nil {
		return nil, fmt.Errorf("failed to read --trusted-root flag: %w", err)
	}
	if opts.GenerateVSA, err = cmd.Flags().GetBool("generate-vsa"); err != nil {
		return nil, fmt.Errorf("failed to read --generate-vsa flag: %w", err)
	}
	if opts.VSAOutput, err = cmd.Flags().GetString("vsa-output"); err != nil {
		return nil, fmt.Errorf("failed to read --vsa-output flag: %w", err)
	}
	if opts.PolicyURI, err = cmd.Flags().GetString("policy-uri"); err != nil {
		return nil, fmt.Errorf("failed to read --policy-uri flag: %w", err)
	}
	if opts.PolicyBundlePath, err = cmd.Flags().GetString("policy-bundle-path"); err != nil {
		return nil, fmt.Errorf("failed to read --policy-bundle-path flag: %w", err)
	}
	if opts.PolicySchemasPath, err = cmd.Flags().GetString("policy-schemas-path"); err != nil {
		return nil, fmt.Errorf("failed to read --policy-schemas-path flag: %w", err)
	}

	return &opts, nil
}

// reads download-specific flags
func ParseDownloadOptions(cmd *cobra.Command) (*DownloadOptions, error) {
	var opts DownloadOptions
	var err error

	if opts.Output, err = cmd.Flags().GetString("output"); err != nil {
		return nil, fmt.Errorf("failed to read --output flag: %w", err)
	}
	if opts.Format, err = cmd.Flags().GetString("format"); err != nil {
		return nil, fmt.Errorf("failed to read --format flag: %w", err)
	}

	return &opts, nil
}
