// handles the verification orchestration process
package orchestrate

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/go-github/v74/github"
	"github.com/liatrio/autogov-verify/pkg/attestations"
	"github.com/liatrio/autogov-verify/pkg/certid"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

// contains all options for verification
type Options struct {
	ArtifactDigest         string
	Repository             string
	CertIdentity           string
	CertIssuer             string
	SourceRef              string
	BlobPaths              []string
	Quiet                  bool
	CertIdentityValidation *certid.Options
}

// verifies multiple blob files and returns all signatures
func VerifyBlobs(ctx context.Context, client *github.Client, opts Options) ([]oci.Signature, error) {
	if len(opts.BlobPaths) == 0 {
		// no blob paths, verify image/container
		return attestations.GetFromGitHub(
			ctx,
			opts.ArtifactDigest,
			client,
			attestations.Options{
				Repository:             opts.Repository,
				CertIdentity:           opts.CertIdentity,
				CertIssuer:             opts.CertIssuer,
				BlobPath:               "",
				SourceRef:              opts.SourceRef,
				Quiet:                  opts.Quiet,
				CertIdentityValidation: opts.CertIdentityValidation,
			},
		)
	}

	// each blob processed individually and collects all signatures
	var allSigs []oci.Signature
	for i, bp := range opts.BlobPaths {
		if !opts.Quiet {
			fmt.Printf("Verifying blob %d/%d: %s\n", i+1, len(opts.BlobPaths), filepath.Base(bp))
		}

		blobSigs, err := attestations.GetFromGitHub(
			ctx,
			opts.ArtifactDigest,
			client,
			attestations.Options{
				Repository:             opts.Repository,
				CertIdentity:           opts.CertIdentity,
				CertIssuer:             opts.CertIssuer,
				BlobPath:               bp,
				SourceRef:              opts.SourceRef,
				Quiet:                  opts.Quiet,
				CertIdentityValidation: opts.CertIdentityValidation,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("error getting attestations for %s: %w", bp, err)
		}
		allSigs = append(allSigs, blobSigs...)
	}

	return allSigs, nil
}

// configures certificate identity validation if needed
func SetupCertIdentityValidation(certIdentityListURL string, noCache bool, quiet bool) *certid.Options {
	if certIdentityListURL == "" {
		return nil
	}

	opts := certid.DefaultOptions()
	opts.DisableCache = noCache
	opts.URL = certIdentityListURL

	if !quiet {
		fmt.Println("Certificate identity validation enabled")
		fmt.Printf("Using identity list: %s\n", opts.URL)
		if opts.DisableCache {
			fmt.Println("Cache disabled")
		}
		fmt.Println("---")
	}

	return &opts
}
