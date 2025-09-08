// Package offline - download.go
// Handles downloading attestations from GitHub API for offline verification
package download

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v74/github"
	"github.com/liatrio/autogov-verify/pkg/offline"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// options for downloading attestations
type DownloadOptions struct {
	// target artifact
	ArtifactPath   string // path to local artifact file
	ArtifactDigest string // SHA256 digest of artifact (alternative to path)

	// repository information (for fetching from specific repo/release)
	Repository string // format: owner/repo
	Tag        string // release tag (optional)

	// output options
	OutputPath   string // path to save bundle file
	OutputFormat string // "jsonl" or "json" (default: jsonl)

	// authentication
	GitHubToken string // GitHub token for API access

	// filtering options
	AttestationTypes []string // filter by attestation types
	MaxAttestations  int      // limit number of attestations (0 = no limit)
}

// handles downloading attestations from GitHub
type AttestationDownloader struct {
	client *github.Client
	opts   DownloadOptions
}

// creates a new attestation downloader
func NewAttestationDownloader(opts DownloadOptions) (*AttestationDownloader, error) {
	var client *github.Client
	if opts.GitHubToken != "" {
		client = github.NewClient(nil).WithAuthToken(opts.GitHubToken)
	} else {
		client = github.NewClient(nil)
	}

	// defaults
	if opts.OutputFormat == "" {
		opts.OutputFormat = "jsonl"
	}

	return &AttestationDownloader{
		client: client,
		opts:   opts,
	}, nil
}

// downloads attestations and saves them as bundles
func (ad *AttestationDownloader) Download(ctx context.Context) error {
	// determine target digest
	var targetDigest string
	var err error

	if ad.opts.ArtifactDigest != "" {
		targetDigest = ad.opts.ArtifactDigest
	} else if ad.opts.ArtifactPath != "" {
		targetDigest, err = calculateFileDigest(ad.opts.ArtifactPath)
		if err != nil {
			return fmt.Errorf("failed to calculate artifact digest: %w", err)
		}
	} else {
		return fmt.Errorf("must specify either artifact path or digest")
	}

	// clean digest format (ensure it has sha256: prefix)
	if !strings.HasPrefix(targetDigest, "sha256:") {
		targetDigest = "sha256:" + targetDigest
	}

	fmt.Printf("Downloading attestations for digest: %s\n", targetDigest)

	// fetch attestations from GitHub
	attestations, err := ad.fetchAttestations(ctx, targetDigest)
	if err != nil {
		return fmt.Errorf("failed to fetch attestations: %w", err)
	}

	if len(attestations) == 0 {
		return fmt.Errorf("no attestations found for digest %s", targetDigest)
	}

	fmt.Printf("Found %d attestations\n", len(attestations))

	// convert to bundles
	bundles, err := ad.convertToBundles(attestations)
	if err != nil {
		return fmt.Errorf("failed to convert attestations to bundles: %w", err)
	}

	// filter bundles if requested
	if len(ad.opts.AttestationTypes) > 0 {
		bundles = ad.filterBundles(bundles)
	}

	// limit number of bundles if requested
	if ad.opts.MaxAttestations > 0 && len(bundles) > ad.opts.MaxAttestations {
		bundles = bundles[:ad.opts.MaxAttestations]
	}

	fmt.Printf("Saving %d bundles to %s\n", len(bundles), ad.opts.OutputPath)

	// save bundles to file
	if err := ad.saveBundles(bundles); err != nil {
		return fmt.Errorf("failed to save bundles: %w", err)
	}

	fmt.Printf("Successfully downloaded attestations to %s\n", ad.opts.OutputPath)
	return nil
}

// fetch attestations fetches attestations from GitHub API
func (ad *AttestationDownloader) fetchAttestations(ctx context.Context, digest string) ([]*github.Attestation, error) {
	if ad.opts.Repository == "" {
		// extract org and repo from the artifact path (if it's a cert-identity URL)
		return nil, fmt.Errorf("repository must be specified (format: owner/repo)")
	}

	// parse repository to get owner and repo
	parts := strings.Split(ad.opts.Repository, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository format, expected owner/repo")
	}
	owner := parts[0]

	// list attestations for the organization and digest
	attestations, _, err := ad.client.Organizations.ListAttestations(ctx, owner, digest, &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
	}

	if attestations == nil || attestations.Attestations == nil {
		return []*github.Attestation{}, nil
	}

	return attestations.Attestations, nil
}

// converts GitHub attestations to Sigstore bundles
func (ad *AttestationDownloader) convertToBundles(attestations []*github.Attestation) ([]*bundle.Bundle, error) {
	bundles := make([]*bundle.Bundle, 0, len(attestations))

	for _, attestation := range attestations {
		b, err := ad.convertAttestationToBundle(attestation)
		if err != nil {
			// Log warning but continue with other attestations
			fmt.Printf("Warning: failed to convert attestation to bundle: %v\n", err)
			continue
		}
		bundles = append(bundles, b)
	}

	return bundles, nil
}

// converts a single GitHub attestation to a Sigstore bundle
func (ad *AttestationDownloader) convertAttestationToBundle(attestation *github.Attestation) (*bundle.Bundle, error) {
	if attestation == nil || attestation.Bundle == nil {
		return nil, fmt.Errorf("attestation or bundle is nil")
	}

	// Parse the JSON bundle directly
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(attestation.Bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	return b, nil
}

// filter bundles by attestation type
func (ad *AttestationDownloader) filterBundles(bundles []*bundle.Bundle) []*bundle.Bundle {
	if len(ad.opts.AttestationTypes) == 0 {
		return bundles
	}

	filtered := make([]*bundle.Bundle, 0)

	for _, bundle := range bundles {
		attestationType := ad.detectBundleType(bundle)

		for _, allowedType := range ad.opts.AttestationTypes {
			if strings.Contains(attestationType, allowedType) {
				filtered = append(filtered, bundle)
				break
			}
		}
	}

	return filtered
}

// detect bundle type detects the attestation type from a bundle
func (ad *AttestationDownloader) detectBundleType(b *bundle.Bundle) string {
	if env, err := b.Envelope(); err == nil {
		if stmt, err := env.Statement(); err == nil {
			return stmt.PredicateType
		}
	}
	return "unknown"
}

// save bundles saves bundles to the output file
func (ad *AttestationDownloader) saveBundles(bundles []*bundle.Bundle) error {
	// ensure output directory exists
	outputDir := filepath.Dir(ad.opts.OutputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// write to output file
	return offline.WriteBundles(bundles, ad.opts.OutputPath, ad.opts.OutputFormat)
}

// calculates SHA256 digest of a file
func calculateFileDigest(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// validate download options validates download options
func ValidateDownloadOptions(opts DownloadOptions) error {
	if opts.ArtifactPath == "" && opts.ArtifactDigest == "" {
		return fmt.Errorf("must specify either artifact-path or artifact-digest")
	}

	if opts.Repository == "" {
		return fmt.Errorf("repository is required")
	}

	if opts.OutputPath == "" {
		return fmt.Errorf("output path is required")
	}

	if opts.OutputFormat != "" && opts.OutputFormat != "json" && opts.OutputFormat != "jsonl" {
		return fmt.Errorf("output format must be 'json' or 'jsonl'")
	}

	return nil
}
