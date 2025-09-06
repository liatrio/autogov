// Package offline - download.go
// Handles downloading attestations from GitHub API for offline verification
package offline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v73/github"
	ghclient "github.com/liatrio/autogov-verify/pkg/github"
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

// NewAttestationDownloader creates a new attestation downloader
func NewAttestationDownloader(opts DownloadOptions) (*AttestationDownloader, error) {
	var client *github.Client
	if opts.GitHubToken != "" {
		client = ghclient.NewClientWithToken(opts.GitHubToken)
	} else {
		client = ghclient.NewClient()
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
		targetDigest, err = CalculateDigest(ad.opts.ArtifactPath)
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
func (ad *AttestationDownloader) convertToBundles(attestations []*github.Attestation) ([]Bundle, error) {
	bundles := make([]Bundle, 0, len(attestations))

	for _, attestation := range attestations {
		bundle, err := ad.convertAttestationToBundle(attestation)
		if err != nil {
			// Log warning but continue with other attestations
			fmt.Printf("Warning: failed to convert attestation to bundle: %v\n", err)
			continue
		}
		bundles = append(bundles, bundle)
	}

	return bundles, nil
}

// converts a single GitHub attestation to a Sigstore bundle
func (ad *AttestationDownloader) convertAttestationToBundle(attestation *github.Attestation) (Bundle, error) {
	if attestation == nil || attestation.Bundle == nil {
		return Bundle{}, fmt.Errorf("attestation or bundle is nil")
	}

	// Parse the JSON bundle directly
	var bundle Bundle
	if err := json.Unmarshal(attestation.Bundle, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	// Ensure the bundle has the correct media type
	if bundle.MediaType == "" {
		bundle.MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	}

	return bundle, nil
}

// filter bundles by attestation type
func (ad *AttestationDownloader) filterBundles(bundles []Bundle) []Bundle {
	if len(ad.opts.AttestationTypes) == 0 {
		return bundles
	}

	filtered := make([]Bundle, 0)

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

// detects the attestation type from a bundle
func (ad *AttestationDownloader) detectBundleType(bundle Bundle) string {
	if bundle.DsseEnvelope == nil {
		return "unknown"
	}

	// parse DSSE payload to extract predicate type
	var envelope struct {
		PredicateType string `json:"predicateType"`
	}

	if err := json.Unmarshal(bundle.DsseEnvelope.Payload, &envelope); err != nil {
		return "unknown"
	}

	return envelope.PredicateType
}

// save bundles saves bundles to the output file
func (ad *AttestationDownloader) saveBundles(bundles []Bundle) error {
	// ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(ad.opts.OutputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	switch ad.opts.OutputFormat {
	case "jsonl":
		return WriteBundles(ad.opts.OutputPath, bundles)
	case "json":
		return ad.saveBundlesAsJSON(bundles)
	default:
		return fmt.Errorf("unsupported output format: %s", ad.opts.OutputFormat)
	}
}

// save bundles as JSON saves bundles as a single JSON array
func (ad *AttestationDownloader) saveBundlesAsJSON(bundles []Bundle) error {
	file, err := os.Create(ad.opts.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(bundles)
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
