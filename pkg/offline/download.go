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

	ghclient "github.com/liatrio/autogov-verify/pkg/github"
	"github.com/google/go-github/v73/github"
)

// DownloadOptions contains options for downloading attestations
type DownloadOptions struct {
	// Target artifact
	ArtifactPath   string // Path to local artifact file
	ArtifactDigest string // SHA256 digest of artifact (alternative to path)
	
	// Repository information (for fetching from specific repo/release)
	Repository string // Format: owner/repo
	Tag        string // Release tag (optional)
	
	// Output options
	OutputPath     string // Path to save bundle file
	OutputFormat   string // "jsonl" or "json" (default: jsonl)
	
	// Authentication
	GitHubToken    string // GitHub token for API access
	
	// Filtering options
	AttestationTypes []string // Filter by attestation types
	MaxAttestations  int      // Limit number of attestations (0 = no limit)
}

// AttestationDownloader handles downloading attestations from GitHub
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

	// Set defaults
	if opts.OutputFormat == "" {
		opts.OutputFormat = "jsonl"
	}

	return &AttestationDownloader{
		client: client,
		opts:   opts,
	}, nil
}

// Download downloads attestations and saves them as bundles
func (ad *AttestationDownloader) Download(ctx context.Context) error {
	// Determine target digest
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

	// Clean digest format (ensure it has sha256: prefix)
	if !strings.HasPrefix(targetDigest, "sha256:") {
		targetDigest = "sha256:" + targetDigest
	}

	fmt.Printf("Downloading attestations for digest: %s\n", targetDigest)

	// Fetch attestations from GitHub
	attestations, err := ad.fetchAttestations(ctx, targetDigest)
	if err != nil {
		return fmt.Errorf("failed to fetch attestations: %w", err)
	}

	if len(attestations) == 0 {
		return fmt.Errorf("no attestations found for digest %s", targetDigest)
	}

	fmt.Printf("Found %d attestations\n", len(attestations))

	// Convert to bundles
	bundles, err := ad.convertToBundles(attestations)
	if err != nil {
		return fmt.Errorf("failed to convert attestations to bundles: %w", err)
	}

	// Filter bundles if requested
	if len(ad.opts.AttestationTypes) > 0 {
		bundles = ad.filterBundles(bundles)
	}

	// Limit number of bundles if requested
	if ad.opts.MaxAttestations > 0 && len(bundles) > ad.opts.MaxAttestations {
		bundles = bundles[:ad.opts.MaxAttestations]
	}

	fmt.Printf("Saving %d bundles to %s\n", len(bundles), ad.opts.OutputPath)

	// Save bundles to file
	if err := ad.saveBundles(bundles); err != nil {
		return fmt.Errorf("failed to save bundles: %w", err)
	}

	fmt.Printf("Successfully downloaded attestations to %s\n", ad.opts.OutputPath)
	return nil
}

// fetchAttestations fetches attestations from GitHub API
func (ad *AttestationDownloader) fetchAttestations(ctx context.Context, digest string) ([]*github.Attestation, error) {
	// For now, return a simple implementation that would need to be integrated
	// with the existing attestation fetching logic from the attestations package
	return nil, fmt.Errorf("GitHub API attestation fetching not implemented yet - use existing attestations package")
}

// convertToBundles converts GitHub attestations to Sigstore bundles
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

// convertAttestationToBundle converts a single GitHub attestation to a Sigstore bundle
func (ad *AttestationDownloader) convertAttestationToBundle(attestation *github.Attestation) (Bundle, error) {
	// This is a simplified implementation - in practice would need to properly
	// convert from the github.Attestation type to our Bundle format
	// For now, return an empty bundle with basic structure
	bundle := Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
	}

	// TODO: Implement proper conversion from github.Attestation to Bundle
	// This would require parsing the JSON RawMessage and extracting the fields
	return bundle, nil
}

// filterBundles filters bundles by attestation type
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

// detectBundleType detects the attestation type from a bundle
func (ad *AttestationDownloader) detectBundleType(bundle Bundle) string {
	if bundle.DsseEnvelope == nil {
		return "unknown"
	}

	// Parse DSSE payload to extract predicate type
	var envelope struct {
		PredicateType string `json:"predicateType"`
	}

	if err := json.Unmarshal(bundle.DsseEnvelope.Payload, &envelope); err != nil {
		return "unknown"
	}

	return envelope.PredicateType
}

// saveBundles saves bundles to the output file
func (ad *AttestationDownloader) saveBundles(bundles []Bundle) error {
	// Ensure output directory exists
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

// saveBundlesAsJSON saves bundles as a single JSON array
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

// ValidateDownloadOptions validates download options
func ValidateDownloadOptions(opts DownloadOptions) error {
	if opts.ArtifactPath == "" && opts.ArtifactDigest == "" {
		return fmt.Errorf("must specify either artifact-path or artifact-digest")
	}

	if opts.OutputPath == "" {
		return fmt.Errorf("output path is required")
	}

	if opts.OutputFormat != "" && opts.OutputFormat != "json" && opts.OutputFormat != "jsonl" {
		return fmt.Errorf("output format must be 'json' or 'jsonl'")
	}

	return nil
}
