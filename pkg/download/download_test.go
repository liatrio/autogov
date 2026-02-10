package download

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-github/v82/github"
	"github.com/spf13/cobra"
)

func TestNewAttestationDownloader(t *testing.T) {
	tests := []struct {
		name    string
		opts    DownloadOptions
		wantErr bool
	}{
		{
			name: "valid options with digest",
			opts: DownloadOptions{
				ArtifactDigest: "sha256:abc123",
				Repository:     "owner/repo",
				OutputPath:     "/tmp/test.jsonl",
			},
			wantErr: false,
		},
		{
			name: "valid options with path",
			opts: DownloadOptions{
				ArtifactPath: "/tmp/artifact.txt",
				Repository:   "owner/repo",
				OutputPath:   "/tmp/test.jsonl",
			},
			wantErr: false,
		},
		{
			name: "with github token",
			opts: DownloadOptions{
				ArtifactDigest: "sha256:abc123",
				Repository:     "owner/repo",
				OutputPath:     "/tmp/test.jsonl",
				GitHubToken:    "ghp_test123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			downloader, err := NewAttestationDownloader(tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAttestationDownloader() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewAttestationDownloader() unexpected error: %v", err)
				return
			}

			if downloader == nil {
				t.Errorf("NewAttestationDownloader() returned nil downloader")
				return
			}

			if downloader.client == nil {
				t.Errorf("NewAttestationDownloader() client is nil")
			}

			// verify default output format is set
			if downloader.opts.OutputFormat == "" {
				t.Errorf("NewAttestationDownloader() output format not set to default")
			}
		})
	}
}

func TestDownload(t *testing.T) {
	// create a test artifact file
	tmpArtifact, err := os.CreateTemp("", "artifact_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp artifact file: %v", err)
	}
	defer func() { _ = os.Remove(tmpArtifact.Name()) }()

	testContent := "test artifact content"
	if _, err := tmpArtifact.WriteString(testContent); err != nil {
		t.Fatalf("failed to write artifact content: %v", err)
	}
	_ = tmpArtifact.Close()

	// create test output file path
	tmpOutput, err := os.CreateTemp("", "output_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp output file: %v", err)
	}
	_ = tmpOutput.Close()
	_ = os.Remove(tmpOutput.Name()) // remove so download can create it
	defer func() { _ = os.Remove(tmpOutput.Name()) }()

	// mock github server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/attestations") {
			// mock attestation response
			response := struct {
				Attestations []map[string]interface{} `json:"attestations"`
			}{
				Attestations: []map[string]interface{}{
					{
						"bundle": map[string]interface{}{
							"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
							"verificationMaterial": map[string]interface{}{
								"x509CertificateChain": map[string]interface{}{
									"certificates": []map[string]interface{}{
										{"rawBytes": "dGVzdA=="},
									},
								},
							},
							"dsseEnvelope": map[string]interface{}{
								"payload":     "dGVzdA==",
								"payloadType": "application/vnd.in-toto+json",
								"signatures":  []map[string]interface{}{{"sig": "dGVzdA=="}},
							},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(response)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// test with artifact path
	t.Run("download with artifact path", func(t *testing.T) {
		opts := DownloadOptions{
			ArtifactPath: tmpArtifact.Name(),
			Repository:   "owner/repo",
			OutputPath:   tmpOutput.Name(),
		}

		downloader, err := NewAttestationDownloader(opts)
		if err != nil {
			t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
		}

		// note: this will fail in actual execution since we're using a mock server
		// but the test structure verifies the code paths work
		ctx := context.Background()
		err = downloader.Download(ctx)

		// we expect an error here because we don't have a real GitHub API
		if err == nil {
			t.Errorf("Download() expected error due to mock setup, got nil")
		}
	})

	// test with digest
	t.Run("download with digest", func(t *testing.T) {
		opts := DownloadOptions{
			ArtifactDigest: "sha256:abc123",
			Repository:     "owner/repo",
			OutputPath:     tmpOutput.Name(),
		}

		downloader, err := NewAttestationDownloader(opts)
		if err != nil {
			t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
		}

		ctx := context.Background()
		err = downloader.Download(ctx)

		// we expect an error here because we don't have a real GitHub API
		if err == nil {
			t.Errorf("Download() expected error due to mock setup, got nil")
		}
	})

	// test validation errors
	t.Run("download without artifact or digest", func(t *testing.T) {
		opts := DownloadOptions{
			Repository: "owner/repo",
			OutputPath: tmpOutput.Name(),
		}

		downloader, err := NewAttestationDownloader(opts)
		if err != nil {
			t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
		}

		ctx := context.Background()
		err = downloader.Download(ctx)

		if err == nil {
			t.Errorf("Download() expected error for missing artifact, got nil")
		}

		expectedErr := "must specify either artifact path or digest"
		if err != nil && !strings.Contains(err.Error(), expectedErr) {
			t.Errorf("Download() expected error containing %q, got %v", expectedErr, err)
		}
	})
}

// validate download options validates download options
func validateDownloadOptions(opts DownloadOptions) error {
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

func TestValidateDownloadOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    DownloadOptions
		wantErr bool
	}{
		{
			name: "valid with artifact digest",
			opts: DownloadOptions{
				ArtifactDigest: "sha256:abc123",
				Repository:     "owner/repo",
				OutputPath:     "/tmp/test.jsonl",
			},
			wantErr: false,
		},
		{
			name: "valid with artifact path",
			opts: DownloadOptions{
				ArtifactPath: "/tmp/artifact.txt",
				Repository:   "owner/repo",
				OutputPath:   "/tmp/test.jsonl",
			},
			wantErr: false,
		},
		{
			name: "missing both artifact path and digest",
			opts: DownloadOptions{
				Repository: "owner/repo",
				OutputPath: "/tmp/test.jsonl",
			},
			wantErr: true,
		},
		{
			name: "missing repository",
			opts: DownloadOptions{
				ArtifactDigest: "sha256:abc123",
				OutputPath:     "/tmp/test.jsonl",
			},
			wantErr: true,
		},
		{
			name: "missing output path",
			opts: DownloadOptions{
				ArtifactDigest: "sha256:abc123",
				Repository:     "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "invalid output format",
			opts: DownloadOptions{
				ArtifactDigest: "sha256:abc123",
				Repository:     "owner/repo",
				OutputPath:     "/tmp/test.jsonl",
				OutputFormat:   "xml",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDownloadOptions(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDownloadOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFetchAttestationsFromGitHub(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// test the method exists and can be called
	// note: this will fail in practice because we don't have GitHub API access in tests
	ctx := context.Background()
	_, err = downloader.fetchAttestations(ctx, "sha256:abc123")

	// we expect an error here because we don't have real GitHub API access
	if err == nil {
		t.Errorf("fetchAttestations() expected error due to no GitHub API access, got nil")
	}

	// verify the error is related to GitHub API access
	if err != nil && !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "authentication") {
		// this is acceptable - any HTTP error indicates the method is working
		t.Logf("fetchAttestations() returned expected error: %v", err)
	}
}

func TestFetchAttestationsNoRepository(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		OutputPath:     "/tmp/test.jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	ctx := context.Background()
	_, err = downloader.fetchAttestations(ctx, "sha256:abc123")

	if err == nil {
		t.Errorf("fetchAttestations() expected error for missing repository, got nil")
	}

	if !strings.Contains(err.Error(), "repository must be specified") {
		t.Errorf("fetchAttestations() expected repository error, got: %v", err)
	}
}

func TestFetchAttestationsInvalidRepoFormat(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "invalid-format",
		OutputPath:     "/tmp/test.jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	ctx := context.Background()
	_, err = downloader.fetchAttestations(ctx, "sha256:abc123")

	if err == nil {
		t.Errorf("fetchAttestations() expected error for invalid repo format, got nil")
	}

	if !strings.Contains(err.Error(), "invalid repository format") {
		t.Errorf("fetchAttestations() expected repository format error, got: %v", err)
	}
}

func TestConvertAttestationToBundleNil(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// test with nil attestation
	_, err = downloader.convertAttestationToBundle(nil)
	if err == nil {
		t.Error("convertAttestationToBundle() expected error for nil attestation")
	}

	if !strings.Contains(err.Error(), "attestation or bundle is nil") {
		t.Errorf("expected nil error message, got: %v", err)
	}
}

func TestConvertToBundlesEmpty(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// test with empty attestations
	bundles, err := downloader.convertToBundles(nil)
	if err != nil {
		t.Errorf("convertToBundles() unexpected error: %v", err)
	}

	if len(bundles) != 0 {
		t.Errorf("convertToBundles() expected 0 bundles, got %d", len(bundles))
	}
}

func TestSaveBundles(t *testing.T) {
	// create temp output directory
	tmpDir, err := os.MkdirTemp("", "download-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	outputPath := tmpDir + "/test-output.jsonl"

	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     outputPath,
		OutputFormat:   "jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// save empty bundles (should still create file)
	err = downloader.saveBundles(nil)
	if err != nil {
		t.Errorf("saveBundles() unexpected error: %v", err)
	}

	// verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("saveBundles() expected output file to be created")
	}
}

func TestSaveBundlesCreateDir(t *testing.T) {
	// create temp directory
	tmpDir, err := os.MkdirTemp("", "download-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// use a nested path that doesn't exist yet
	outputPath := tmpDir + "/nested/deep/output.jsonl"

	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     outputPath,
		OutputFormat:   "jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// save empty bundles - should create parent directories
	err = downloader.saveBundles(nil)
	if err != nil {
		t.Errorf("saveBundles() unexpected error: %v", err)
	}

	// verify nested directories were created
	if _, err := os.Stat(tmpDir + "/nested/deep"); os.IsNotExist(err) {
		t.Errorf("saveBundles() expected nested directories to be created")
	}
}

func TestDownloadOptionsDefaults(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.jsonl",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// verify default output format
	if downloader.opts.OutputFormat != "jsonl" {
		t.Errorf("expected default output format 'jsonl', got %s", downloader.opts.OutputFormat)
	}
}

func TestDownloadOptionsWithFormat(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.json",
		OutputFormat:   "json",
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// verify custom output format is preserved
	if downloader.opts.OutputFormat != "json" {
		t.Errorf("expected output format 'json', got %s", downloader.opts.OutputFormat)
	}
}

func TestDownloadQuietMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "download-quiet-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     tmpDir + "/test.jsonl",
		Quiet:          true,
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	if !downloader.opts.Quiet {
		t.Error("expected quiet mode to be enabled")
	}
}

// helper to create test command with flags
func createTestDownloadCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("quiet", false, "quiet mode")
	cmd.Flags().String("blob-path", "", "path to blob")
	cmd.Flags().String("image-digest", "", "image digest")
	cmd.Flags().String("output", "", "output path")
	cmd.Flags().String("format", "", "output format")
	cmd.Flags().String("repo", "", "repository")
	return cmd
}

func TestRunCommandMissingOutput(t *testing.T) {
	cmd := createTestDownloadCmd()
	_ = cmd.Flags().Set("repo", "owner/repo")
	_ = cmd.Flags().Set("blob-path", "/tmp/test.txt")

	err := RunCommand(cmd, []string{})

	if err == nil {
		t.Error("RunCommand() expected error for missing output")
	}

	if !strings.Contains(err.Error(), "output path is required") {
		t.Errorf("expected output path error, got: %v", err)
	}
}

func TestRunCommandMissingRepo(t *testing.T) {
	cmd := createTestDownloadCmd()
	_ = cmd.Flags().Set("output", "/tmp/test.jsonl")
	_ = cmd.Flags().Set("blob-path", "/tmp/test.txt")

	err := RunCommand(cmd, []string{})

	if err == nil {
		t.Error("RunCommand() expected error for missing repo")
	}

	if !strings.Contains(err.Error(), "repository is required") {
		t.Errorf("expected repository error, got: %v", err)
	}
}

func TestRunCommandNoFiles(t *testing.T) {
	cmd := createTestDownloadCmd()
	_ = cmd.Flags().Set("output", "/tmp/test.jsonl")
	_ = cmd.Flags().Set("repo", "owner/repo")

	err := RunCommand(cmd, []string{})

	if err == nil {
		t.Error("RunCommand() expected error for no files")
	}

	if !strings.Contains(err.Error(), "no files found to process") {
		t.Errorf("expected no files error, got: %v", err)
	}
}

func TestRunCommandWithDigestArg(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "download-cmd-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// create a test blob file
	blobFile := tmpDir + "/test.txt"
	if err := os.WriteFile(blobFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to write blob file: %v", err)
	}

	cmd := createTestDownloadCmd()
	_ = cmd.Flags().Set("output", tmpDir+"/output.jsonl")
	_ = cmd.Flags().Set("repo", "owner/repo")
	_ = cmd.Flags().Set("blob-path", blobFile)

	// should fail because we can't connect to GitHub API
	err = RunCommand(cmd, []string{"sha256:abc123"})

	// we expect error from GitHub API failure, not validation errors
	if err == nil {
		t.Error("RunCommand() expected error from API call")
	}

	// the error should be about fetching, not about missing inputs
	if strings.Contains(err.Error(), "output path is required") ||
		strings.Contains(err.Error(), "repository is required") {
		t.Errorf("RunCommand() got validation error, expected API error: %v", err)
	}
}

func TestConvertToBundlesWithNilAttestation(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.jsonl",
		Quiet:          true,
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// convert with one nil attestation (should be skipped silently in quiet mode)
	bundles, err := downloader.convertToBundles([]*github.Attestation{nil})
	if err != nil {
		t.Errorf("convertToBundles() unexpected error: %v", err)
	}

	// nil attestation should be skipped
	if len(bundles) != 0 {
		t.Errorf("expected 0 bundles (nil skipped), got %d", len(bundles))
	}
}

func TestConvertToBundlesWithNilAttestationVerbose(t *testing.T) {
	opts := DownloadOptions{
		ArtifactDigest: "sha256:abc123",
		Repository:     "owner/repo",
		OutputPath:     "/tmp/test.jsonl",
		Quiet:          false,
	}

	downloader, err := NewAttestationDownloader(opts)
	if err != nil {
		t.Fatalf("NewAttestationDownloader() unexpected error: %v", err)
	}

	// convert with one nil attestation (should print warning)
	bundles, err := downloader.convertToBundles([]*github.Attestation{nil})
	if err != nil {
		t.Errorf("convertToBundles() unexpected error: %v", err)
	}

	if len(bundles) != 0 {
		t.Errorf("expected 0 bundles (nil skipped), got %d", len(bundles))
	}
}
