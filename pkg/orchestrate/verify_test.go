package orchestrate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-github/v89/github"
	"github.com/liatrio/autogov/pkg/certid"
	"github.com/stretchr/testify/assert"
)

// mustClient builds a *github.Client for tests, failing the test on construction error.
func mustClient(t *testing.T, opts ...github.ClientOptionsFunc) *github.Client {
	t.Helper()
	c, err := github.NewClient(opts...)
	if err != nil {
		t.Fatalf("github.NewClient: %v", err)
	}
	return c
}

func TestVerifyBlobs(t *testing.T) {
	ctx := context.Background()
	client := mustClient(t)

	tests := []struct {
		name      string
		opts      Options
		wantError bool
		errorMsg  string
	}{
		{
			name: "verify container with no blob paths",
			opts: Options{
				ArtifactDigest: "sha256:abc123",
				Repository:     "test/repo",
				CertIdentity:   "test-identity",
				CertIssuer:     "test-issuer",
				BlobPaths:      []string{},
			},
			wantError: true,
			errorMsg:  "failed to parse image reference",
		},
		{
			name: "verify single blob",
			opts: Options{
				Repository:   "test/repo",
				CertIdentity: "test-identity",
				CertIssuer:   "test-issuer",
				BlobPaths:    []string{"/nonexistent/file.txt"},
			},
			wantError: true,
			errorMsg:  "error getting attestations",
		},
		{
			name: "verify multiple blobs with error",
			opts: Options{
				Repository:   "test/repo",
				CertIdentity: "test-identity",
				CertIssuer:   "test-issuer",
				BlobPaths:    []string{"/nonexistent/file1.txt", "/nonexistent/file2.txt"},
			},
			wantError: true,
			errorMsg:  "error getting attestations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyBlobs(ctx, client, tt.opts)
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSetupCertIdentityValidation(t *testing.T) {
	tests := []struct {
		name                string
		certIdentityListURL string
		noCache             bool
		quiet               bool
		expectNil           bool
	}{
		{
			name:                "empty URL returns nil",
			certIdentityListURL: "",
			noCache:             false,
			quiet:               false,
			expectNil:           true,
		},
		{
			name:                "valid URL returns options",
			certIdentityListURL: "https://example.com/cert-identities.json",
			noCache:             false,
			quiet:               true,
			expectNil:           false,
		},
		{
			name:                "valid URL with cache disabled",
			certIdentityListURL: "https://example.com/cert-identities.json",
			noCache:             true,
			quiet:               true,
			expectNil:           false,
		},
		{
			name:                "valid URL with output",
			certIdentityListURL: "https://example.com/cert-identities.json",
			noCache:             false,
			quiet:               false,
			expectNil:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SetupCertIdentityValidation(tt.certIdentityListURL, tt.noCache, tt.quiet)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.certIdentityListURL, result.URL)
				assert.Equal(t, tt.noCache, result.DisableCache)
			}
		})
	}
}

func TestVerifyBlobsMultipleBlobs(t *testing.T) {
	ctx := context.Background()
	client := mustClient(t)

	opts := Options{
		Repository:   "test/repo",
		CertIdentity: "test-identity",
		CertIssuer:   "test-issuer",
		BlobPaths:    []string{"blob1", "blob2", "blob3"},
		Quiet:        false,
	}

	_, err := VerifyBlobs(ctx, client, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error getting attestations")
}

func TestVerifyBlobsQuietMode(t *testing.T) {
	ctx := context.Background()
	client := mustClient(t)

	opts := Options{
		Repository:   "test/repo",
		CertIdentity: "test-identity",
		CertIssuer:   "test-issuer",
		BlobPaths:    []string{"test.txt"},
		Quiet:        true, // test quiet mode
	}

	// will fail but we're testing quiet mode
	_, err := VerifyBlobs(ctx, client, opts)
	assert.Error(t, err)
}

func TestSetupCertIdentityValidationQuiet(t *testing.T) {
	// quiet mode enabled
	opts := SetupCertIdentityValidation("https://example.com/cert.json", false, true)
	assert.NotNil(t, opts)
	assert.Equal(t, "https://example.com/cert.json", opts.URL)
	assert.False(t, opts.DisableCache)
}

func TestSetupCertIdentityValidationCacheDisabled(t *testing.T) {
	// cache disabled and not quiet / covers line 90-92
	opts := SetupCertIdentityValidation("https://example.com/cert.json", true, false)
	assert.NotNil(t, opts)
	assert.Equal(t, "https://example.com/cert.json", opts.URL)
	assert.True(t, opts.DisableCache)
}

func TestVerifyBlobsWithCertIdentityValidation(t *testing.T) {
	ctx := context.Background()
	client := mustClient(t)

	certOpts := certid.DefaultOptions()
	certOpts.URL = "https://example.com/cert-identities.json"

	opts := Options{
		Repository:             "test/repo",
		CertIdentity:           "test-identity",
		CertIssuer:             "test-issuer",
		BlobPaths:              []string{},
		CertIdentityValidation: &certOpts,
		Quiet:                  true,
	}

	// will fail due to GitHub client requirement, but tests the cert validation path
	_, err := VerifyBlobs(ctx, client, opts)
	assert.Error(t, err)
}

func TestVerifyBlobsCertIdentityListFailsClosed(t *testing.T) {
	// a malformed identity list must fail closed in VerifyBlobs (online),
	// never silently fall through to accept-any (WithoutIdentitiesUnsafe).
	ctx := context.Background()
	client := mustClient(t)

	badList := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badList, []byte("not json"), 0644); err != nil {
		t.Fatalf("write bad list: %v", err)
	}

	certOpts := certid.DefaultOptions()
	certOpts.URL = badList
	certOpts.DisableCache = true

	// no --cert-identity, list only: the list alone must be resolved and enforced
	_, err := VerifyBlobs(ctx, client, Options{
		Repository:             "test/repo",
		BlobPaths:              []string{},
		CertIdentityValidation: &certOpts,
		Quiet:                  true,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolve accepted certificate identities")
}
