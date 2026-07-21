package attestations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v89/github"
	"github.com/liatrio/autogov/pkg/certid"
	"github.com/liatrio/autogov/pkg/root"
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

const (
	testFileName              = "test.txt"
	testFileData              = "test data"
	testCertIdentity          = "https://github.com/liatrio/autogov/.github/workflows/test.yml@abc1234567890abcdef1234567890abcdef12345"
	verifyCertIdentity        = "https://github.com/liatrio/autogov/.github/workflows/verify.yml@def1234567890abcdef1234567890abcdef12345"
	testCertIssuer            = "https://token.actions.githubusercontent.com"
	testDigest                = "sha256:abc123def456789012345678901234567890123456789012345678901234"
	shortTestDigest           = "sha256:abc123"
	validTestDigest           = "sha256:1234567890123456789012345678901234567890123456789012345678901234"
	errMsgNilClient           = "nil client"
	errMsgClientRequired      = "github client is required"
	errMsgOrgRequired         = "github organization name is required"
	errMsgArtifactRefRequired = "artifact reference is required"
)

func newAttestationTestClient(t *testing.T, handler http.HandlerFunc) *github.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	baseURL := server.URL + "/"
	return mustClient(
		t,
		github.WithHTTPClient(server.Client()),
		github.WithURLs(&baseURL, nil),
	)
}

func assertAttestationRequest(t *testing.T, request *http.Request, expectedPage int) {
	t.Helper()
	if request.Method != http.MethodGet {
		t.Errorf("request method = %s, want %s", request.Method, http.MethodGet)
	}
	wantPath := "/orgs/test-org/attestations/" + validTestDigest
	if request.URL.Path != wantPath {
		t.Errorf("request path = %s, want %s", request.URL.Path, wantPath)
	}
	if got := request.URL.Query().Get("page"); got != strconv.Itoa(expectedPage) {
		t.Errorf("request page = %q, want %d", got, expectedPage)
	}
}

func writeAttestationPage(
	t *testing.T,
	w http.ResponseWriter,
	request *http.Request,
	attestations []*github.Attestation,
	nextPage int,
) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if nextPage != 0 {
		nextURL := fmt.Sprintf("http://%s%s?page=%d", request.Host, request.URL.Path, nextPage)
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", nextURL))
	}
	if err := json.NewEncoder(w).Encode(github.AttestationsResponse{Attestations: attestations}); err != nil {
		t.Errorf("encode attestation page: %v", err)
	}
}

func testAttestation(bundleData string) *github.Attestation {
	return &github.Attestation{Bundle: json.RawMessage(bundleData)}
}

func instantRetryConfig(attempts int, waited *[]time.Duration) attestationRetryConfig {
	return attestationRetryConfig{
		attempts:  attempts,
		baseDelay: time.Millisecond,
		wait: func(_ context.Context, delay time.Duration) error {
			*waited = append(*waited, delay)
			return nil
		},
	}
}

func getGitHubToken(t *testing.T) string {
	// check for gh tokens
	for _, envVar := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if token := os.Getenv(envVar); token != "" {
			return token
		}
	}
	t.Skip("No GitHub token found. Set GITHUB_TOKEN, GH_TOKEN, or GITHUB_AUTH_TOKEN")
	return ""
}

func TestGetFromGitHub(t *testing.T) {
	// skip if no GitHub token available
	token := getGitHubToken(t)

	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, testFileName)
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		imageRef string
		opts     Options
		client   *github.Client
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "invalid org",
			imageRef: "invalid-org/repo@" + testDigest,
			opts: Options{
				CertIdentity: testCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
		},
		{
			name:     "invalid digest",
			imageRef: "liatrio/repo@invalid-digest",
			opts: Options{
				CertIdentity: testCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
		},
		{
			name:     "with registry",
			imageRef: "ghcr.io/liatrio/repo@" + testDigest,
			opts: Options{
				CertIdentity: testCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
		},
		{
			name:     "with tag",
			imageRef: "liatrio/repo:latest@" + testDigest,
			opts: Options{
				CertIdentity: testCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
		},
		{
			name:     errMsgNilClient,
			imageRef: "liatrio/repo@" + validTestDigest,
			opts: Options{
				CertIdentity: testCertIdentity,
			},
			client:  nil,
			wantErr: true,
			errMsg:  errMsgClientRequired,
		},
		{
			name:     "empty cert identity with blob",
			imageRef: "",
			opts: Options{
				BlobPath: blobPath,
			},
			wantErr: true,
			errMsg:  "for blob verification, provide --repo, --cert-identity, or use offline mode with --attestations-path",
		},
		{
			name:     "invalid cert identity format with blob",
			imageRef: "",
			opts: Options{
				BlobPath:     blobPath,
				CertIdentity: "invalid-url",
			},
			wantErr: true,
			errMsg:  "invalid certificate identity format",
		},
		{
			name:     "missing_both_artifact_digest_and_blob_path",
			imageRef: "",
			opts: Options{
				CertIdentity: verifyCertIdentity,
			},
			wantErr: true,
			errMsg:  "artifact digest is required for container verification",
		},
		{
			name:     "empty artifact digest for container verification",
			imageRef: "",
			opts: Options{
				CertIdentity: testCertIdentity,
				BlobPath:     "",
			},
			wantErr: true,
			errMsg:  "artifact digest is required for container verification",
		},
		{
			name:     "invalid blob path",
			imageRef: "",
			opts: Options{
				CertIdentity: testCertIdentity,
				BlobPath:     "/nonexistent/path",
			},
			wantErr: true,
			errMsg:  "failed to read blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c *github.Client
			if tt.client == nil && tt.name != errMsgNilClient {
				c = mustClient(t, github.WithAuthToken(token))
			} else {
				c = tt.client
			}

			_, err := GetFromGitHub(context.Background(), tt.imageRef, c, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("GetFromGitHub() error = %v, want to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestGetFromGitHubWithBlob(t *testing.T) {
	// skip if no GitHub token available
	token := getGitHubToken(t)

	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, testFileName)
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name: "valid blob attestation",
			opts: Options{
				CertIdentity: testCertIdentity,
				CertIssuer:   testCertIssuer,
				BlobPath:     blobPath,
			},
			wantErr: true, // this is true because the test artifact doesn't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := mustClient(t, github.WithAuthToken(token))
			_, err := GetFromGitHub(context.Background(), "", client, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFromGitHub() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateInputs(t *testing.T) {
	validDigest, err := NewDigest(validTestDigest)
	if err != nil {
		t.Fatalf("failed to create digest: %v", err)
	}
	tests := []struct {
		name        string
		client      *github.Client
		org         string
		artifactRef *Digest
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid inputs",
			client:      mustClient(t),
			org:         "liatrio",
			artifactRef: validDigest,
			wantErr:     false,
		},
		{
			name:        errMsgNilClient,
			client:      nil,
			org:         "liatrio",
			artifactRef: validDigest,
			wantErr:     true,
			errMsg:      errMsgClientRequired,
		},
		{
			name:        "empty org",
			client:      mustClient(t),
			org:         "",
			artifactRef: validDigest,
			wantErr:     true,
			errMsg:      errMsgOrgRequired,
		},
		{
			name:        "nil artifact ref",
			client:      mustClient(t),
			org:         "liatrio",
			artifactRef: nil,
			wantErr:     true,
			errMsg:      errMsgArtifactRefRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInputs(tt.client, tt.org, tt.artifactRef)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInputs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("validateInputs() error msg = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestSetDefaultOptionsExtended(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		want    *Options
		wantErr bool
	}{
		{
			name: "all options provided",
			opts: &Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			want: &Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: false,
		},
		{
			name: "missing cert issuer",
			opts: &Options{
				CertIdentity: verifyCertIdentity,
			},
			want: &Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setDefaultOptions(*tt.opts)
			if got.CertIdentity != tt.want.CertIdentity {
				t.Errorf("setDefaultOptions() CertIdentity = %v, want %v", got.CertIdentity, tt.want.CertIdentity)
			}
			if got.CertIssuer != tt.want.CertIssuer {
				t.Errorf("setDefaultOptions() CertIssuer = %v, want %v", got.CertIssuer, tt.want.CertIssuer)
			}
		})
	}
}

func TestVerifyAttestation(t *testing.T) {
	// create temp test file
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	// create verify dir
	cacheDir := filepath.Join(tmpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}

	// get trusted root with fallback
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	// write trusted root
	trust := filepath.Join(cacheDir, "github-trusted-root.json")
	if err := os.WriteFile(trust, trustedRootData, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		att     *github.Attestation
		opts    Options
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid bundle",
			att: &github.Attestation{
				Bundle: json.RawMessage(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9hdHRlc3RhdGlvbi92MC4xIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7fX0=","signatures":[{"sig":"MEUCIQD/GAXOMtmvjC3/JzJJRZWJ0B8DM7WGf5GbCt5PvcF5RQIgYBwL/lR8YGYhUQWZWYDJ2UJKZyK4QxgWbcIj+KVxCkE="}]}`),
			},
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle",
		},
		{
			name: "nil attestation",
			att:  nil,
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
			errMsg:  "attestation is nil",
		},
		{
			name: "invalid bundle json",
			att: &github.Attestation{
				Bundle: json.RawMessage(`invalid json`),
			},
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle",
		},
		{
			name: "provenance with expected ref mismatch",
			att: &github.Attestation{
				Bundle: json.RawMessage(`{
					"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
					"dsseEnvelope": {
						"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9wcm92ZW5hbmNlL3YxIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7ImJ1aWxkRGVmaW5pdGlvbiI6eyJleHRlcm5hbFBhcmFtZXRlcnMiOnsid29ya2Zsb3ciOnsicmVmIjoicmVmcy9oZWFkcy9tYWluIn19fX19",
						"signatures": [{"sig": "MEUCIQD/GAXOMtmvjC3/JzJJRZWJ0B8DM7WGf5GbCt5PvcF5RQIgYBwL/lR8YGYhUQWZWYDJ2UJKZyK4QxgWbcIj+KVxCkE="}]
					}
				}`),
			},
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
				SourceRef:    "refs/heads/other",
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle: invalid bundle: validation error: missing verification material",
		},
		{
			name: "invalid signature",
			att: &github.Attestation{
				Bundle: json.RawMessage(`{
					"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
					"dsseEnvelope": {
						"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NsLmRldi9hdHRlc3RhdGlvbi92MC4xIiwic3ViamVjdCI6W3sibmFtZSI6InNoYTI1NjphYmMxMjMiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7fX0=",
						"signatures": [{"sig": "invalid"}]
					}
				}`),
			},
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
			},
			wantErr: true,
			errMsg:  "failed to unmarshal bundle: invalid bundle: validation error: missing verification material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifyAttestation(tt.att, blobPath, trust, 0, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyAttestation() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("verifyAttestation() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestGetFromGitHubCertIdentityListFailsClosed(t *testing.T) {
	// at the attestations layer, a configured but malformed identity list must
	// fail closed in GetFromGitHub's fallback resolution — never silently ignored or
	// degraded to accept-any. (resolution runs before any GitHub API call, so no token
	// is required to exercise this path.)
	badList := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badList, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	certOpts := certid.DefaultOptions()
	certOpts.URL = badList
	certOpts.DisableCache = true

	_, err := GetFromGitHub(context.Background(), "liatrio/repo@"+validTestDigest, nil, Options{
		CertIdentityValidation: &certOpts,
		Quiet:                  true,
	})
	if err == nil {
		t.Fatal("expected fail-closed error for malformed cert-identity list, got nil")
	}
	if !strings.Contains(err.Error(), "certificate identities") {
		t.Errorf("expected a certificate-identity resolution error (list enforced, not ignored), got: %v", err)
	}
}

func TestHandleBlobVerification(t *testing.T) {
	// skip if no GitHub token available
	token := getGitHubToken(t)

	// create test files and directories
	tmpDir := t.TempDir()
	validBlobPath := filepath.Join(tmpDir, "valid.txt")
	if err := os.WriteFile(validBlobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	// create test digest with non-nil value
	validDigest := &Digest{value: "sha256:abc123def456789012345678901234567890123456789012345678901234"}

	tests := []struct {
		name        string
		artifactRef *Digest
		org         string
		client      *github.Client
		opts        Options
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid blob verification",
			artifactRef: validDigest,
			org:         "liatrio",
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
				BlobPath:     validBlobPath,
			},
			wantErr: true, // expect error since we don't have real attestations
		},
		{
			name:        "invalid blob path",
			artifactRef: validDigest,
			org:         "liatrio",
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
				BlobPath:     "/nonexistent/path",
			},
			wantErr: true,
			errMsg:  "failed to read blob",
		},
		{
			name:        "missing blob path",
			artifactRef: validDigest,
			org:         "liatrio",
			client:      mustClient(t, github.WithAuthToken(token)),
			opts: Options{
				CertIdentity: verifyCertIdentity,
				CertIssuer:   testCertIssuer,
				BlobPath:     "",
			},
			wantErr: true,
			errMsg:  "blob path is required",
		},
		{
			name:        errMsgNilClient,
			artifactRef: validDigest,
			org:         "liatrio",
			client:      nil,
			opts: Options{
				CertIdentity: verifyCertIdentity,
				BlobPath:     validBlobPath,
			},
			wantErr: true,
			errMsg:  errMsgClientRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.client
			if tt.client == nil && tt.name != errMsgNilClient {
				client = mustClient(t, github.WithAuthToken(token))
			}
			_, err := handleBlobVerification(context.Background(), tt.artifactRef, tt.org, client, tt.opts, t.TempDir())
			if (err != nil) != tt.wantErr {
				t.Errorf("handleBlobVerification() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("handleBlobVerification() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		name       string
		ref        string
		wantOrg    string
		wantRepo   string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "valid ref",
			ref:        "liatrio/repo@" + shortTestDigest,
			wantOrg:    "liatrio",
			wantRepo:   "repo",
			wantDigest: shortTestDigest,
			wantErr:    false,
		},
		{
			name:       "with registry",
			ref:        "ghcr.io/liatrio/repo@" + shortTestDigest,
			wantOrg:    "liatrio",
			wantRepo:   "repo",
			wantDigest: shortTestDigest,
			wantErr:    false,
		},
		{
			name:       "with tag",
			ref:        "liatrio/repo:latest@" + shortTestDigest,
			wantOrg:    "liatrio",
			wantRepo:   "repo",
			wantDigest: shortTestDigest,
			wantErr:    false,
		},
		{
			name:    "no digest",
			ref:     "liatrio/repo",
			wantErr: true,
		},
		{
			name:    "invalid format",
			ref:     "invalid@" + shortTestDigest,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo, digest, err := ParseImageRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImageRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if org != tt.wantOrg {
					t.Errorf("ParseImageRef() org = %v, want %v", org, tt.wantOrg)
				}
				if repo != tt.wantRepo {
					t.Errorf("ParseImageRef() repo = %v, want %v", repo, tt.wantRepo)
				}
				if digest != tt.wantDigest {
					t.Errorf("ParseImageRef() digest = %v, want %v", digest, tt.wantDigest)
				}
			}
		})
	}
}

func TestNewDigest(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "valid digest",
			value:   validTestDigest,
			wantErr: false,
		},
		{
			name:    "empty digest for blob",
			value:   "",
			wantErr: false,
		},
		{
			name:    "invalid prefix",
			value:   "invalid:abc123",
			wantErr: true,
		},
		{
			name:    "invalid length",
			value:   "sha256:short",
			wantErr: true,
		},
		{
			name:    "missing colon",
			value:   "sha256abc123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDigest(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && d.String() != tt.value {
				t.Errorf("NewDigest() = %v, want %v", d.String(), tt.value)
			}
		})
	}
}

func TestParseOrgRepoFromWorkflowURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantOrg  string
		wantRepo string
		wantErr  bool
	}{
		{
			name:     "valid workflow url",
			url:      testCertIdentity,
			wantOrg:  "liatrio",
			wantRepo: "autogov",
			wantErr:  false,
		},
		{
			name:    "invalid url format",
			url:     "invalid-url",
			wantErr: true,
		},
		{
			name:    "missing org/repo",
			url:     "https://github.com/",
			wantErr: true,
		},
		{
			name:    "wrong hostname",
			url:     "https://gitlab.com/org/repo/.github/workflows/test.yml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo, err := parseOrgRepoFromWorkflowURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOrgRepoFromWorkflowURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if org != tt.wantOrg {
					t.Errorf("parseOrgRepoFromWorkflowURL() org = %v, want %v", org, tt.wantOrg)
				}
				if repo != tt.wantRepo {
					t.Errorf("parseOrgRepoFromWorkflowURL() repo = %v, want %v", repo, tt.wantRepo)
				}
			}
		})
	}
}

func TestSourceRefMismatchError(t *testing.T) {
	err := &SourceRefMismatchError{
		Found:    "refs/heads/feature",
		Expected: "refs/heads/main",
	}

	expected := "source repository ref refs/heads/feature does not match expected refs/heads/main"
	if err.Error() != expected {
		t.Errorf("SourceRefMismatchError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestDigestString(t *testing.T) {
	tests := []struct {
		name   string
		digest *Digest
		want   string
	}{
		{
			name:   "valid digest",
			digest: &Digest{value: validTestDigest},
			want:   validTestDigest,
		},
		{
			name:   "empty digest",
			digest: &Digest{value: ""},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.digest.String(); got != tt.want {
				t.Errorf("Digest.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOptionsDefaults(t *testing.T) {
	// Test that Options struct can be created with various fields
	opts := Options{
		BlobPath:     "/path/to/blob",
		Repository:   "owner/repo",
		SourceRef:    "refs/heads/main",
		CertIdentity: testCertIdentity,
		CertIssuer:   testCertIssuer,
		Quiet:        true,
	}

	if opts.BlobPath != "/path/to/blob" {
		t.Error("Options.BlobPath not set correctly")
	}
	if opts.Repository != "owner/repo" {
		t.Error("Options.Repository not set correctly")
	}
	if opts.SourceRef != "refs/heads/main" {
		t.Error("Options.SourceRef not set correctly")
	}
	if opts.CertIdentity != testCertIdentity {
		t.Error("Options.CertIdentity not set correctly")
	}
	if opts.CertIssuer != testCertIssuer {
		t.Error("Options.CertIssuer not set correctly")
	}
	if !opts.Quiet {
		t.Error("Options.Quiet not set correctly")
	}
}

func TestVerifyAttestationNilAttestationDirect(t *testing.T) {
	// Test nil attestation directly
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	// Get trusted root
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	trustPath := filepath.Join(tmpDir, "trusted-root.json")
	if err := os.WriteFile(trustPath, trustedRootData, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		CertIdentity: testCertIdentity,
		CertIssuer:   testCertIssuer,
	}

	_, err = verifyAttestation(nil, blobPath, trustPath, 0, opts)
	if err == nil {
		t.Error("verifyAttestation() with nil attestation expected error")
	}
	if !strings.Contains(err.Error(), "attestation is nil") {
		t.Errorf("verifyAttestation() error = %v, want error containing 'attestation is nil'", err)
	}
}

func TestVerifyAttestationEmptyBundle(t *testing.T) {
	// Test empty bundle
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	// Get trusted root
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	trustPath := filepath.Join(tmpDir, "trusted-root.json")
	if err := os.WriteFile(trustPath, trustedRootData, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		CertIdentity: testCertIdentity,
		CertIssuer:   testCertIssuer,
	}

	att := &github.Attestation{
		Bundle: json.RawMessage(`{}`),
	}

	_, err = verifyAttestation(att, blobPath, trustPath, 0, opts)
	if err == nil {
		t.Error("verifyAttestation() with empty bundle expected error")
	}
}

func TestVerifyAttestationNilBundle(t *testing.T) {
	// Test nil bundle in attestation
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	// Get trusted root
	trustedRootData, err := root.GetTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	trustPath := filepath.Join(tmpDir, "trusted-root.json")
	if err := os.WriteFile(trustPath, trustedRootData, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		CertIdentity: testCertIdentity,
		CertIssuer:   testCertIssuer,
	}

	att := &github.Attestation{
		Bundle: nil,
	}

	_, err = verifyAttestation(att, blobPath, trustPath, 0, opts)
	if err == nil {
		t.Error("verifyAttestation() with nil bundle expected error")
	}
}

func TestParseImageRefAdditional(t *testing.T) {
	// Additional test cases for ParseImageRef
	tests := []struct {
		name       string
		ref        string
		wantOrg    string
		wantRepo   string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "simple org/repo",
			ref:        "myorg/myrepo@sha256:abc123",
			wantOrg:    "myorg",
			wantRepo:   "myrepo",
			wantDigest: "sha256:abc123",
			wantErr:    false,
		},
		{
			name:    "nested path repo (not supported)",
			ref:     "ghcr.io/org/repo/subpath@sha256:abc123",
			wantErr: true,
		},
		{
			name:    "missing @ separator",
			ref:     "org/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo, digest, err := ParseImageRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImageRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if org != tt.wantOrg {
					t.Errorf("ParseImageRef() org = %v, want %v", org, tt.wantOrg)
				}
				if repo != tt.wantRepo {
					t.Errorf("ParseImageRef() repo = %v, want %v", repo, tt.wantRepo)
				}
				if digest != tt.wantDigest {
					t.Errorf("ParseImageRef() digest = %v, want %v", digest, tt.wantDigest)
				}
			}
		})
	}
}

func TestVerifyAttestationWithInvalidTrustedRoot(t *testing.T) {
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	// Create invalid trusted root
	invalidTrustPath := filepath.Join(tmpDir, "invalid-root.json")
	if err := os.WriteFile(invalidTrustPath, []byte("invalid json"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		CertIdentity: testCertIdentity,
		CertIssuer:   testCertIssuer,
	}

	att := &github.Attestation{
		Bundle: json.RawMessage(`{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1"}`),
	}

	_, err := verifyAttestation(att, blobPath, invalidTrustPath, 0, opts)
	if err == nil {
		t.Error("verifyAttestation() with invalid trusted root expected error")
	}
}

func TestVerifyAttestationWithNonexistentTrustedRoot(t *testing.T) {
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(blobPath, []byte(testFileData), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		CertIdentity: testCertIdentity,
		CertIssuer:   testCertIssuer,
	}

	att := &github.Attestation{
		Bundle: json.RawMessage(`{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1"}`),
	}

	_, err := verifyAttestation(att, blobPath, "/nonexistent/path/root.json", 0, opts)
	if err == nil {
		t.Error("verifyAttestation() with nonexistent trusted root expected error")
	}
}

func TestFetchGitHubAttestationsRetriesUnavailableBundle(t *testing.T) {
	var calls atomic.Int32
	available := testAttestation(`{"bundle":"available"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		if calls.Add(1) == 1 {
			writeAttestationPage(t, w, request, []*github.Attestation{{Bundle: nil}}, 0)
			return
		}
		writeAttestationPage(t, w, request, []*github.Attestation{available}, 0)
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(5, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("request count = %d, want 2", calls.Load())
	}
	if len(waited) != 1 || waited[0] != time.Millisecond {
		t.Errorf("retry delays = %v, want [1ms]", waited)
	}
	if len(got) != 1 || string(got[0].Bundle) != string(available.Bundle) {
		t.Errorf("returned attestations = %#v, want complete second snapshot", got)
	}
}

func TestFetchGitHubAttestationsExhaustsBoundedRetries(t *testing.T) {
	var calls atomic.Int32
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		calls.Add(1)
		writeAttestationPage(t, w, request, []*github.Attestation{nil}, 0)
	})

	var waited []time.Duration
	_, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(attestationFetchAttempts, &waited),
	)
	if err == nil {
		t.Fatal("fetchGitHubAttestationsWithRetry() error = nil, want bounded exhaustion")
	}
	if calls.Load() != attestationFetchAttempts {
		t.Errorf("request count = %d, want %d", calls.Load(), attestationFetchAttempts)
	}
	wantDelays := []time.Duration{
		time.Millisecond,
		2 * time.Millisecond,
		4 * time.Millisecond,
		8 * time.Millisecond,
	}
	if len(waited) != len(wantDelays) {
		t.Fatalf("retry delays = %v, want %v", waited, wantDelays)
	}
	for index := range wantDelays {
		if waited[index] != wantDelays[index] {
			t.Errorf("retry delay %d = %v, want %v", index, waited[index], wantDelays[index])
		}
	}
	if !strings.Contains(err.Error(), "attestation list did not stabilize after 5 attempts") ||
		!strings.Contains(err.Error(), "not yet available") ||
		!strings.Contains(err.Error(), "retry verification shortly") {
		t.Errorf("exhaustion error = %v, want stable actionable guidance", err)
	}
}

func TestFetchGitHubAttestationsCancellationDuringWait(t *testing.T) {
	var calls atomic.Int32
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		calls.Add(1)
		writeAttestationPage(t, w, request, []*github.Attestation{{Bundle: nil}}, 0)
	})

	ctx, cancel := context.WithCancel(context.Background())
	waitEntered := make(chan struct{})
	config := attestationRetryConfig{
		attempts:  5,
		baseDelay: time.Hour,
		wait: func(waitCtx context.Context, _ time.Duration) error {
			close(waitEntered)
			cancel()
			<-waitCtx.Done()
			return waitCtx.Err()
		},
	}

	_, err := fetchGitHubAttestationsWithRetry(ctx, client, "test-org", validTestDigest, config)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v, want context canceled", err)
	}
	select {
	case <-waitEntered:
	default:
		t.Fatal("retry waiter was not entered")
	}
	if calls.Load() != 1 {
		t.Errorf("request count = %d, want 1", calls.Load())
	}
}

func TestWaitForAttestationRetryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- waitForAttestationRetry(ctx, time.Minute)
	}()

	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waitForAttestationRetry() error = %v, want context canceled", err)
		}
	case <-watchdog.C:
		t.Fatal("waitForAttestationRetry() did not stop after context cancellation")
	}
}

func TestFetchGitHubAttestationsDoesNotRetryAPIError(t *testing.T) {
	var calls atomic.Int32
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		calls.Add(1)
		http.Error(w, "temporary server failure", http.StatusInternalServerError)
	})

	var waited []time.Duration
	_, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(5, &waited),
	)
	if err == nil || !strings.Contains(err.Error(), "failed to list attestations") {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v, want list error", err)
	}
	if calls.Load() != 1 {
		t.Errorf("request count = %d, want 1", calls.Load())
	}
	if len(waited) != 0 {
		t.Errorf("retry delays = %v, want none", waited)
	}
}

func TestFetchGitHubAttestationsDoesNotRetryLaterPageAPIError(t *testing.T) {
	var calls atomic.Int32
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			assertAttestationRequest(t, request, 1)
			writeAttestationPage(t, w, request, []*github.Attestation{testAttestation(`{"id":"first"}`)}, 2)
			return
		}
		assertAttestationRequest(t, request, 2)
		http.Error(w, "later page failure", http.StatusBadGateway)
	})

	var waited []time.Duration
	_, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(5, &waited),
	)
	if err == nil || !strings.Contains(err.Error(), "failed to list attestations") {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v, want list error", err)
	}
	if calls.Load() != 2 {
		t.Errorf("request count = %d, want 2", calls.Load())
	}
	if len(waited) != 0 {
		t.Errorf("retry delays = %v, want none", waited)
	}
}

func TestFetchGitHubAttestationsReturnsMalformedNonNullWithoutRetry(t *testing.T) {
	var calls atomic.Int32
	malformed := testAttestation(`"invalid json"`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		calls.Add(1)
		writeAttestationPage(t, w, request, []*github.Attestation{malformed}, 0)
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(5, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 1 || len(waited) != 0 {
		t.Errorf("requests = %d, waits = %v; want one request and no retry", calls.Load(), waited)
	}
	_, _, _, _, err = parseAttestationBundle(got[0])
	if err == nil || !strings.Contains(err.Error(), "failed to unmarshal bundle") {
		t.Errorf("parseAttestationBundle() error = %v, want existing parse failure", err)
	}
}

func TestFetchGitHubAttestationsRetriesWholePaginatedSnapshot(t *testing.T) {
	var calls atomic.Int32
	first := testAttestation(`{"id":"first"}`)
	second := testAttestation(`{"id":"second"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		call := int(calls.Add(1))
		wantPage := 1
		if call%2 == 0 {
			wantPage = 2
		}
		assertAttestationRequest(t, request, wantPage)

		switch call {
		case 1, 3:
			writeAttestationPage(t, w, request, []*github.Attestation{first}, 2)
		case 2:
			writeAttestationPage(t, w, request, []*github.Attestation{{Bundle: nil}}, 0)
		case 4:
			writeAttestationPage(t, w, request, []*github.Attestation{second}, 0)
		default:
			t.Errorf("unexpected request %d", call)
		}
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(5, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 4 || len(waited) != 1 {
		t.Errorf("requests = %d, waits = %v; want four requests and one wait", calls.Load(), waited)
	}
	if len(got) != 2 || string(got[0].Bundle) != string(first.Bundle) || string(got[1].Bundle) != string(second.Bundle) {
		t.Errorf("returned snapshot = %#v, want complete second two-page snapshot", got)
	}
}

func TestFetchGitHubAttestationsDeduplicatesAvailableOverlapForContinuity(t *testing.T) {
	var calls atomic.Int32
	first := testAttestation(`{"id":"first"}`)
	second := testAttestation(`{"id":"second"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		call := int(calls.Add(1))
		wantPage := 1
		if call%2 == 0 {
			wantPage = 2
		}
		assertAttestationRequest(t, request, wantPage)

		switch call {
		case 1, 3:
			writeAttestationPage(t, w, request, []*github.Attestation{first}, 2)
		case 2:
			writeAttestationPage(t, w, request, []*github.Attestation{first, {Bundle: nil}}, 0)
		case 4:
			writeAttestationPage(t, w, request, []*github.Attestation{second}, 0)
		default:
			t.Errorf("unexpected request %d", call)
		}
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(3, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 4 || len(waited) != 1 {
		t.Errorf("requests = %d, waits = %v; want four requests and one wait", calls.Load(), waited)
	}
	if len(got) != 2 {
		t.Fatalf("returned attestation count = %d, want untouched complete snapshot of 2", len(got))
	}
}

func TestFetchGitHubAttestationsRetriesLostDistinctIdentity(t *testing.T) {
	var calls atomic.Int32
	first := testAttestation(`{"id":"first"}`)
	second := testAttestation(`{"id":"second"}`)
	third := testAttestation(`{"id":"third"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		switch calls.Add(1) {
		case 1:
			writeAttestationPage(t, w, request, []*github.Attestation{first, second, {Bundle: nil}}, 0)
		case 2:
			writeAttestationPage(t, w, request, []*github.Attestation{first, third, third}, 0)
		case 3:
			writeAttestationPage(t, w, request, []*github.Attestation{first, second, third}, 0)
		default:
			t.Error("unexpected request")
		}
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(3, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 3 || len(waited) != 2 {
		t.Errorf("requests = %d, waits = %v; want three requests and two waits", calls.Load(), waited)
	}
	if len(got) != 3 {
		t.Errorf("returned attestation count = %d, want 3", len(got))
	}
}

func TestFetchGitHubAttestationsCanonicalizesIdentity(t *testing.T) {
	var calls atomic.Int32
	firstEncoding := testAttestation(`{"a":1,"b":{"c":2}}`)
	secondEncoding := testAttestation(` { "b": { "c": 2 }, "a": 1 } `)
	firstEncoding.RepositoryID = 1
	secondEncoding.RepositoryID = 2
	replacement := testAttestation(`{"id":"replacement"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		if calls.Add(1) == 1 {
			writeAttestationPage(t, w, request, []*github.Attestation{firstEncoding, {Bundle: nil}}, 0)
			return
		}
		writeAttestationPage(t, w, request, []*github.Attestation{secondEncoding, replacement}, 0)
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(3, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 2 || len(waited) != 1 {
		t.Errorf("requests = %d, waits = %v; want two requests and one wait", calls.Load(), waited)
	}
	if len(got) != 2 || got[0].RepositoryID != secondEncoding.RepositoryID {
		t.Errorf("returned snapshot did not preserve the complete response encoding: %#v", got)
	}
}

func TestFetchGitHubAttestationsRejectsOneResolutionForTwoUnavailableRecords(t *testing.T) {
	var calls atomic.Int32
	resolved := testAttestation(`{"id":"resolved"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		if calls.Add(1) == 1 {
			writeAttestationPage(t, w, request, []*github.Attestation{{Bundle: nil}, {Bundle: json.RawMessage(`null`)}}, 0)
			return
		}
		writeAttestationPage(t, w, request, []*github.Attestation{resolved}, 0)
	})

	var waited []time.Duration
	_, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(2, &waited),
	)
	if err == nil {
		t.Fatal("fetchGitHubAttestationsWithRetry() error = nil, want incomplete resolution rejection")
	}
	if calls.Load() != 2 || len(waited) != 1 {
		t.Errorf("requests = %d, waits = %v; want two requests and one wait", calls.Load(), waited)
	}
	if !strings.Contains(err.Error(), "observed minimum of 2") {
		t.Errorf("error = %v, want two-record evidence lower bound", err)
	}
}

func TestFetchGitHubAttestationsEventuallyResolvesTwoUnavailableRecords(t *testing.T) {
	var calls atomic.Int32
	first := testAttestation(`{"id":"first"}`)
	second := testAttestation(`{"id":"second"}`)
	client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
		assertAttestationRequest(t, request, 1)
		switch calls.Add(1) {
		case 1:
			writeAttestationPage(t, w, request, []*github.Attestation{{Bundle: nil}, {Bundle: json.RawMessage(` null `)}}, 0)
		case 2:
			writeAttestationPage(t, w, request, []*github.Attestation{first}, 0)
		case 3:
			writeAttestationPage(t, w, request, []*github.Attestation{first, second}, 0)
		default:
			t.Error("unexpected request")
		}
	})

	var waited []time.Duration
	got, err := fetchGitHubAttestationsWithRetry(
		context.Background(),
		client,
		"test-org",
		validTestDigest,
		instantRetryConfig(3, &waited),
	)
	if err != nil {
		t.Fatalf("fetchGitHubAttestationsWithRetry() error = %v", err)
	}
	if calls.Load() != 3 || len(waited) != 2 {
		t.Errorf("requests = %d, waits = %v; want three requests and two waits", calls.Load(), waited)
	}
	if len(got) != 2 {
		t.Errorf("returned attestation count = %d, want 2", len(got))
	}
}

func TestListAllGitHubAttestationsRejectsInvalidPageProgress(t *testing.T) {
	tests := []struct {
		name          string
		nextPages     map[int]int
		wantCalls     int32
		wantErrorText string
	}{
		{
			name:          "repeated current page",
			nextPages:     map[int]int{1: 1},
			wantCalls:     1,
			wantErrorText: "next page 1 was already visited",
		},
		{
			name:          "cycle to visited page",
			nextPages:     map[int]int{1: 2, 2: 1},
			wantCalls:     2,
			wantErrorText: "next page 1 was already visited",
		},
		{
			name:          "non-contiguous next page",
			nextPages:     map[int]int{1: 3},
			wantCalls:     1,
			wantErrorText: "next page 3 is not contiguous after page 1",
		},
		{
			name:          "negative next page",
			nextPages:     map[int]int{1: -1},
			wantCalls:     1,
			wantErrorText: "next page -1 from page 1 is not positive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			client := newAttestationTestClient(t, func(w http.ResponseWriter, request *http.Request) {
				page, err := strconv.Atoi(request.URL.Query().Get("page"))
				if err != nil {
					t.Errorf("parse request page: %v", err)
					return
				}
				assertAttestationRequest(t, request, page)
				calls.Add(1)
				writeAttestationPage(t, w, request, []*github.Attestation{testAttestation(`{"id":"page"}`)}, test.nextPages[page])
			})

			_, err := listAllGitHubAttestations(context.Background(), client, "test-org", validTestDigest)
			if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Errorf("listAllGitHubAttestations() error = %v, want %q", err, test.wantErrorText)
			}
			if calls.Load() != test.wantCalls {
				t.Errorf("request count = %d, want %d", calls.Load(), test.wantCalls)
			}
		})
	}
}

func TestUnavailableAttestationBundleClassificationAndParsing(t *testing.T) {
	tests := []struct {
		name        string
		attestation *github.Attestation
		unavailable bool
	}{
		{name: "nil attestation", attestation: nil, unavailable: true},
		{name: "nil bundle", attestation: &github.Attestation{Bundle: nil}, unavailable: true},
		{name: "empty bundle", attestation: testAttestation(""), unavailable: true},
		{name: "whitespace bundle", attestation: testAttestation(" \n\t "), unavailable: true},
		{name: "literal null", attestation: testAttestation("null"), unavailable: true},
		{name: "whitespace null", attestation: testAttestation(" \n null\t"), unavailable: true},
		{name: "non-null object", attestation: testAttestation(`{}`), unavailable: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isAttestationBundleUnavailable(test.attestation); got != test.unavailable {
				t.Errorf("isAttestationBundleUnavailable() = %t, want %t", got, test.unavailable)
			}
			if !test.unavailable {
				return
			}

			_, _, _, _, err := parseAttestationBundle(test.attestation)
			if err == nil || err.Error() != attestationBundleUnavailableError {
				t.Errorf("parseAttestationBundle() error = %v, want %q", err, attestationBundleUnavailableError)
			}
		})
	}
}

func TestCanonicalAttestationBundleIdentity(t *testing.T) {
	first := json.RawMessage(`{"a":1,"b":{"c":2}}`)
	reordered := json.RawMessage("  { \"b\": { \"c\": 2 }, \"a\": 1 }\n")
	if got, want := canonicalAttestationBundleIdentity(first), canonicalAttestationBundleIdentity(reordered); got != want {
		t.Errorf("canonical identities differ: %q != %q", got, want)
	}

	if got := canonicalAttestationBundleIdentity(json.RawMessage("  invalid json \n")); got != "invalid json" {
		t.Errorf("malformed fallback identity = %q, want trimmed raw data", got)
	}
	if got := canonicalAttestationBundleIdentity(json.RawMessage(`{"a":1} {"b":2}`)); got != `{"a":1} {"b":2}` {
		t.Errorf("trailing JSON fallback identity = %q, want trimmed raw data", got)
	}
}

func TestAttestationSnapshotEvidenceCountsUnavailableRecordsIndividually(t *testing.T) {
	duplicate := testAttestation(`{"id":"duplicate"}`)
	identities, unavailableCount := attestationSnapshotEvidence([]*github.Attestation{
		duplicate,
		duplicate,
		nil,
		{Bundle: nil},
		{Bundle: json.RawMessage(` null `)},
	})
	if len(identities) != 1 {
		t.Errorf("distinct available identities = %d, want 1", len(identities))
	}
	if unavailableCount != 3 {
		t.Errorf("unavailable record count = %d, want 3", unavailableCount)
	}
}

func TestFetchGitHubAttestationsRejectsInvalidRetryConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        attestationRetryConfig
		wantErrorText string
	}{
		{
			name:          "no attempts",
			config:        attestationRetryConfig{attempts: 0, wait: waitForAttestationRetry},
			wantErrorText: "attempts must be positive",
		},
		{
			name:          "negative delay",
			config:        attestationRetryConfig{attempts: 1, baseDelay: -time.Second, wait: waitForAttestationRetry},
			wantErrorText: "base delay must not be negative",
		},
		{
			name:          "missing waiter",
			config:        attestationRetryConfig{attempts: 1},
			wantErrorText: "wait function is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := fetchGitHubAttestationsWithRetry(
				context.Background(),
				mustClient(t),
				"test-org",
				validTestDigest,
				test.config,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Errorf("fetchGitHubAttestationsWithRetry() error = %v, want %q", err, test.wantErrorText)
			}
		})
	}
}
