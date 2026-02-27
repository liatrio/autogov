package attestations

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v82/github"
	"github.com/liatrio/autogov/pkg/root"
)

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
				c = github.NewClient(nil).WithAuthToken(token)
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
			client := github.NewClient(nil).WithAuthToken(token)
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
			client:      github.NewClient(nil),
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
			client:      github.NewClient(nil),
			org:         "",
			artifactRef: validDigest,
			wantErr:     true,
			errMsg:      errMsgOrgRequired,
		},
		{
			name:        "nil artifact ref",
			client:      github.NewClient(nil),
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
			client:      github.NewClient(nil).WithAuthToken(token),
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
				client = github.NewClient(nil).WithAuthToken(token)
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
