package attestations

import (
	"context"
	"fmt"

	"github.com/google/go-github/v81/github"
)

// example options
const (
	// cert identity patterns
	ExampleWorkflowMainRef   = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main"
	ExampleWorkflowTagRef    = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/tags/v1.0.0"
	ExampleWorkflowCommitRef = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@refs/pull/123/merge"
	ExampleWorkflowSHARef    = "https://github.com/OWNER/REPO/.github/workflows/rw-hp-attest-image.yaml@f1a9b0be784bc27ba9076d76b75025d77ba18919"
)

// example container/blob options
var (
	ExampleContainerOptions = Options{
		SourceRef:    "refs/heads/main",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/rw-hp-attest-image.yaml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		Quiet:        false,
	}

	ExampleBlobOptions = Options{
		BlobPath:     "/path/to/my/file.txt",
		SourceRef:    "refs/heads/main",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/rw-hp-attest-blob.yaml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		Quiet:        false,
	}
)

// demonstrates how to use the GetFromGitHub function
// uses the sigstore-go for attestation verification
// and automatically fetches GitHub's trusted root with fallback to embedded root
func ExampleGetFromGitHub() {
	// Create a mock client with a token
	client := github.NewClient(nil).WithAuthToken("mock-token")

	// Example 1: Verify a container image
	// The tool will automatically:
	// 1. Try to fetch GitHub's trusted root dynamically using 'gh attestation trusted-root'
	// 2. Fall back to embedded trusted root if dynamic fetch fails
	// 3. Use sigstore-go for verification with proper timestamp validation
	imageRef := "myorg/my-container-repo@sha256:1234567890123456789012345678901234567890123456789012345678901234"
	opts := Options{
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/verify.yml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		SourceRef:    "refs/heads/main",
	}

	_, err := GetFromGitHub(context.Background(), imageRef, client, opts)
	fmt.Printf("Container verification error: %v\n", err)

	// Example 2: Verify a blob
	// Blob verification also uses the same trusted root fetching logic
	blobOpts := Options{
		BlobPath:     "testdata/example.txt",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/verify.yml@refs/heads/main",
		CertIssuer:   DefaultCertIssuer,
		SourceRef:    "refs/heads/main",
	}

	_, err = GetFromGitHub(context.Background(), "", client, blobOpts)
	fmt.Printf("Blob verification error: %v\n", err)

	// Output:
	// Container verification error: failed to get manifest: failed to fetch manifest: GET https://ghcr.io/v2/myorg/my-container-repo/manifests/sha256:1234567890123456789012345678901234567890123456789012345678901234: UNAUTHORIZED: authentication required; [map[Action:pull Class:manifest Name:myorg/my-container-repo Type:repository]]
	// Blob verification error: failed to read blob: open testdata/example.txt: no such file or directory
}
