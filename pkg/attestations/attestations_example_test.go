package attestations

import (
	"context"
	"fmt"

	"github.com/google/go-github/v88/github"
)

// ExampleGetFromGitHub shows verifying GitHub attestations with sigstore-go (trusted
// root fetched dynamically, falling back to the embedded root). It is a compile-checked
// example only — it makes network calls, so it carries no // Output: and is not run.
func ExampleGetFromGitHub() {
	client, err := github.NewClient(github.WithAuthToken("mock-token"))
	if err != nil {
		fmt.Printf("failed to create GitHub client: %v\n", err)
		return
	}

	// verify a container image
	imageRef := "myorg/my-container-repo@sha256:1234567890123456789012345678901234567890123456789012345678901234"
	opts := Options{
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/verify.yml@f1a9b0be784bc27ba9076d76b75025d77ba18919",
		CertIssuer:   DefaultCertIssuer,
		SourceRef:    "refs/tags/v1.0.0",
	}
	_, err = GetFromGitHub(context.Background(), imageRef, client, opts)
	fmt.Printf("Container verification error: %v\n", err)

	// verify a blob
	blobOpts := Options{
		BlobPath:     "testdata/example.txt",
		CertIdentity: "https://github.com/myorg/myrepo/.github/workflows/verify.yml@f1a9b0be784bc27ba9076d76b75025d77ba18919",
		CertIssuer:   DefaultCertIssuer,
		SourceRef:    "refs/tags/v1.0.0",
	}
	_, err = GetFromGitHub(context.Background(), "", client, blobOpts)
	fmt.Printf("Blob verification error: %v\n", err)
}
