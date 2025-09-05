package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// handles VSA storage and retrieval using ORAS-Go
type VSAStorage struct {
	repo *remote.Repository
}

// creates a new VSA storage instance for a specific repository
func NewVSAStorage(repoRef string) (*VSAStorage, error) {
	repo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// authentication config similar to attestations.go
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
	}

	return &VSAStorage{repo: repo}, nil
}

// creates a VSA storage instance with authentication
func NewVSAStorageWithAuth(repoRef, username, token string) (*VSAStorage, error) {
	repo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// authentication config
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(repoRef, auth.Credential{
			Username: username,
			Password: token,
		}),
	}

	return &VSAStorage{repo: repo}, nil
}

// stores a VSA as a manifest in the registry
func (s *VSAStorage) StoreVSA(ctx context.Context, vsa *vsa.VSA, tag string) error {
	// VSA to JSON
	vsaBytes, err := json.Marshal(vsa)
	if err != nil {
		return fmt.Errorf("failed to marshal VSA: %w", err)
	}

	// calculate digest
	hash := sha256.Sum256(vsaBytes)
	vsaDigest := digest.NewDigestFromBytes(digest.SHA256, hash[:])

	// create descriptor for VSA
	desc := ocispec.Descriptor{
		MediaType: "application/vnd.in-toto+json",
		Digest:    vsaDigest,
		Size:      int64(len(vsaBytes)),
		Annotations: map[string]string{
			"org.opencontainers.image.title":        "Verification Summary Attestation",
			"dev.slsa.verification_summary.version": "v1",
		},
	}

	// push VSA content as blob
	if err := s.repo.Blobs().Push(ctx, desc, bytes.NewReader(vsaBytes)); err != nil {
		return fmt.Errorf("failed to push VSA blob: %w", err)
	}

	// create manifest
	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", // empty config
			Size:      2,
		},
		Layers: []ocispec.Descriptor{desc},
	}
	manifest.SchemaVersion = 2

	// marshal manifest
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// push manifest
	manifestDigest := digest.FromBytes(manifestBytes)
	manifestDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      int64(len(manifestBytes)),
	}

	if err := s.repo.Manifests().Push(ctx, manifestDesc, bytes.NewReader(manifestBytes)); err != nil {
		return fmt.Errorf("failed to push manifest: %w", err)
	}

	// tag the manifest using reference
	if err := s.repo.PushReference(ctx, manifestDesc, bytes.NewReader(manifestBytes), tag); err != nil {
		return fmt.Errorf("failed to tag VSA: %w", err)
	}

	return nil
}

// retrieves a VSA from the registry
func (s *VSAStorage) RetrieveVSA(ctx context.Context, tag string) (*vsa.VSA, error) {
	// resolve tag to get manifest descriptor
	manifestDesc, err := s.repo.Resolve(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve VSA tag: %w", err)
	}

	// fetch manifest
	manifestReader, err := s.repo.Manifests().Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer func() {
		if err := manifestReader.Close(); err != nil {
			fmt.Printf("Warning: failed to close manifest reader: %v\n", err)
		}
	}()

	manifestBytes, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// parse manifest
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// get the first layer (VSA content)
	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers found in VSA manifest")
	}

	vsaDesc := manifest.Layers[0]

	// fetch VSA content
	vsaReader, err := s.repo.Blobs().Fetch(ctx, vsaDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VSA content: %w", err)
	}
	defer func() {
		if err := vsaReader.Close(); err != nil {
			fmt.Printf("Warning: failed to close VSA reader: %v\n", err)
		}
	}()

	vsaBytes, err := io.ReadAll(vsaReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read VSA content: %w", err)
	}

	// unmarshal VSA
	var vsaObj vsa.VSA
	if err := json.Unmarshal(vsaBytes, &vsaObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VSA: %w", err)
	}

	return &vsaObj, nil
}

// handles OPA/Rego policy retrieval from OCI containers
type PolicyStorage struct {
	repo *remote.Repository
}

// creates a new policy storage instance for liatrio-rego-policy-library
func NewPolicyStorage(repoRef string) (*PolicyStorage, error) {
	repo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// authentication config
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
	}

	// get token from environment for authentication
	if token := getTokenFromEnv(); token != "" {
		repo.Client = &auth.Client{
			Client: retry.DefaultClient,
			Cache:  auth.NewCache(),
			Credential: auth.StaticCredential(repoRef, auth.Credential{
				Username: "token",
				Password: token,
			}),
		}
	}

	return &PolicyStorage{repo: repo}, nil
}

// retrieves a Rego policy from OCI container
func (p *PolicyStorage) RetrievePolicy(ctx context.Context, policyTag string) ([]byte, error) {
	// resolve tag to get manifest descriptor
	manifestDesc, err := p.repo.Resolve(ctx, policyTag)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy tag: %w", err)
	}

	// fetch manifest
	manifestReader, err := p.repo.Manifests().Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer func() {
		if err := manifestReader.Close(); err != nil {
			fmt.Printf("Warning: failed to close manifest reader: %v\n", err)
		}
	}()

	manifestBytes, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// parse manifest
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// get the first layer (policy content)
	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers found in policy manifest")
	}

	policyDesc := manifest.Layers[0]

	// fetch policy content
	policyReader, err := p.repo.Blobs().Fetch(ctx, policyDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch policy content: %w", err)
	}
	defer func() {
		if err := policyReader.Close(); err != nil {
			fmt.Printf("Warning: failed to close policy reader: %v\n", err)
		}
	}()

	policyBytes, err := io.ReadAll(policyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy content: %w", err)
	}

	return policyBytes, nil
}

// calculates the digest of a policy for VSA ResourceDescriptor
func (p *PolicyStorage) GetPolicyDigest(ctx context.Context, policyTag string) (map[string]string, error) {
	// resolve tag to get manifest descriptor
	manifestDesc, err := p.repo.Resolve(ctx, policyTag)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy descriptor: %w", err)
	}

	return map[string]string{
		manifestDesc.Digest.Algorithm().String(): manifestDesc.Digest.Encoded(),
	}, nil
}

// gets authentication token from environment variables
func getTokenFromEnv() string {
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("GITHUB_AUTH_TOKEN"); token != "" {
		return token
	}
	return ""
}
