package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/liatrio/autogov/pkg/digest"
	"github.com/liatrio/autogov/pkg/github"
)

const (
	// ociScheme is the URI prefix that routes a bundle path to the OCI puller.
	ociScheme = "oci://"
	// ghcrHost is the only registry host autogov sends a GitHub token to. Other
	// hosts use anonymous access (token auth is scoped to GitHub's registry).
	ghcrHost = "ghcr.io"
	// dockerManifestListMediaType is the Docker equivalent of an OCI image index.
	dockerManifestListMediaType = "application/vnd.docker.distribution.manifest.list.v2+json"
	// dockerImageManifestMediaType is the Docker equivalent of an OCI image
	// manifest; accepted alongside the OCI type so bundles pushed by either tool
	// resolve.
	dockerImageManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	// maxOCIBlobSize bounds how many bytes fetchAndVerify will buffer for any
	// single descriptor (manifest or layer). The size is taken from the
	// registry-served manifest, so an explicit cap prevents a compromised
	// registry from forcing an unbounded allocation. Policy bundles are KB-MB;
	// 128 MiB is generous headroom.
	maxOCIBlobSize = 128 << 20
)

// ociFetcher is the subset of oras.ReadOnlyTarget the bundle puller needs:
// resolve a tag/digest to a descriptor and fetch content by descriptor. Both
// *remote.Repository and *memory.Store satisfy it, so unit tests can inject an
// in-memory store and avoid the network entirely.
type ociFetcher interface {
	Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error)
	Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error)
}

// parseOCIReference strips the oci:// prefix and parses the remainder into a
// registry reference (host, repository, and tag-or-digest). It rejects
// references that omit the tag/digest so resolution failures surface here
// rather than as an opaque registry error.
func parseOCIReference(uri string) (registry.Reference, error) {
	trimmed := strings.TrimPrefix(uri, ociScheme)
	ref, err := registry.ParseReference(trimmed)
	if err != nil {
		return registry.Reference{}, fmt.Errorf("invalid oci reference %q: %w", uri, err)
	}
	if ref.Reference == "" {
		return registry.Reference{}, fmt.Errorf("oci reference %q must include a tag (:tag) or digest (@sha256:...)", uri)
	}
	return ref, nil
}

// ociAuthClient builds an ORAS auth client. retry.DefaultClient provides
// transient-failure resilience (429/502/503) on both the authenticated and
// anonymous paths. A GitHub token is attached only for ghcr.io; every other
// host uses anonymous access so a token is never leaked to an arbitrary
// registry.
func ociAuthClient(host, username string) *auth.Client {
	client := &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
	}
	if host == ghcrHost {
		if token := github.GetToken(); token != "" {
			client.Credential = auth.StaticCredential(host, auth.Credential{
				Username: username,
				Password: token,
			})
		}
	}
	return client
}

// pullOCIBundle resolves an oci:// reference to a local directory holding the
// extracted policy bundle. It is the dispatcher entry point for the oci://
// scheme (registered in resolveBundlePath).
func pullOCIBundle(ctx context.Context, uri string) (string, func(), error) {
	ref, err := parseOCIReference(uri)
	if err != nil {
		return "", nil, err
	}

	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create OCI repository for %q: %w", uri, err)
	}

	// org is the first path segment of the repository, matching the credential
	// username convention in pkg/attestations.
	org, _, _ := strings.Cut(ref.Repository, "/")
	repo.Client = ociAuthClient(ref.Registry, org)

	return resolveOCITargetToDir(ctx, repo, ref.Reference)
}

// resolveOCITargetToDir resolves reference against target, extracts the single
// gzipped-tar bundle layer into a temp directory, and returns that directory
// with a cleanup func (per the resolveBundlePath contract). The temp directory
// is removed on any error after creation.
func resolveOCITargetToDir(ctx context.Context, target ociFetcher, reference string) (string, func(), error) {
	manifestDesc, err := target.Resolve(ctx, reference)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve oci reference %q: %w", reference, err)
	}

	// Only image manifests carry the gzipped-tar bundle layer. Positively
	// allow-list the manifest media types instead of blindly unmarshalling
	// whatever the registry returns: multi-arch indexes get a clear, dedicated
	// error, and any other type (config blob, artifact/attestation manifest,
	// empty, arbitrary JSON) is rejected up front rather than producing a
	// misleading "no layer found" error after a doomed unmarshal.
	switch manifestDesc.MediaType {
	case ocispec.MediaTypeImageManifest, dockerImageManifestMediaType:
		// expected: an image manifest — proceed.
	case ocispec.MediaTypeImageIndex, dockerManifestListMediaType:
		return "", nil, fmt.Errorf("expected an image manifest but got an image index (%s); multi-arch indexes are not supported for policy bundles", manifestDesc.MediaType)
	default:
		return "", nil, fmt.Errorf("expected an image manifest but got media type %q", manifestDesc.MediaType)
	}

	manifestBytes, err := fetchAndVerify(ctx, target, manifestDesc)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read oci manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", nil, fmt.Errorf("failed to parse oci manifest: %w", err)
	}

	layerDesc, err := selectBundleLayer(manifest.Layers)
	if err != nil {
		return "", nil, err
	}

	// The layer blob is content-addressable; fetchAndVerify confirms the bytes
	// match the manifest's layer digest.
	layerBytes, err := fetchAndVerify(ctx, target, layerDesc)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read oci bundle layer: %w", err)
	}

	tempDir, cleanup, err := digest.CreateTempDir("opa-bundle-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	if err := extractTarGz(bytes.NewReader(layerBytes), tempDir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to extract oci bundle: %w", err)
	}

	return tempDir, cleanup, nil
}

// fetchAndVerify fetches a descriptor's content and verifies it against the
// descriptor's size and digest (content.ReadAll). The descriptor size is
// registry-supplied, so it is bounded before the fetch: content.ReadAll would
// otherwise allocate make([]byte, desc.Size) up front, letting a compromised
// registry force an unbounded allocation. The reader is always closed.
func fetchAndVerify(ctx context.Context, target ociFetcher, desc ocispec.Descriptor) ([]byte, error) {
	if desc.Size > maxOCIBlobSize {
		return nil, fmt.Errorf("oci content %s size %d exceeds maximum allowed %d bytes", desc.Digest, desc.Size, maxOCIBlobSize)
	}
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", desc.Digest, err)
	}
	data, err := content.ReadAll(rc, desc)
	if closeErr := rc.Close(); closeErr != nil {
		log.Printf("warning: failed to close oci content reader: %v", closeErr)
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// selectBundleLayer returns the single layer whose media type marks it as a
// gzipped-tar policy bundle. Zero matches and more than one match are both
// errors — never silently pick one.
func selectBundleLayer(layers []ocispec.Descriptor) (ocispec.Descriptor, error) {
	var matches []ocispec.Descriptor
	for _, l := range layers {
		if l.MediaType == ocispec.MediaTypeImageLayerGzip {
			matches = append(matches, l)
		}
	}
	switch len(matches) {
	case 0:
		return ocispec.Descriptor{}, fmt.Errorf("no layer with media type %s found in manifest", ocispec.MediaTypeImageLayerGzip)
	case 1:
		return matches[0], nil
	default:
		return ocispec.Descriptor{}, fmt.Errorf("ambiguous manifest: %d layers match media type %s", len(matches), ocispec.MediaTypeImageLayerGzip)
	}
}
