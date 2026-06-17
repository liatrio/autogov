package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// pushBlob stores data in the memory target and returns its descriptor.
func pushBlob(t *testing.T, store *memory.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	desc := content.NewDescriptorFromBytes(mediaType, data)
	if err := store.Push(context.Background(), desc, bytes.NewReader(data)); err != nil {
		t.Fatalf("failed to push blob: %v", err)
	}
	return desc
}

// pushManifest builds an image manifest referencing layers, pushes it, tags it
// with ref, and returns the manifest descriptor.
func pushManifest(t *testing.T, store *memory.Store, layers []ocispec.Descriptor, ref string) ocispec.Descriptor {
	t.Helper()
	m := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, []byte("{}")),
		Layers:    layers,
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}
	md := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, mb)
	if err := store.Push(context.Background(), md, bytes.NewReader(mb)); err != nil {
		t.Fatalf("failed to push manifest: %v", err)
	}
	if err := store.Tag(context.Background(), md, ref); err != nil {
		t.Fatalf("failed to tag manifest: %v", err)
	}
	return md
}

func TestParseOCIReference(t *testing.T) {
	digestRef := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name     string
		uri      string
		wantHost string
		wantRepo string
		wantRef  string
		wantErr  bool
	}{
		{"tag", "oci://ghcr.io/org/repo:v1.2.0", "ghcr.io", "org/repo", "v1.2.0", false},
		{"digest", "oci://ghcr.io/org/repo@" + digestRef, "ghcr.io", "org/repo", digestRef, false},
		{"nested repo", "oci://ghcr.io/org/team/repo:latest", "ghcr.io", "org/team/repo", "latest", false},
		{"no reference", "oci://ghcr.io/org/repo", "", "", "", true},
		{"empty", "oci://", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := parseOCIReference(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none", tt.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref.Registry != tt.wantHost || ref.Repository != tt.wantRepo || ref.Reference != tt.wantRef {
				t.Errorf("parseOCIReference(%q) = (%s, %s, %s), want (%s, %s, %s)",
					tt.uri, ref.Registry, ref.Repository, ref.Reference, tt.wantHost, tt.wantRepo, tt.wantRef)
			}
		})
	}
}

func TestOCIAuthClient(t *testing.T) {
	origToken := viper.GetString("token")
	t.Cleanup(func() { viper.Set("token", origToken) })

	t.Run("ghcr with token attaches credential", func(t *testing.T) {
		viper.Set("token", "")
		t.Setenv("GH_TOKEN", "secret-token")
		c := ociAuthClient("ghcr.io", "org")
		if c.Client != retry.DefaultClient {
			t.Error("expected retry.DefaultClient transport (AC9)")
		}
		if c.Credential == nil {
			t.Fatal("expected credential set for ghcr.io with token")
		}
		cred, err := c.Credential(context.Background(), "ghcr.io")
		if err != nil {
			t.Fatalf("credential func errored: %v", err)
		}
		if cred.Username != "org" || cred.Password != "secret-token" {
			t.Errorf("credential = {%s, %s}, want {org, secret-token}", cred.Username, cred.Password)
		}
	})

	t.Run("ghcr without token is anonymous", func(t *testing.T) {
		viper.Set("token", "")
		t.Setenv("GH_TOKEN", "")
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GITHUB_AUTH_TOKEN", "")
		c := ociAuthClient("ghcr.io", "org")
		if c.Client != retry.DefaultClient {
			t.Error("expected retry.DefaultClient transport (AC9)")
		}
		if c.Credential != nil {
			t.Error("expected anonymous (nil credential) when no token present (AC8)")
		}
	})

	t.Run("non-ghcr host never receives token", func(t *testing.T) {
		viper.Set("token", "")
		t.Setenv("GH_TOKEN", "secret-token")
		c := ociAuthClient("registry.example.com", "org")
		if c.Client != retry.DefaultClient {
			t.Error("expected retry.DefaultClient transport (AC9)")
		}
		if c.Credential != nil {
			t.Error("token must not be sent to non-ghcr.io hosts (AC3/AC4)")
		}
	})
}

func TestResolveOCIBundle(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	layerData := buildTarGz(t, map[string]string{"policy.rego": "package governance"})
	layer := pushBlob(t, store, ocispec.MediaTypeImageLayerGzip, layerData)
	pushManifest(t, store, []ocispec.Descriptor{layer}, "v1")

	dir, cleanup, err := resolveOCITargetToDir(ctx, store, "v1")
	if err != nil {
		t.Fatalf("resolveOCITargetToDir failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "policy.rego"))
	if err != nil {
		t.Fatalf("extracted policy.rego missing: %v", err)
	}
	if string(got) != "package governance" {
		t.Errorf("policy.rego content = %q, want %q", string(got), "package governance")
	}

	cleanup()
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("temp dir %s not removed after cleanup (AC10)", dir)
	}
}

func TestResolveOCIBundleDigestRef(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	layer := pushBlob(t, store, ocispec.MediaTypeImageLayerGzip, buildTarGz(t, map[string]string{"policy.rego": "package x"}))
	md := pushManifest(t, store, []ocispec.Descriptor{layer}, "v1")
	// tag by digest so the in-memory store can resolve a digest reference (AC2)
	if err := store.Tag(ctx, md, md.Digest.String()); err != nil {
		t.Fatalf("tag by digest failed: %v", err)
	}

	dir, cleanup, err := resolveOCITargetToDir(ctx, store, md.Digest.String())
	if err != nil {
		t.Fatalf("digest-ref resolve failed: %v", err)
	}
	cleanup()
	if dir == "" {
		t.Error("expected a non-empty extracted dir")
	}
}

func TestResolveOCIBundleNoLayer(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	// layer present but with a non-matching media type
	layer := pushBlob(t, store, "application/vnd.example.unknown", buildTarGz(t, map[string]string{"policy.rego": "package x"}))
	pushManifest(t, store, []ocispec.Descriptor{layer}, "v1")

	_, _, err := resolveOCITargetToDir(ctx, store, "v1")
	if err == nil {
		t.Fatal("expected error when no gzip bundle layer present (AC7)")
	}
	if !strings.Contains(err.Error(), "no layer with media type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveOCIBundleMultipleLayers(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	l1 := pushBlob(t, store, ocispec.MediaTypeImageLayerGzip, buildTarGz(t, map[string]string{"a.rego": "package a"}))
	l2 := pushBlob(t, store, ocispec.MediaTypeImageLayerGzip, buildTarGz(t, map[string]string{"b.rego": "package b"}))
	pushManifest(t, store, []ocispec.Descriptor{l1, l2}, "v1")

	_, _, err := resolveOCITargetToDir(ctx, store, "v1")
	if err == nil {
		t.Fatal("expected ambiguous error for multiple matching layers (AC5)")
	}
	if !strings.Contains(err.Error(), "ambiguous manifest") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveOCIBundleIndexRejected(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	indexBytes := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	idx := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, indexBytes)
	if err := store.Push(ctx, idx, bytes.NewReader(indexBytes)); err != nil {
		t.Fatalf("push index: %v", err)
	}
	if err := store.Tag(ctx, idx, "multi"); err != nil {
		t.Fatalf("tag index: %v", err)
	}

	_, _, err := resolveOCITargetToDir(ctx, store, "multi")
	if err == nil {
		t.Fatal("expected error for image index")
	}
	if !strings.Contains(err.Error(), "image index") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveOCIBundleDockerManifestListRejected(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	listBytes := []byte(`{"schemaVersion":2,"mediaType":"` + dockerManifestListMediaType + `","manifests":[]}`)
	desc := content.NewDescriptorFromBytes(dockerManifestListMediaType, listBytes)
	if err := store.Push(ctx, desc, bytes.NewReader(listBytes)); err != nil {
		t.Fatalf("push manifest list: %v", err)
	}
	if err := store.Tag(ctx, desc, "multi"); err != nil {
		t.Fatalf("tag manifest list: %v", err)
	}

	_, _, err := resolveOCITargetToDir(ctx, store, "multi")
	if err == nil {
		t.Fatal("expected error for docker manifest list")
	}
	if !strings.Contains(err.Error(), "image index") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveOCIBundleNonManifestRejected(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	// tag points at content whose media type is neither image manifest nor
	// index — it must be rejected up front, not blindly unmarshalled.
	data := []byte("not a manifest")
	desc := content.NewDescriptorFromBytes("application/vnd.example.unknown", data)
	if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
		t.Fatalf("push blob: %v", err)
	}
	if err := store.Tag(ctx, desc, "weird"); err != nil {
		t.Fatalf("tag blob: %v", err)
	}

	_, _, err := resolveOCITargetToDir(ctx, store, "weird")
	if err == nil {
		t.Fatal("expected error for non-manifest media type")
	}
	if !strings.Contains(err.Error(), "expected an image manifest but got media type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveOCIBundleLayerTooLarge(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	layer := pushBlob(t, store, ocispec.MediaTypeImageLayerGzip, buildTarGz(t, map[string]string{"policy.rego": "package x"}))
	// the manifest advertises an oversized layer; the size cap must reject it
	// before content.ReadAll attempts a make([]byte, desc.Size) allocation.
	layer.Size = maxOCIBlobSize + 1
	pushManifest(t, store, []ocispec.Descriptor{layer}, "v1")

	_, _, err := resolveOCITargetToDir(ctx, store, "v1")
	if err == nil {
		t.Fatal("expected error for oversized layer descriptor")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPullOCIBundleInvalidReference(t *testing.T) {
	// a reference without tag/digest must fail fast at parse time (no network)
	_, _, err := pullOCIBundle(context.Background(), "oci://ghcr.io/org/repo")
	if err == nil {
		t.Fatal("expected parse error for reference without tag/digest")
	}
}

func TestResolveBundlePathRoutesOCI(t *testing.T) {
	// resolveBundlePath must dispatch oci:// to the OCI puller, not fall through
	// to the local-directory passthrough. A reference without a tag/digest fails
	// fast in parseOCIReference, so an error here proves the oci:// case ran
	// (the default case would return the path with a nil error).
	_, _, err := resolveBundlePath(context.Background(), "oci://ghcr.io/org/repo", &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected resolveBundlePath to route oci:// to the OCI puller and surface a parse error")
	}
	if !strings.Contains(err.Error(), "must include a tag") {
		t.Errorf("unexpected error (did oci:// route correctly?): %v", err)
	}
}
