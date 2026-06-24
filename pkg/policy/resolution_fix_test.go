package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A ghrel:// (or oci://) reference whose ?asset ends in ".tar.gz" must route by
// scheme, not be mistaken for a local .tar.gz archive. A malformed reference
// (missing repo) fails fast in ghrel parsing with no network, proving the
// ghrel:// case ran rather than the .tar.gz/extractBundle case (which would
// report "failed to open bundle file").
func TestResolveBundlePathRoutesGHRelWithTarGzAsset(t *testing.T) {
	_, _, err := resolveBundlePath(context.Background(), "ghrel://owner?asset=bundle.tar.gz", &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "failed to open bundle file") {
		t.Fatalf("ghrel:// with a .tar.gz asset was misrouted to local extraction: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid ghrel reference") {
		t.Errorf("ghrel:// with a .tar.gz asset did not route by scheme: %v", err)
	}
}

// tar archives commonly include a "./" archive-root entry; extraction must accept
// it (it resolves to dest itself) rather than flag it as path traversal.
func TestExtractTarGzAllowsArchiveRootEntry(t *testing.T) {
	content := []byte("schema")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, h := range []struct {
		hdr  *tar.Header
		body []byte
	}{
		{&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0755}, nil},
		{&tar.Header{Name: "schema.json", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(content))}, content},
	} {
		if err := tw.WriteHeader(h.hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if h.body != nil {
			if _, err := tw.Write(h.body); err != nil {
				t.Fatalf("write body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	dest := t.TempDir()
	if err := extractTarGz(&buf, dest); err != nil {
		t.Fatalf("extractTarGz rejected a benign './' archive-root entry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "schema.json")); err != nil {
		t.Fatalf("expected schema.json to be extracted: %v", err)
	}
}

// A real traversal entry (escaping dest) must still be rejected.
func TestExtractTarGzRejectsTraversal(t *testing.T) {
	content := []byte("x")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	err := extractTarGz(&buf, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("expected a path-traversal rejection, got: %v", err)
	}
}
