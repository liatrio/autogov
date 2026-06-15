package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/spf13/viper"
)

// builds an in-memory tar.gz from a map of file name -> content
func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header for %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content for %s: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	return buf.Bytes()
}

// writes a tar.gz file to disk and returns its path
func writeTarGzFile(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	data := buildTarGz(t, files)
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write tar.gz file: %v", err)
	}
	return path
}

// serves the given tar.gz bytes over HTTP for the duration of the test
func serveTarGz(t *testing.T, data []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data); err != nil {
			t.Logf("warning: failed to write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// captures everything written to os.Stdout while fn runs
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Logf("warning: failed to close pipe writer: %v", err)
	}
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	return buf.String()
}

// captures everything written via the standard logger while fn runs
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// AC4/AC5, Task 6.2: HTTP URL dispatch downloads and extracts the bundle.
func TestResolveBundlePathHTTP(t *testing.T) {
	data := buildTarGz(t, map[string]string{"test.rego": testPolicyContent})
	server := serveTarGz(t, data)

	localPath, cleanup, err := resolveBundlePath(context.Background(), server.URL, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err != nil {
		t.Fatalf("resolveBundlePath returned error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup for HTTP download")
	}
	defer cleanup()

	if _, err := os.Stat(filepath.Join(localPath, "test.rego")); err != nil {
		t.Errorf("expected test.rego in resolved dir: %v", err)
	}
}

// Task 6.2 (negative): the tightened prefix only matches http://, https://.
// A bare "httpfoo" path is treated as a local directory passthrough, not a download.
func TestResolveBundlePathHTTPPrefixTightened(t *testing.T) {
	localPath, cleanup, err := resolveBundlePath(context.Background(), "httpfoo-not-a-url", nil)
	if err != nil {
		t.Fatalf("resolveBundlePath returned error: %v", err)
	}
	defer cleanup()
	if localPath != "httpfoo-not-a-url" {
		t.Errorf("expected passthrough of non-URL path, got %q", localPath)
	}
}

// AC4/AC5, Task 6.3: tar.gz extraction dispatch.
func TestResolveBundlePathTarGz(t *testing.T) {
	dir := t.TempDir()
	tarPath := writeTarGzFile(t, dir, map[string]string{"test.rego": testPolicyContent})

	localPath, cleanup, err := resolveBundlePath(context.Background(), tarPath, nil)
	if err != nil {
		t.Fatalf("resolveBundlePath returned error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup for tar.gz extraction")
	}
	defer cleanup()

	if _, err := os.Stat(filepath.Join(localPath, "test.rego")); err != nil {
		t.Errorf("expected test.rego in resolved dir: %v", err)
	}
}

// AC4, Task 6.4: directory passthrough returns the path unchanged with a no-op cleanup.
func TestResolveBundlePathDirectory(t *testing.T) {
	dir := t.TempDir()

	localPath, cleanup, err := resolveBundlePath(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("resolveBundlePath returned error: %v", err)
	}
	if localPath != dir {
		t.Errorf("expected passthrough of dir, got %q", localPath)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil (no-op) cleanup for directory")
	}
	// no-op cleanup must not remove the directory
	cleanup()
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("directory should still exist after no-op cleanup: %v", err)
	}
}

// AC6, Task 6.5: cleanup function actually removes the extracted temp dir.
func TestResolveBundlePathCleanupRemovesTempDir(t *testing.T) {
	dir := t.TempDir()
	tarPath := writeTarGzFile(t, dir, map[string]string{"test.rego": testPolicyContent})

	localPath, cleanup, err := resolveBundlePath(context.Background(), tarPath, nil)
	if err != nil {
		t.Fatalf("resolveBundlePath returned error: %v", err)
	}

	if _, err := os.Stat(localPath); err != nil {
		t.Fatalf("expected temp dir to exist before cleanup: %v", err)
	}

	cleanup()

	if _, err := os.Stat(localPath); !os.IsNotExist(err) {
		t.Errorf("expected temp dir to be removed after cleanup, stat err = %v", err)
	}
}

// AC6, Task 6.6: Stop() calls all collected cleanup functions.
func TestStopCallsCleanups(t *testing.T) {
	called := make([]bool, 3)
	e := &OPAEvaluator{
		cleanups: []func(){
			func() { called[0] = true },
			nil, // Stop must tolerate nil entries
			func() { called[2] = true },
		},
	}

	e.Stop(context.Background())

	if !called[0] || !called[2] {
		t.Errorf("expected all non-nil cleanups to be called, got %v", called)
	}
}

// AC6, Task 6.6 (integration): NewOPAEvaluator wires the extraction temp dir into
// Stop(), which removes it.
func TestStopRemovesEvaluatorTempDir(t *testing.T) {
	dir := t.TempDir()
	tarPath := writeTarGzFile(t, dir, map[string]string{"test.rego": testPolicyContent})

	evaluator, err := NewOPAEvaluator(context.Background(), tarPath, "", "")
	if err != nil {
		t.Fatalf("NewOPAEvaluator returned error: %v", err)
	}

	resolved := evaluator.ResolvedPolicyPath()
	if _, err := os.Stat(resolved); err != nil {
		t.Fatalf("expected resolved bundle dir to exist: %v", err)
	}

	evaluator.Stop(context.Background())

	if _, err := os.Stat(resolved); !os.IsNotExist(err) {
		t.Errorf("expected resolved bundle dir to be removed by Stop(), stat err = %v", err)
	}
}

// AC3, Task 6.7: schemas path served over HTTP is downloaded, extracted, and loaded
// (a new capability — previously schemas only supported tar.gz files and directories).
func TestNewOPAEvaluatorSchemasViaHTTP(t *testing.T) {
	// bundle: a local directory containing a valid policy
	bundleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundleDir, "test.rego"), []byte(testPolicyContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// schemas: served as a tar.gz over HTTP, containing a JSON schema
	schemaJSON := `{"type":"object","properties":{"foo":{"type":"string"}}}`
	schemasData := buildTarGz(t, map[string]string{"myschema.json": schemaJSON})
	schemasServer := serveTarGz(t, schemasData)

	// sanity: the dispatcher resolves the HTTP schemas URL to a dir with the schema
	resolved, cleanup, err := resolveBundlePath(context.Background(), schemasServer.URL, &ResolveOptions{DefaultAsset: "schemas.tar.gz"})
	if err != nil {
		t.Fatalf("resolveBundlePath for schemas URL returned error: %v", err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(resolved, "myschema.json")); err != nil {
		t.Errorf("expected myschema.json in resolved schemas dir: %v", err)
	}

	// NewOPAEvaluator must succeed end-to-end with an HTTP schemas path AND
	// actually load the schema (construction succeeds even with zero schemas, so
	// "no error" alone would not prove the new capability works).
	origQuiet := viper.Get("quiet")
	viper.Set("quiet", false)
	defer viper.Set("quiet", origQuiet)
	var evaluator *OPAEvaluator
	out := captureStdout(t, func() {
		var e error
		evaluator, e = NewOPAEvaluator(context.Background(), bundleDir, schemasServer.URL, "")
		if e != nil {
			t.Errorf("NewOPAEvaluator with HTTP schemas returned error: %v", e)
		}
	})
	if evaluator != nil {
		defer evaluator.Stop(context.Background())
	}
	if !bytes.Contains([]byte(out), []byte("Loaded 1 schemas for validation")) {
		t.Errorf("expected schema to be loaded from HTTP source, stdout was: %q", out)
	}
}

// AC3, Task 3.2: schemas resolution degrades gracefully — a failing schemas path
// logs a warning and does not fail evaluator construction.
func TestNewOPAEvaluatorSchemasGracefulDegradation(t *testing.T) {
	bundleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundleDir, "test.rego"), []byte(testPolicyContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// a server that always 500s for the schemas download
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	// the degradation branch must actually fire (warning logged) — not merely
	// "no error", which is also true when schemas load or when there are none.
	var evaluator *OPAEvaluator
	logOut := captureLog(t, func() {
		var err error
		evaluator, err = NewOPAEvaluator(context.Background(), bundleDir, failServer.URL, "")
		if err != nil {
			t.Errorf("expected graceful degradation, got error: %v", err)
		}
	})
	if evaluator == nil {
		t.Fatal("expected a constructed evaluator despite schemas failure")
	}
	defer evaluator.Stop(context.Background())

	if !bytes.Contains([]byte(logOut), []byte("failed to resolve schemas path")) {
		t.Errorf("expected a schemas-resolution warning to be logged, log was: %q", logOut)
	}

	// and the evaluator must still be usable for policy evaluation
	if _, err := evaluator.EvaluatePolicyWithBundles(context.Background(), nil); err != nil {
		t.Errorf("evaluator should still evaluate after schemas degradation: %v", err)
	}
}

// counts leftover opa-bundle-* temp dirs under os.TempDir()
func countOpaBundleTempDirs(t *testing.T) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "opa-bundle-*"))
	if err != nil {
		t.Fatalf("failed to glob temp dirs: %v", err)
	}
	return len(matches)
}

// AC7 regression (#1/#13): for a .tar.gz bundle, the policy digest now reflects
// the extracted directory contents (CalculateDirectory), NOT the archive bytes
// (CalculateFile). Pins the intentional behavior change so it can't regress
// silently.
func TestCalculateDigestUsesExtractedContents(t *testing.T) {
	dir := t.TempDir()
	tarPath := writeTarGzFile(t, dir, map[string]string{"test.rego": testPolicyContent})

	resolved, cleanup, err := resolveBundlePath(context.Background(), tarPath, nil)
	if err != nil {
		t.Fatalf("resolveBundlePath returned error: %v", err)
	}
	defer cleanup()

	got, err := CalculateDigest(resolved)
	if err != nil {
		t.Fatalf("CalculateDigest(resolved) returned error: %v", err)
	}

	// equals the digest of a plain directory holding the same content...
	wantDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wantDir, "test.rego"), []byte(testPolicyContent), 0644); err != nil {
		t.Fatalf("failed to write reference policy: %v", err)
	}
	want, err := CalculateDigest(wantDir)
	if err != nil {
		t.Fatalf("CalculateDigest(wantDir) returned error: %v", err)
	}
	if got != want {
		t.Errorf("digest of extracted dir = %q, want directory-content digest %q", got, want)
	}

	// ...and is NOT the old archive-bytes digest (tarPath is a file -> CalculateFile)
	archiveDigest, err := CalculateDigest(tarPath)
	if err != nil {
		t.Fatalf("CalculateDigest(tarPath) returned error: %v", err)
	}
	if got == archiveDigest {
		t.Error("digest should reflect extracted contents, not archive bytes")
	}
}

// #2 regression: when --policy-schemas-path is omitted, generate.go defaults
// schemasPath to the bundle path. An http(s):// bundle must be downloaded only
// ONCE, not re-fetched for schemas resolution.
func TestNewOPAEvaluatorHTTPBundleDownloadedOnce(t *testing.T) {
	var hits int32
	data := buildTarGz(t, map[string]string{"test.rego": testPolicyContent})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data); err != nil {
			t.Logf("warning: failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// schemasPath == bundlePath mirrors the generate.go default
	evaluator, err := NewOPAEvaluator(context.Background(), server.URL, server.URL, "")
	if err != nil {
		t.Fatalf("NewOPAEvaluator returned error: %v", err)
	}
	defer evaluator.Stop(context.Background())

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected bundle to be downloaded once, got %d downloads", got)
	}
}

// #3 regression: when construction fails AFTER a temp dir was created (here, an
// unparseable policy fails PrepareForEval), the extracted temp dir must not leak
// — Stop() is unreachable on the error return, so the constructor must clean up.
func TestNewOPAEvaluatorCleansUpTempDirOnError(t *testing.T) {
	dir := t.TempDir()
	// extracts fine, but the .rego is not valid -> PrepareForEval fails
	tarPath := writeTarGzFile(t, dir, map[string]string{"bad.rego": "package governance\n\nthis is not valid rego {{{"})

	before := countOpaBundleTempDirs(t)

	evaluator, err := NewOPAEvaluator(context.Background(), tarPath, "", "")
	if err == nil {
		evaluator.Stop(context.Background())
		t.Fatal("expected NewOPAEvaluator to fail on an invalid policy")
	}

	if after := countOpaBundleTempDirs(t); after > before {
		t.Errorf("temp dir leaked on error path: before=%d after=%d", before, after)
	}
}
