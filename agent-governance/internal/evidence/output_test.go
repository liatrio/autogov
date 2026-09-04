package evidence

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteOutputWritesExactStdoutBytes(t *testing.T) {
	want := []byte(`{"valid":true}`)
	captured, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = captured
	t.Cleanup(func() { os.Stdout = original })

	writeErr := writeOutput(want, "")
	os.Stdout = original
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, err := captured.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(captured)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stdout bytes = %q, want exact predicate bytes %q", got, want)
	}
}

func TestWriteOutputReportsStdoutFailure(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "closed-stdout-")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	original := os.Stdout
	os.Stdout = closed
	t.Cleanup(func() { os.Stdout = original })

	err = writeOutput([]byte(`{"valid":true}`), "")
	if err == nil || !strings.Contains(err.Error(), "failed to write output") {
		t.Fatalf("stdout write error = %v, want propagated failure", err)
	}
}

func TestWriteOutputCommitsAtomicallyAndCleansFailedTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "predicate.json")
	want := []byte(`{"valid":true}`)
	if err := writeOutput(want, outputPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("output = %q, want %q", got, want)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("output mode = %o, want 600", info.Mode().Perm())
	}

	directoryTarget := filepath.Join(dir, "cannot-replace-directory")
	if err := os.Mkdir(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOutput(want, directoryTarget); err == nil {
		t.Fatal("expected atomic rename over a directory to fail")
	}
	temporaries, err := filepath.Glob(filepath.Join(dir, ".cannot-replace-directory.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporaries) != 0 {
		t.Errorf("failed output left temporary files: %v", temporaries)
	}
}
