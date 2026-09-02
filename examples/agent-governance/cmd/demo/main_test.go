package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPrepareWorkdirCreatesCallerSuppliedDirectoryWithoutRemovingIt(t *testing.T) {
	requested := filepath.Join(t.TempDir(), "nested", "demo-output")
	dir, cleanup, err := prepareWorkdir(requested, false)
	if err != nil {
		t.Fatal(err)
	}
	if dir != requested {
		t.Errorf("workdir = %q, want %q", dir, requested)
	}
	if info, err := os.Stat(requested); err != nil || !info.IsDir() {
		t.Fatalf("caller-supplied workdir was not created: info=%v err=%v", info, err)
	}
	cleanup()
	if _, err := os.Stat(requested); err != nil {
		t.Errorf("cleanup removed caller-supplied workdir: %v", err)
	}
}

func TestPrepareWorkdirRemovesOnlyAutomaticTemporaryDirectory(t *testing.T) {
	dir, cleanup, err := prepareWorkdir("", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("automatic workdir was not created: %v", err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("automatic workdir remains after cleanup: %v", err)
	}
}

func TestPrepareWorkdirKeepsAutomaticTemporaryDirectoryWhenRequested(t *testing.T) {
	dir, cleanup, err := prepareWorkdir("", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cleanup()
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("automatic workdir was not retained: info=%v err=%v", info, err)
	}
}

// the demo compares the production predicate command with demokit's
// deterministic library output before it signs every case. run that exact
// boundary in the ordinary Go suite so the check is not manual-only.
func TestDemoExercisesCLIAndLibraryBoundary(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "autogov")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build demo binary: %v\n%s", err, output)
	}
	if err := run(binary, filepath.Join(root, "examples", "agent-governance"), filepath.Join(t.TempDir(), "demo-output"), false); err != nil {
		t.Fatal(err)
	}
}
