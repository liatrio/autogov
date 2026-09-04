package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCommittedCheckpointMatchesGeneratedArtifacts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	got, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(root, manifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed extraction checkpoint differs from generated artifacts")
	}

	var checkpoint manifest
	if err := json.Unmarshal(got, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.BaselineCommit != baselineCommit {
		t.Errorf("baseline commit = %q, want %q", checkpoint.BaselineCommit, baselineCommit)
	}
	wantCounts := map[string]int{
		"frozen-input":          47,
		"policy-bundle":         1,
		"predicate-body":        10,
		"test-result-statement": 10,
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	digestPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, item := range checkpoint.Entries {
		counts[item.Kind]++
		key := item.Kind + "\x00" + item.Name
		if seen[key] {
			t.Errorf("duplicate checkpoint entry %s/%s", item.Kind, item.Name)
		}
		seen[key] = true
		if !digestPattern.MatchString(item.SHA256) {
			t.Errorf("%s/%s has malformed SHA-256 %q", item.Kind, item.Name, item.SHA256)
		}
	}
	for kind, count := range wantCounts {
		if counts[kind] != count {
			t.Errorf("%s entries = %d, want %d", kind, counts[kind], count)
		}
	}
}

func TestCheckpointCommandModesAndFailures(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := run([]string{"-root", root, "-verify"}, &stderr); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		nil,
		{"-root", root},
		{"-root", root, "-write"},
		{"-root", root, "-write", "-verify"},
		{"-root", root, "unexpected"},
	} {
		if err := run(args, &stderr); err == nil {
			t.Errorf("run(%v) unexpectedly succeeded", args)
		}
	}
	if err := run([]string{"-help"}, &stderr); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v, want flag.ErrHelp", err)
	}

	copyRoot := copyCheckpointInputs(t, root)
	manifestPath := filepath.Join(copyRoot, manifestFilename)
	immutable := []byte("immutable checkpoint sentinel\n")
	if err := os.WriteFile(manifestPath, immutable, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-root", copyRoot, "-write"}, &stderr); err == nil {
		t.Fatal("write mode unexpectedly succeeded")
	}
	if got, err := os.ReadFile(manifestPath); err != nil || !bytes.Equal(got, immutable) {
		t.Fatalf("rejected write mode changed checkpoint: got=%q err=%v", got, err)
	}
	if err := run([]string{"-root", copyRoot, "-verify"}, &stderr); err == nil {
		t.Fatal("verify mode accepted a mismatched manifest")
	}
	if err := run([]string{"-root", t.TempDir(), "-verify"}, &stderr); err == nil {
		t.Fatal("checkpoint accepted a root with missing frozen inputs")
	}
}

func TestCheckpointRejectsSymlinkedFrozenInput(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	copyRoot := copyCheckpointInputs(t, root)
	path := filepath.Join(copyRoot, filepath.FromSlash(frozenInputs[0]))
	external := filepath.Join(t.TempDir(), "external-input")
	if err := os.WriteFile(external, []byte("outside extraction tree"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := run([]string{"-root", copyRoot, "-verify"}, &stderr); err == nil || !strings.Contains(err.Error(), "regular non-symlink file") {
		t.Fatalf("symlinked frozen input error = %v, want regular-file rejection", err)
	}
}

func copyCheckpointInputs(t *testing.T, sourceRoot string) string {
	t.Helper()
	destinationRoot := t.TempDir()
	for _, rel := range frozenInputs {
		source := filepath.Join(sourceRoot, filepath.FromSlash(rel))
		destination := filepath.Join(destinationRoot, filepath.FromSlash(rel))
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatalf("create parent for %s: %v", rel, err)
		}
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatalf("copy %s: %v", rel, err)
		}
	}
	return destinationRoot
}

func TestCheckpointPolicyDigestIgnoresNonPolicyFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("package test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := hashBytes([]byte("policy.regopackage test\n"))
	got, err := calculatePolicyDirectoryDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("policy digest = %s, want %s", got, want)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotAfterIgnored, err := calculatePolicyDirectoryDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gotAfterIgnored != want {
		t.Errorf("non-policy file changed digest to %s", gotAfterIgnored)
	}
}
