package verify_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liatrio/autogov/cmd/verify"
	"github.com/spf13/cobra"
)

func newVerifyAttestationCmd() *cobra.Command {
	root := &cobra.Command{Use: "autogov"}
	root.AddCommand(verify.NewVerifyCmdForTesting())
	return root
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was written.
// the unsafe-mode warning is written to os.Stderr directly (not cmd.ErrOrStderr) so it
// survives stdout capture and quiet CI runs — so the test must capture os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

func TestVerifyAttestation_OfflineEnforcesCertIdentityList(t *testing.T) {
	// the offline branch must resolve and enforce --cert-identity-list
	// (it ignored the list entirely before). a malformed list fails closed rather than
	// silently falling through to accept-any.
	t.Setenv("GITHUB_TOKEN", "dummy-token-for-prerun")

	tmp := t.TempDir()
	blob := filepath.Join(tmp, "artifact.txt")
	if err := os.WriteFile(blob, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	attDir := filepath.Join(tmp, "atts")
	if err := os.MkdirAll(attDir, 0755); err != nil {
		t.Fatal(err)
	}
	badList := filepath.Join(tmp, "bad-list.json")
	if err := os.WriteFile(badList, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	root := newVerifyAttestationCmd()
	root.SetArgs([]string{"verify", "attestation",
		"--blob-path", blob,
		"--attestations-path", attDir,
		"--repo", "liatrio/test",
		"--cert-identity-list", badList,
		"--quiet",
	})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	err := root.Execute()
	if err == nil {
		t.Fatal("expected fail-closed error for malformed --cert-identity-list in offline mode, got nil")
	}
	if !strings.Contains(err.Error(), "resolve accepted certificate identities") {
		t.Errorf("expected the offline branch to resolve+enforce the list (not ignore it); got: %v", err)
	}
}

func TestVerifyAttestation_UnsafeWarningUngatedByQuiet(t *testing.T) {
	// when neither --cert-identity nor --cert-identity-list is set, a single
	// warning goes to stderr, is "warning:"-prefixed, and fires even under --quiet.
	t.Setenv("GITHUB_TOKEN", "dummy-token-for-prerun")

	tmp := t.TempDir()
	blob := filepath.Join(tmp, "artifact.txt")
	if err := os.WriteFile(blob, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	attDir := filepath.Join(tmp, "atts")
	if err := os.MkdirAll(attDir, 0755); err != nil {
		t.Fatal(err)
	}

	root := newVerifyAttestationCmd()
	root.SetArgs([]string{"verify", "attestation",
		"--blob-path", blob,
		"--attestations-path", attDir,
		"--repo", "liatrio/test",
		"--quiet",
	})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	stderr := captureStderr(t, func() {
		// verification itself fails (no real bundles); we only assert the warning fired
		_ = root.Execute()
	})

	const want = "warning: no certificate identity enforced"
	if got := strings.Count(stderr, want); got != 1 {
		t.Errorf("expected exactly one unsafe-mode warning on stderr (ungated by --quiet), got %d; stderr: %q", got, stderr)
	}
}
