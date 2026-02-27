package verify_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov/cmd/verify"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVerifyGitCmd creates a fresh verify command tree for testing.
func newVerifyGitCmd() *cobra.Command {
	root := &cobra.Command{Use: "autogov"}
	// Re-use the exported VerifyCmd but add to a fresh root to avoid global state
	vc := verify.NewVerifyCmdForTesting()
	root.AddCommand(vc)
	return root
}

// executeVerifyGitCmd runs the verify git subcommand with given args and captures output.
func executeVerifyGitCmd(t *testing.T, args []string) (string, error) {
	t.Helper()

	root := newVerifyGitCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"verify", "git"}, args...))

	err := root.Execute()
	return buf.String(), err
}

// createTestRepo creates a temp git repo with some unsigned commits.
func createTestRepo(t *testing.T, commitMsgs []string) (string, []string) {
	t.Helper()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	var hashes []string
	for i, msg := range commitMsgs {
		content := []byte(fmt.Sprintf("content %d\n", i))
		err = os.WriteFile(filepath.Join(dir, "file.txt"), content, 0o644)
		require.NoError(t, err)

		_, err = wt.Add("file.txt")
		require.NoError(t, err)

		hash, err := wt.Commit(msg, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test User",
				Email: "test@example.com",
				When:  time.Date(2025, 1, i+1, 0, 0, 0, 0, time.UTC),
			},
		})
		require.NoError(t, err)
		hashes = append(hashes, hash.String())
	}

	return dir, hashes
}

func TestVerifyGit_UnsignedHEAD(t *testing.T) {
	dir, _ := createTestRepo(t, []string{"feat: initial commit"})

	out, err := executeVerifyGitCmd(t, []string{"--repo-path", dir})
	require.NoError(t, err)
	assert.Contains(t, out, "Unsigned")
}

func TestVerifyGit_SpecificRevision(t *testing.T) {
	dir, hashes := createTestRepo(t, []string{
		"feat: first commit",
		"feat: second commit",
	})

	out, err := executeVerifyGitCmd(t, []string{"--repo-path", dir, hashes[0]})
	require.NoError(t, err)
	assert.Contains(t, out, hashes[0][:8]) // short hash prefix present
}

func TestVerifyGit_JSONFormat(t *testing.T) {
	dir, _ := createTestRepo(t, []string{"feat: json test"})

	out, err := executeVerifyGitCmd(t, []string{"--repo-path", dir, "--format", "json"})
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Contains(t, result, "commit")
	assert.Contains(t, result, "unsigned")
}

func TestVerifyGit_CommitRange(t *testing.T) {
	dir, hashes := createTestRepo(t, []string{
		"feat: commit one",
		"feat: commit two",
		"feat: commit three",
	})

	out, err := executeVerifyGitCmd(t, []string{
		"--repo-path", dir,
		"--from", hashes[0],
		"--to", hashes[2],
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Summary:")
	assert.Contains(t, out, "3 commits")
}

func TestVerifyGit_InvalidRepo(t *testing.T) {
	_, err := executeVerifyGitCmd(t, []string{"--repo-path", "/nonexistent/path"})
	require.Error(t, err)
}

func TestVerifyGit_InvalidRevision(t *testing.T) {
	dir, _ := createTestRepo(t, []string{"feat: initial"})

	_, err := executeVerifyGitCmd(t, []string{"--repo-path", dir, "nonexistent-hash"})
	require.Error(t, err)
}

func TestVerifyGit_UnsupportedFormat(t *testing.T) {
	dir, _ := createTestRepo(t, []string{"feat: initial"})

	_, err := executeVerifyGitCmd(t, []string{"--repo-path", dir, "--format", "xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestVerifyGit_HelpOutput(t *testing.T) {
	out, err := executeVerifyGitCmd(t, []string{"--help"})
	require.NoError(t, err)

	assert.Contains(t, out, "--repo-path")
	assert.Contains(t, out, "--cert-identity")
	assert.Contains(t, out, "--cert-issuer")
	assert.Contains(t, out, "--format")
	assert.Contains(t, out, "--from")
	assert.Contains(t, out, "--to")
}

func TestVerifyGit_CertIdentityFlagExists(t *testing.T) {
	dir, _ := createTestRepo(t, []string{"feat: initial"})

	// cert-identity specified but commit is unsigned — should report unsigned, not error
	out, err := executeVerifyGitCmd(t, []string{
		"--repo-path", dir,
		"--cert-identity", "user@example.com",
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Unsigned")
}

func TestVerifyGit_DefaultHEAD(t *testing.T) {
	dir, _ := createTestRepo(t, []string{"feat: default head test"})

	// no positional arg = HEAD
	out, err := executeVerifyGitCmd(t, []string{"--repo-path", dir})
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestVerifyGit_JSONRangeFormat(t *testing.T) {
	dir, hashes := createTestRepo(t, []string{
		"feat: first",
		"feat: second",
	})

	out, err := executeVerifyGitCmd(t, []string{
		"--repo-path", dir,
		"--from", hashes[0],
		"--to", hashes[1],
		"--format", "json",
	})
	require.NoError(t, err)

	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &results))
	assert.NotEmpty(t, results)
	for _, r := range results {
		assert.Contains(t, r, "commit")
	}
}
