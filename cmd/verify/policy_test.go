package verify_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov/cmd/verify"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newVerifyPolicyCmd() *cobra.Command {
	root := &cobra.Command{Use: "autogov"}
	vc := verify.NewVerifyCmdForTesting()
	root.AddCommand(vc)
	return root
}

func executeVerifyPolicyCmd(t *testing.T, args []string) (string, error) {
	t.Helper()

	root := newVerifyPolicyCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"verify", "policy"}, args...))

	err := root.Execute()
	return buf.String(), err
}

// createPolicyTestRepo creates a test repo with policy file.
func createPolicyTestRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	for i := range 3 {
		content := []byte(fmt.Sprintf("content %d\n", i))
		err = os.WriteFile(filepath.Join(dir, "file.txt"), content, 0o644)
		require.NoError(t, err)

		_, err = wt.Add("file.txt")
		require.NoError(t, err)

		_, err = wt.Commit(fmt.Sprintf("feat: commit %d", i), &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test User",
				Email: "test@example.com",
				When:  time.Date(2025, 1, i+1, 0, 0, 0, 0, time.UTC),
			},
		})
		require.NoError(t, err)
	}

	// Create policy file.
	policyFile := filepath.Join(dir, "policy.json")
	data := []byte(`{
		"rules": [{"name": "signed-commits", "pattern": "refs/heads/master"}],
		"protected_branches": {
			"refs/heads/master": {
				"require_pr": true,
				"require_signed_commits": true
			}
		},
		"required_signers": {}
	}`)
	require.NoError(t, os.WriteFile(policyFile, data, 0o644))

	return dir, policyFile
}

func TestVerifyPolicy_MissingRef(t *testing.T) {
	_, err := executeVerifyPolicyCmd(t, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ref")
}

func TestVerifyPolicy_WithExplicitPolicy(t *testing.T) {
	repoDir, policyFile := createPolicyTestRepo(t)

	out, err := executeVerifyPolicyCmd(t, []string{
		"--repo-path", repoDir,
		"--ref", "refs/heads/master",
		"--policy-path", policyFile,
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Policy Verification")
	assert.Contains(t, out, "refs/heads/master")
}

func TestVerifyPolicy_JSONOutput(t *testing.T) {
	repoDir, policyFile := createPolicyTestRepo(t)

	out, err := executeVerifyPolicyCmd(t, []string{
		"--repo-path", repoDir,
		"--ref", "refs/heads/master",
		"--policy-path", policyFile,
		"--format", "json",
	})
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Contains(t, result, "verified")
	assert.Contains(t, result, "ref")
}

func TestVerifyPolicy_JSONFailsClosed(t *testing.T) {
	repoDir, _ := createPolicyTestRepo(t)

	// a malformed --policy-path makes VerifyPolicy return Verified==false with a
	// non-empty ErrorMsg ("failed to load policy from ..."). under --format json the
	// body must be printed AND the command must exit nonzero.
	badPolicy := filepath.Join(t.TempDir(), "bad-policy.json")
	require.NoError(t, os.WriteFile(badPolicy, []byte("{ not valid json"), 0o600))

	out, err := executeVerifyPolicyCmd(t, []string{
		"--repo-path", repoDir,
		"--ref", "refs/heads/master",
		"--policy-path", badPolicy,
		"--format", "json",
	})
	require.Error(t, err)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(strings.NewReader(out)).Decode(&result))
	assert.Equal(t, false, result["verified"])
}

func TestVerifyPolicy_PartialVerifiedExitUnchanged(t *testing.T) {
	repoDir, policyFile := createPolicyTestRepo(t)

	// a valid policy whose rules are not fully satisfied (unsigned commits) is the
	// "Partially Verified" case: Verified==false with an empty ErrorMsg. AC5 — this
	// must keep its prior exit status (success) under both formats, because the new
	// fail-closed check keys on the same !Verified && ErrorMsg != "" predicate.
	outText, errText := executeVerifyPolicyCmd(t, []string{
		"--repo-path", repoDir,
		"--ref", "refs/heads/master",
		"--policy-path", policyFile,
		"--format", "text",
	})
	require.NoError(t, errText)
	assert.Contains(t, outText, "Partially Verified")

	_, errJSON := executeVerifyPolicyCmd(t, []string{
		"--repo-path", repoDir,
		"--ref", "refs/heads/master",
		"--policy-path", policyFile,
		"--format", "json",
	})
	require.NoError(t, errJSON)
}

func TestVerifyPolicy_HelpOutput(t *testing.T) {
	out, err := executeVerifyPolicyCmd(t, []string{"--help"})
	require.NoError(t, err)

	assert.Contains(t, out, "--repo-path")
	assert.Contains(t, out, "--ref")
	assert.Contains(t, out, "--policy-path")
	assert.Contains(t, out, "--cert-identity")
	assert.Contains(t, out, "--cert-issuer")
	assert.Contains(t, out, "--format")
	assert.Contains(t, out, "--quiet")
}

func TestVerifyPolicy_InvalidRepo(t *testing.T) {
	_, err := executeVerifyPolicyCmd(t, []string{
		"--repo-path", "/nonexistent",
		"--ref", "refs/heads/main",
	})
	require.Error(t, err)
}

func TestVerifyPolicy_VSAFlagsRegistered(t *testing.T) {
	out, err := executeVerifyPolicyCmd(t, []string{"--help"})
	require.NoError(t, err)
	assert.Contains(t, out, "--generate-vsa")
	assert.Contains(t, out, "--vsa-output")
	assert.Contains(t, out, "--policy-uri")
}

func TestVerifyPolicy_InvalidFormat(t *testing.T) {
	repoDir, policyFile := createPolicyTestRepo(t)

	_, err := executeVerifyPolicyCmd(t, []string{
		"--repo-path", repoDir,
		"--ref", "refs/heads/master",
		"--policy-path", policyFile,
		"--format", "xml",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}
