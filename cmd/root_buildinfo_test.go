package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov/cmd/verify"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestVerifyPolicyVSAUsesRuntimeLinkedBuildInfo(t *testing.T) {
	originalVersion, originalOPA := Version, OpaVersion
	originalViperOPA := viper.GetString("opa-version")
	t.Cleanup(func() {
		Version, OpaVersion = originalVersion, originalOPA
		viper.Set("opa-version", originalViperOPA)
		verify.SetBuildInfo(originalVersion, originalOPA)
		resetCommandFlags(rootCmd)
		rootCmd.SetArgs(nil)
	})

	Version = "v9.9.9-test"
	OpaVersion = "v9.9.8-test"
	repoPath := t.TempDir()
	repo, err := git.PlainInit(repoPath, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "evidence.txt"), []byte("evidence\n"), 0o600))
	_, err = worktree.Add("evidence.txt")
	require.NoError(t, err)
	_, err = worktree.Commit("test evidence", &git.CommitOptions{Author: &object.Signature{
		Name: "Test", Email: "test@example.com", When: time.Unix(0, 0),
	}})
	require.NoError(t, err)

	policyPath := filepath.Join(repoPath, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"protected_branches":{"refs/heads/master":{}}}`), 0o600))
	vsaPath := filepath.Join(repoPath, "vsa.json")
	rootCmd.SetArgs([]string{"verify", "policy", "--repo-path", repoPath, "--ref", "refs/heads/master", "--policy-path", policyPath, "--generate-vsa", "--vsa-output", vsaPath, "--policy-uri", "https://example.test/policy", "--quiet"})
	require.NoError(t, rootCmd.Execute())

	var statement struct {
		Predicate struct {
			Verifier struct {
				Version map[string]string `json:"version"`
			} `json:"verifier"`
		} `json:"predicate"`
	}
	data, err := os.ReadFile(vsaPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &statement))
	require.Equal(t, Version, statement.Predicate.Verifier.Version["autogov"])

	require.Equal(t, OpaVersion, viper.GetString("opa-version"))
}

func resetCommandFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		_ = flag.Value.Set(flag.DefValue)
		flag.Changed = false
	})
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		_ = flag.Value.Set(flag.DefValue)
		flag.Changed = false
	})
	for _, child := range cmd.Commands() {
		resetCommandFlags(child)
	}
}
