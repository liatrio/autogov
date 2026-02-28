package verify_test

import (
	"bytes"
	"testing"

	"github.com/liatrio/autogov/cmd/verify"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newVerifySourceCmd() *cobra.Command {
	root := &cobra.Command{Use: "autogov"}
	vc := verify.NewVerifyCmdForTesting()
	root.AddCommand(vc)
	return root
}

func executeVerifySourceCmd(t *testing.T, args []string) (string, error) {
	t.Helper()

	root := newVerifySourceCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"verify", "source"}, args...))

	err := root.Execute()
	return buf.String(), err
}

func TestVerifySource_MissingAttestationPath(t *testing.T) {
	_, err := executeVerifySourceCmd(t, []string{
		"--repo-uri", "https://github.com/org/repo",
		"--commit", "abc123",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation-path")
}

func TestVerifySource_MissingRepoURI(t *testing.T) {
	_, err := executeVerifySourceCmd(t, []string{
		"--attestation-path", "bundle.json",
		"--commit", "abc123",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repo-uri")
}

func TestVerifySource_MissingCommit(t *testing.T) {
	_, err := executeVerifySourceCmd(t, []string{
		"--attestation-path", "bundle.json",
		"--repo-uri", "https://github.com/org/repo",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit")
}

func TestVerifySource_HelpOutput(t *testing.T) {
	out, err := executeVerifySourceCmd(t, []string{"--help"})
	require.NoError(t, err)

	assert.Contains(t, out, "--attestation-path")
	assert.Contains(t, out, "--repo-uri")
	assert.Contains(t, out, "--commit")
	assert.Contains(t, out, "--source-ref")
	assert.Contains(t, out, "--cert-identity")
	assert.Contains(t, out, "--cert-issuer")
	assert.Contains(t, out, "--format")
	assert.Contains(t, out, "--quiet")
}

func TestVerifySource_FormatFlagRegistered(t *testing.T) {
	out, err := executeVerifySourceCmd(t, []string{"--help"})
	require.NoError(t, err)
	assert.Contains(t, out, "text, json")
}

func TestVerifySource_VSAFlagsRegistered(t *testing.T) {
	out, err := executeVerifySourceCmd(t, []string{"--help"})
	require.NoError(t, err)
	assert.Contains(t, out, "--generate-vsa")
	assert.Contains(t, out, "--vsa-output")
	assert.Contains(t, out, "--policy-uri")
}
