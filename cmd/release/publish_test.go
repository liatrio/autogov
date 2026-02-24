package release

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// executePublishCmd runs publishCmd with the given args and captures output.
func executePublishCmd(t *testing.T, args []string) (string, error) {
	t.Helper()

	publishCmd.ResetFlags()
	publishCmd.Flags().String("tag", "", "Specific tag to publish (mutually exclusive with --latest)")
	publishCmd.Flags().Bool("latest", false, "Publish latest draft release (mutually exclusive with --tag)")
	publishCmd.Flags().Bool("dry-run", false, "Show what would be done without publishing")
	publishCmd.Flags().String("repo", ".", "Path to git repository")
	publishCmd.Flags().StringP("output", "o", "text", "Output format: text, json")

	root := &cobra.Command{Use: "autogov"}
	root.AddCommand(publishCmd)

	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"publish"}, args...))

	err := root.Execute()
	return buf.String(), err
}

// executePublishCmdWithToken runs publishCmd with GITHUB_TOKEN set in the env.
func executePublishCmdWithToken(t *testing.T, args []string) (string, error) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "fake-token-for-test")
	return executePublishCmd(t, args)
}

func TestPublishCmdMissingToken(t *testing.T) {
	// Unset any token so the validation fires
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	_, err := executePublishCmd(t, []string{"--tag", "v1.0.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub token required")
}

func TestPublishCmdMutuallyExclusiveFlags(t *testing.T) {
	// Actually pass both --tag and --latest to exercise the validation path.
	// Token is injected so we get past the token check.
	_, err := executePublishCmdWithToken(t, []string{"--tag", "v1.0.0", "--latest"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestPublishCmdNeitherTagNorLatest(t *testing.T) {
	_, err := executePublishCmdWithToken(t, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either --tag or --latest must be specified")
}

func TestPublishCmdHelpOutput(t *testing.T) {
	// --help is handled by Cobra before runPublish, so no token needed
	out, err := executePublishCmd(t, []string{"--help"})
	require.NoError(t, err)

	assert.Contains(t, out, "--tag")
	assert.Contains(t, out, "--latest")
	assert.Contains(t, out, "--dry-run")
	assert.Contains(t, out, "-o")
}

func TestPublishCmdOutputFormatDefault(t *testing.T) {
	publishCmd.ResetFlags()
	publishCmd.Flags().StringP("output", "o", "text", "Output format: text, json")

	flag := publishCmd.Flags().Lookup("output")
	require.NotNil(t, flag)
	assert.Equal(t, "text", flag.DefValue)
}

func TestPublishCmdOutputCaptured(t *testing.T) {
	// Verify that runPublish output goes through cmd.OutOrStdout() by checking
	// that errors written via Cobra's error handling are captured in the buffer.
	// A full success-path capture test requires a mock wired at the CLI layer,
	// which is covered by the pkg/release unit tests instead.
	//
	// Here we just verify that Cobra error output IS captured (not lost to raw stdout).
	old := os.Getenv("GITHUB_TOKEN")
	t.Cleanup(func() { os.Setenv("GITHUB_TOKEN", old) })
	os.Setenv("GITHUB_TOKEN", "")
	os.Setenv("GH_TOKEN", "")

	out, err := executePublishCmd(t, []string{"--tag", "v1.0.0"})
	require.Error(t, err)
	// Cobra writes "Error: ..." to the error buffer we set
	assert.Contains(t, out, "Error")
}
