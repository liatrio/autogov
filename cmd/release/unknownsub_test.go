package release

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReleaseUnknownSubcommandFailsClosed locks the fail-open fix: a typo'd
// release subcommand must return a non-zero error rather than printing help and
// exiting 0, while a bare `release` still shows help cleanly.
func TestReleaseUnknownSubcommandFailsClosed(t *testing.T) {
	newRoot := func() *cobra.Command {
		root := &cobra.Command{Use: "autogov", SilenceErrors: true, SilenceUsage: true}
		root.AddCommand(ReleaseCmd)
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		return root
	}

	t.Run("unknown subcommand returns error", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"release", "bogus"})
		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown command")
	})

	t.Run("bare release shows help without error", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"release"})
		assert.NoError(t, root.Execute())
	})
}
