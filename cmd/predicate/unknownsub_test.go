package predicate

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPredicateUnknownSubcommandFailsClosed locks the fail-open fix: a typo'd
// predicate subcommand must return a non-zero error rather than printing help
// and exiting 0, while a bare `predicate` still shows help cleanly.
func TestPredicateUnknownSubcommandFailsClosed(t *testing.T) {
	newRoot := func() *cobra.Command {
		root := &cobra.Command{Use: "autogov", SilenceErrors: true, SilenceUsage: true}
		root.AddCommand(PredicateCmd)
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		return root
	}

	t.Run("unknown subcommand returns error", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"predicate", "bogus"})
		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown command")
	})

	t.Run("bare predicate shows help without error", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"predicate"})
		assert.NoError(t, root.Execute())
	})
}
