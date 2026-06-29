package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestCommandGroupsAreRunnable is a regression guard for the fail-open fixed in
// the verify/predicate/release groups: a cobra parent with no Run/RunE is
// non-runnable, and cobra returns flag.ErrHelp (prints help, exits 0) before it
// ever reaches arg validation — so an unknown subcommand silently "passes".
//
// Every autogov command group (a non-root command that has subcommands) must
// therefore be runnable, so cobra runs ValidateArgs and NoArgs rejects unknown
// subcommands with a non-zero exit. The root is exempt: cobra's legacyArgs only
// raises "unknown command" for the root, which already errors on a typo.
//
// This walks the live command tree, so a future group added without a RunE
// fails the build rather than reintroducing the fail-open.
func TestCommandGroupsAreRunnable(t *testing.T) {
	// cobra's auto-generated built-ins are not autogov's concern.
	builtin := map[string]bool{"help": true, "completion": true}

	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if builtin[sub.Name()] {
				continue
			}
			if sub.HasAvailableSubCommands() && !sub.Runnable() {
				t.Errorf("command group %q has subcommands but is not runnable (no Run/RunE); "+
					"an unknown subcommand will print help and exit 0 — add a no-op RunE (see cmd/verify/verify.go)",
					sub.CommandPath())
			}
			walk(sub)
		}
	}
	walk(GetRootCmd())
}
