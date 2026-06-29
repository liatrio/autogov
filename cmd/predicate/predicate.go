package predicate

import "github.com/spf13/cobra"

// PredicateCmd is the parent command for predicate generation.
var PredicateCmd = &cobra.Command{
	Use:   "predicate",
	Short: "Generate attestation predicates",
	Long:  "Generate attestation predicates for metadata, dependency scan, test-result, code-scan, and source-review attestations.",
	// a no-op RunE makes this parent runnable so NoArgs is enforced; otherwise
	// cobra prints help and exits 0 for an unknown subcommand (see verify.go).
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

func init() {
	PredicateCmd.AddCommand(metadataCmd)
	PredicateCmd.AddCommand(depscanCmd)
	PredicateCmd.AddCommand(testResultCmd)
	PredicateCmd.AddCommand(codeScanCmd)
	PredicateCmd.AddCommand(sourceReviewCmd)
}
