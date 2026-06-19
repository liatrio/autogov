package predicate

import "github.com/spf13/cobra"

// PredicateCmd is the parent command for predicate generation.
var PredicateCmd = &cobra.Command{
	Use:   "predicate",
	Short: "Generate attestation predicates",
	Long:  "Generate attestation predicates for metadata, dependency scan, and test-result attestations.",
}

func init() {
	PredicateCmd.AddCommand(metadataCmd)
	PredicateCmd.AddCommand(depscanCmd)
	PredicateCmd.AddCommand(testResultCmd)
}
