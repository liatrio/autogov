package predicate

import (
	"fmt"

	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/spf13/cobra"
)

var depscanCmd = &cobra.Command{
	Use:   "depscan",
	Short: "Generate dependency scan attestation predicate",
	RunE:  runDepscan,
}

var (
	depscanResultsPath   string
	depscanSubjectName   string
	depscanSubjectPath   string
	depscanSubjectDigest string
	depscanOutput        string
	depscanType          string
)

func init() {
	flags := depscanCmd.Flags()
	flags.StringVar(&depscanResultsPath, "results-path", "", "Path to Grype results JSON file")
	flags.StringVar(&depscanSubjectName, "subject-name", "", "Name of the subject being scanned (required for image type)")
	flags.StringVar(&depscanSubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&depscanSubjectDigest, "subject-digest", "", "Digest of the subject (required for image type, auto-calculated for blobs)")
	flags.StringVar(&depscanOutput, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&depscanType, "type", "image", "Type of artifact (image or blob)")
	cobra.CheckErr(depscanCmd.MarkFlagRequired("results-path"))
}

func runDepscan(_ *cobra.Command, _ []string) error {
	var opts pred.DependencyScanOptions

	opts.ResultsPath = depscanResultsPath
	opts.SubjectName = depscanSubjectName
	opts.SubjectPath = depscanSubjectPath
	opts.Digest = depscanSubjectDigest

	switch depscanType {
	case "image":
		opts.Type = pred.ArtifactTypeContainerImage
		if opts.SubjectName == "" {
			return fmt.Errorf("--subject-name is required for image type")
		}
		if opts.Digest == "" {
			return fmt.Errorf("--subject-digest is required for image type")
		}
	case "blob":
		opts.Type = pred.ArtifactTypeBlob
		if opts.SubjectPath == "" {
			return fmt.Errorf("--subject-path is required for blob type")
		}
		// calculate digest for blob if not provided
		if opts.Digest == "" {
			digest, err := pred.CalculateDigest(opts.SubjectPath)
			if err != nil {
				return fmt.Errorf("failed to calculate digest: %w", err)
			}
			opts.Digest = digest
		}
	default:
		return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", depscanType)
	}

	return pred.GenerateDepscan(opts, depscanOutput)
}
