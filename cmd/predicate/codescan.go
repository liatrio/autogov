package predicate

import (
	"fmt"

	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/spf13/cobra"
)

var codeScanCmd = &cobra.Command{
	Use:   "code-scan",
	Short: "Generate code-scan attestation predicate from a SARIF report",
	Long: `Generate an autogov code-scan attestation predicate from a SARIF 2.1.0 report.

SARIF is the standard interchange format for static analysis, so this is
scanner-agnostic — point --results-path at the report your tool produces:

  CodeQL:    github/codeql-action upload artifact, or codeql database analyze --format=sarif-latest
  semgrep:   semgrep --sarif --output results.sarif
  others:    any SARIF 2.1.0 producer

Only fail-kind results are counted; each is bucketed by SARIF level and by the
rule's security-severity. Findings (file paths, lines, messages) are EXCLUDED by
default — pass --include-findings to embed them, noting the predicate is a
permanent, public, signed artifact.`,
	RunE: runCodeScan,
}

var (
	codeScanResultsPath     string
	codeScanSubjectName     string
	codeScanSubjectPath     string
	codeScanSubjectDigest   string
	codeScanOutput          string
	codeScanType            string
	codeScanIncludeFindings bool
	codeScanMaxFindings     int
	codeScanConfigURI       string
	codeScanCommitSHA       string
	codeScanRef             string
	codeScanURL             string
)

func init() {
	flags := codeScanCmd.Flags()
	flags.StringVar(&codeScanResultsPath, "results-path", "", "Path to a SARIF 2.1.0 report (from CodeQL, semgrep, etc.)")
	flags.StringVar(&codeScanSubjectName, "subject-name", "", "Name of the subject being scanned (required for image type)")
	flags.StringVar(&codeScanSubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&codeScanSubjectDigest, "subject-digest", "", "Digest of the subject (required for image type, auto-calculated for blobs)")
	flags.StringVar(&codeScanOutput, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&codeScanType, "type", "image", "Type of artifact (image or blob)")
	flags.BoolVar(&codeScanIncludeFindings, "include-findings", false, "Embed per-finding details (paths, lines, messages) in the predicate; off by default for privacy")
	flags.IntVar(&codeScanMaxFindings, "max-findings", 1000, "Maximum number of findings to embed when --include-findings is set")
	flags.StringVar(&codeScanConfigURI, "config-uri", "", "Optional URI of the scan configuration (populates the 'configuration' field)")
	flags.StringVar(&codeScanCommitSHA, "commit-sha", "", "Optional commit SHA of the scanned source")
	flags.StringVar(&codeScanRef, "ref", "", "Optional git ref of the scanned source")
	flags.StringVar(&codeScanURL, "url", "", "Optional URL linking to the full scan report")
	cobra.CheckErr(codeScanCmd.MarkFlagRequired("results-path"))
}

func runCodeScan(_ *cobra.Command, _ []string) error {
	var opts pred.CodeScanOptions

	opts.ResultsPath = codeScanResultsPath
	opts.SubjectName = codeScanSubjectName
	opts.SubjectPath = codeScanSubjectPath
	opts.Digest = codeScanSubjectDigest
	opts.IncludeFindings = codeScanIncludeFindings
	opts.MaxFindings = codeScanMaxFindings
	opts.ConfigURI = codeScanConfigURI
	opts.CommitSHA = codeScanCommitSHA
	opts.Ref = codeScanRef
	opts.URL = codeScanURL

	switch codeScanType {
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
		return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", codeScanType)
	}

	return pred.GenerateCodeScan(opts, codeScanOutput)
}
