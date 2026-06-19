package predicate

import (
	"fmt"

	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/spf13/cobra"
)

var testResultCmd = &cobra.Command{
	Use:   "test-result",
	Short: "Generate test-result attestation predicate from JUnit XML",
	Long: `Generate an in-toto test-result attestation predicate from a JUnit XML report.

JUnit XML is the common interchange format emitted by most test runners, so this
is framework-agnostic — point --results-path at the report your tool produces:

  pytest:   pytest --junitxml=report.xml
  go:       go test -v ./... | go-junit-report > report.xml
  jest:     jest --reporters=default --reporters=jest-junit
  maven:    target/surefire-reports/*.xml (or aggregate them)
  gradle:   build/test-results/test/*.xml

Test cases are classified into passedTests, warnedTests (skipped), and failedTests
(failure or error); result is FAILED when any test failed or errored, else PASSED.`,
	RunE: runTestResult,
}

var (
	testResultResultsPath   string
	testResultSubjectName   string
	testResultSubjectPath   string
	testResultSubjectDigest string
	testResultOutput        string
	testResultType          string
	testResultURL           string
)

func init() {
	flags := testResultCmd.Flags()
	flags.StringVar(&testResultResultsPath, "results-path", "", "Path to a JUnit XML test report (from pytest --junitxml, go-junit-report, jest-junit, surefire, etc.)")
	flags.StringVar(&testResultSubjectName, "subject-name", "", "Name of the subject being tested (required for image type)")
	flags.StringVar(&testResultSubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&testResultSubjectDigest, "subject-digest", "", "Digest of the subject (required for image type, auto-calculated for blobs)")
	flags.StringVar(&testResultOutput, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&testResultType, "type", "image", "Type of artifact (image or blob)")
	flags.StringVar(&testResultURL, "url", "", "Optional URL linking to the full test report")
	cobra.CheckErr(testResultCmd.MarkFlagRequired("results-path"))
}

func runTestResult(_ *cobra.Command, _ []string) error {
	var opts pred.TestResultOptions

	opts.ResultsPath = testResultResultsPath
	opts.SubjectName = testResultSubjectName
	opts.SubjectPath = testResultSubjectPath
	opts.Digest = testResultSubjectDigest
	opts.URL = testResultURL

	switch testResultType {
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
		return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", testResultType)
	}

	return pred.GenerateTestResult(opts, testResultOutput)
}
