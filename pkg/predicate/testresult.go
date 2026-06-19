package predicate

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
)

// TestResultPredicateTypeURI is the in-toto test-result predicate type.
const TestResultPredicateTypeURI = "https://in-toto.io/attestation/test-result/v0.1"

// Result values for the in-toto test-result predicate.
const (
	TestResultPassed = "PASSED"
	TestResultWarned = "WARNED"
	TestResultFailed = "FAILED"
)

// ResourceDescriptor is an in-toto v1 ResourceDescriptor. Per spec a descriptor
// must specify at least one of uri, digest, or content.
type ResourceDescriptor struct {
	Name             string            `json:"name,omitempty"`
	URI              string            `json:"uri,omitempty"`
	Digest           map[string]string `json:"digest,omitempty"`
	Content          string            `json:"content,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	MediaType        string            `json:"mediaType,omitempty"`
	Annotations      map[string]any    `json:"annotations,omitempty"`
}

// TestResult represents the predicate portion of an in-toto test-result
// attestation (https://in-toto.io/attestation/test-result/v0.1).
type TestResult struct {
	Type        ArtifactType `json:"-"`
	SubjectName string       `json:"-"`
	SubjectPath string       `json:"-"`
	Digest      string       `json:"-"`

	// Result is one of PASSED, WARNED, or FAILED.
	Result string `json:"result"`
	// Configuration references the configuration used for the test run. Required
	// by the spec; may be an empty list when no configuration is referenced.
	Configuration []ResourceDescriptor `json:"configuration"`
	// URL optionally links to the test run (e.g. logs).
	URL string `json:"url,omitempty"`
	// PassedTests, WarnedTests, FailedTests hold test identifiers by outcome.
	// Skipped tests map to warnedTests. Never null (empty arrays preferred).
	PassedTests []string `json:"passedTests"`
	WarnedTests []string `json:"warnedTests"`
	FailedTests []string `json:"failedTests"`
}

// TestResultOptions contains options for creating a test-result predicate.
type TestResultOptions struct {
	Type        ArtifactType
	SubjectName string
	SubjectPath string
	Digest      string
	ResultsPath string
	URL         string
	ConfigURI   string
}

// junitTestSuites models the JUnit <testsuites> root.
type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

// junitTestSuite models a JUnit <testsuite> element (also valid as a root).
type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

// junitTestCase models a JUnit <testcase>; the child pointers indicate outcome.
type junitTestCase struct {
	Name      string    `xml:"name,attr"`
	ClassName string    `xml:"classname,attr"`
	Failure   *struct{} `xml:"failure"`
	Error     *struct{} `xml:"error"`
	Skipped   *struct{} `xml:"skipped"`
}

// id returns a stable identifier for a test case (classname.name when present).
func (tc junitTestCase) id() string {
	if tc.ClassName != "" {
		return tc.ClassName + "." + tc.Name
	}
	return tc.Name
}

// parseJUnit parses JUnit XML with either a <testsuites> root or a single
// <testsuite> root, returning the flat list of suites.
func parseJUnit(data []byte) ([]junitTestSuite, error) {
	var multi junitTestSuites
	if err := xml.Unmarshal(data, &multi); err == nil && multi.XMLName.Local == "testsuites" {
		return multi.Suites, nil
	}

	var single junitTestSuite
	if err := xml.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("failed to parse JUnit XML: %w", err)
	}
	if single.XMLName.Local != "testsuite" {
		return nil, fmt.Errorf("unrecognized JUnit XML: expected <testsuites> or <testsuite> root")
	}
	return []junitTestSuite{single}, nil
}

// NewTestResult builds an in-toto test-result predicate from JUnit XML.
func NewTestResult(opts TestResultOptions) (*TestResult, error) {
	data, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	suites, err := parseJUnit(data)
	if err != nil {
		return nil, err
	}

	t := &TestResult{
		Type:          opts.Type,
		SubjectName:   opts.SubjectName,
		SubjectPath:   opts.SubjectPath,
		Digest:        opts.Digest,
		URL:           opts.URL,
		Configuration: []ResourceDescriptor{},
		PassedTests:   []string{},
		WarnedTests:   []string{},
		FailedTests:   []string{},
	}

	if opts.ConfigURI != "" {
		t.Configuration = append(t.Configuration, ResourceDescriptor{URI: opts.ConfigURI})
	}

	for _, s := range suites {
		for _, tc := range s.TestCases {
			switch {
			case tc.Failure != nil || tc.Error != nil:
				t.FailedTests = append(t.FailedTests, tc.id())
			case tc.Skipped != nil:
				t.WarnedTests = append(t.WarnedTests, tc.id())
			default:
				t.PassedTests = append(t.PassedTests, tc.id())
			}
		}
	}

	switch {
	case len(t.FailedTests) > 0:
		t.Result = TestResultFailed
	case len(t.WarnedTests) > 0:
		t.Result = TestResultWarned
	default:
		t.Result = TestResultPassed
	}

	return t, nil
}

// Generate produces the JSON representation of the test-result predicate.
func (t *TestResult) Generate() ([]byte, error) {
	return json.MarshalIndent(t, "", "  ")
}

// GenerateTestResult generates an in-toto test-result attestation predicate from JUnit XML.
func GenerateTestResult(opts TestResultOptions, outputFile string) error {
	t, err := NewTestResult(opts)
	if err != nil {
		return err
	}

	output, err := t.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate predicate: %w", err)
	}

	if err := ValidateTestResult(output); err != nil {
		return fmt.Errorf("failed to validate test-result: %w", err)
	}

	return writeOutput(output, outputFile)
}
