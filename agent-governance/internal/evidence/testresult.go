package evidence

// TestResultPredicateTypeURI is the standard in-toto test-result predicate
// consumed by AutoGov as an otherwise unknown predicate.
const TestResultPredicateTypeURI = "https://in-toto.io/attestation/test-result/v0.1"

const (
	TestResultPassed = "PASSED"
	TestResultWarned = "WARNED"
	TestResultFailed = "FAILED"
)

// ResourceDescriptor is the small in-toto wire surface needed by the
// companion's conformance test-result statements.
type ResourceDescriptor struct {
	Name             string            `json:"name,omitempty"`
	URI              string            `json:"uri,omitempty"`
	Digest           map[string]string `json:"digest,omitempty"`
	Content          string            `json:"content,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	MediaType        string            `json:"mediaType,omitempty"`
	Annotations      map[string]any    `json:"annotations,omitempty"`
}

// TestResult is the standard test-result predicate wire used for the paired
// bounded observation. It intentionally has no AutoGov-specific fields.
type TestResult struct {
	Result        string               `json:"result"`
	Configuration []ResourceDescriptor `json:"configuration"`
	URL           string               `json:"url,omitempty"`
	PassedTests   []string             `json:"passedTests"`
	WarnedTests   []string             `json:"warnedTests"`
	FailedTests   []string             `json:"failedTests"`
}
