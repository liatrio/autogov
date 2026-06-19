package predicate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeJUnit(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "junit.xml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write junit: %v", err)
	}
	return path
}

func TestNewTestResult_FailingTestsuites(t *testing.T) {
	path := writeJUnit(t, `<testsuites>
  <testsuite name="pkg/foo">
    <testcase name="TestA" classname="pkg/foo"/>
    <testcase name="TestB" classname="pkg/foo"><failure message="boom"/></testcase>
  </testsuite>
  <testsuite name="pkg/bar">
    <testcase name="TestC" classname="pkg/bar"/>
    <testcase name="TestD" classname="pkg/bar"><skipped/></testcase>
  </testsuite>
</testsuites>`)

	tr, err := NewTestResult(TestResultOptions{ResultsPath: path, Type: ArtifactTypeContainerImage})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	if tr.Result != TestResultFailed {
		t.Errorf("result = %q, want FAILED", tr.Result)
	}
	if !slices.Equal(tr.FailedTests, []string{"pkg/foo.TestB"}) {
		t.Errorf("failedTests = %v, want [pkg/foo.TestB]", tr.FailedTests)
	}
	if !slices.Equal(tr.WarnedTests, []string{"pkg/bar.TestD"}) {
		t.Errorf("warnedTests = %v, want [pkg/bar.TestD]", tr.WarnedTests)
	}
	if !slices.Equal(tr.PassedTests, []string{"pkg/foo.TestA", "pkg/bar.TestC"}) {
		t.Errorf("passedTests = %v, want [pkg/foo.TestA pkg/bar.TestC]", tr.PassedTests)
	}
	// configuration is required by the in-toto spec and must always be present.
	if tr.Configuration == nil {
		t.Error("configuration must be non-nil (empty list), got nil")
	}
}

func TestNewTestResult_PassingSingleSuite(t *testing.T) {
	path := writeJUnit(t, `<testsuite name="all">
  <testcase name="TestA" classname="all"/>
  <testcase name="TestB" classname="all"/>
</testsuite>`)

	tr, err := NewTestResult(TestResultOptions{ResultsPath: path, Type: ArtifactTypeBlob, URL: "https://ci/run/1"})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	if tr.Result != TestResultPassed {
		t.Errorf("result = %q, want PASSED", tr.Result)
	}
	if len(tr.PassedTests) != 2 || len(tr.FailedTests) != 0 {
		t.Errorf("passed=%d failed=%d, want 2/0", len(tr.PassedTests), len(tr.FailedTests))
	}
	if tr.URL != "https://ci/run/1" {
		t.Errorf("url = %q, want https://ci/run/1", tr.URL)
	}
}

func TestNewTestResult_WarnedOnSkippedOnly(t *testing.T) {
	path := writeJUnit(t, `<testsuite name="s">
  <testcase name="TestA" classname="s"/>
  <testcase name="TestB" classname="s"><skipped/></testcase>
</testsuite>`)
	tr, err := NewTestResult(TestResultOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	if tr.Result != TestResultWarned {
		t.Errorf("result = %q, want WARNED (skipped, no failures)", tr.Result)
	}
	if !slices.Equal(tr.WarnedTests, []string{"s.TestB"}) {
		t.Errorf("warnedTests = %v, want [s.TestB]", tr.WarnedTests)
	}
}

func TestNewTestResult_ErrorsCountAsFailed(t *testing.T) {
	path := writeJUnit(t, `<testsuite name="e">
  <testcase name="TestA" classname="e"/>
  <testcase name="TestB" classname="e"><error message="panic"/></testcase>
</testsuite>`)
	tr, err := NewTestResult(TestResultOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	if tr.Result != TestResultFailed {
		t.Errorf("result = %q, want FAILED (error present)", tr.Result)
	}
	if !slices.Equal(tr.FailedTests, []string{"e.TestB"}) {
		t.Errorf("failedTests = %v, want [e.TestB]", tr.FailedTests)
	}
}

func TestNewTestResult_ConfigURIPopulatesConfiguration(t *testing.T) {
	path := writeJUnit(t, `<testsuite name="s"><testcase name="TestA" classname="s"/></testsuite>`)
	tr, err := NewTestResult(TestResultOptions{ResultsPath: path, ConfigURI: "https://github.com/owner/repo/.github/workflows/test.yml@sha"})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	if len(tr.Configuration) != 1 || tr.Configuration[0].URI != "https://github.com/owner/repo/.github/workflows/test.yml@sha" {
		t.Errorf("configuration = %+v, want one descriptor with the config uri", tr.Configuration)
	}
}

func TestNewTestResult_EmptyArraysNotNull(t *testing.T) {
	path := writeJUnit(t, `<testsuite name="empty"></testsuite>`)
	tr, err := NewTestResult(TestResultOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	// in-toto consumers expect arrays, not null
	if tr.PassedTests == nil || tr.WarnedTests == nil || tr.FailedTests == nil || tr.Configuration == nil {
		t.Error("test arrays and configuration must be non-nil (empty), got a nil slice")
	}
	if tr.Result != TestResultPassed {
		t.Errorf("result = %q, want PASSED for empty suite", tr.Result)
	}
}

func TestNewTestResult_InvalidXML(t *testing.T) {
	path := writeJUnit(t, `not xml at all`)
	if _, err := NewTestResult(TestResultOptions{ResultsPath: path}); err == nil {
		t.Error("expected error for invalid XML, got nil")
	}
}

func TestNewTestResult_MissingFile(t *testing.T) {
	if _, err := NewTestResult(TestResultOptions{ResultsPath: "/nonexistent/junit.xml"}); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestTestResult_GenerateValidatesAgainstSchema(t *testing.T) {
	path := writeJUnit(t, `<testsuites>
  <testsuite name="s">
    <testcase name="TestA" classname="s"/>
  </testsuite>
</testsuites>`)
	// include a config descriptor so the required configuration field is exercised
	tr, err := NewTestResult(TestResultOptions{ResultsPath: path, ConfigURI: "https://ci/config"})
	if err != nil {
		t.Fatalf("NewTestResult: %v", err)
	}
	out, err := tr.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ValidateTestResult(out); err != nil {
		t.Errorf("ValidateTestResult: %v", err)
	}
}
