package predicate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/liatrio/autogov/pkg/attestations"
)

func writeSARIF(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "results.sarif")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	return path
}

// realisticSARIF exercises level resolution (omitted level -> rule default ->
// warning), security-severity bucketing, suppression, baselineState, an excluded
// non-fail result, and multiple runs/tools.
const realisticSARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodeQL",
          "version": "2.16.0",
          "informationUri": "https://codeql.github.com",
          "rules": [
            {"id": "js/sql-injection", "defaultConfiguration": {"level": "error"}, "properties": {"security-severity": "9.8"}},
            {"id": "js/weak-crypto", "defaultConfiguration": {"level": "warning"}, "properties": {"security-severity": "7.0"}},
            {"id": "js/unused-var", "defaultConfiguration": {"level": "note"}}
          ]
        }
      },
      "invocations": [
        {"executionSuccessful": true, "startTimeUtc": "2026-06-19T10:00:00Z", "endTimeUtc": "2026-06-19T10:05:00Z"}
      ],
      "results": [
        {"ruleId": "js/sql-injection", "kind": "fail", "baselineState": "new",
         "message": {"text": "sql injection"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.js"}, "region": {"startLine": 10, "endLine": 12}}}]},
        {"ruleId": "js/weak-crypto", "level": "warning", "baselineState": "unchanged",
         "message": {"text": "weak crypto"}},
        {"ruleId": "js/unused-var", "baselineState": "updated", "message": {"text": "unused"}},
        {"ruleId": "js/sql-injection", "kind": "pass", "message": {"text": "passed"}},
        {"ruleId": "js/weak-crypto", "level": "error", "message": {"text": "suppressed one"},
         "suppressions": [{"kind": "external"}]}
      ]
    },
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "version": "1.0.0",
          "rules": [
            {"id": "py/weak-hash", "defaultConfiguration": {"level": "warning"}, "properties": {"security-severity": "5.5"}}
          ]
        }
      },
      "invocations": [{"executionSuccessful": true}],
      "results": [
        {"ruleId": "py/weak-hash", "level": "warning", "message": {"text": "md5"}}
      ]
    }
  ]
}`

func TestNewCodeScan_SummaryAndExclusions(t *testing.T) {
	path := writeSARIF(t, realisticSARIF)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, Type: ArtifactTypeContainerImage})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}

	// two tools, in run order
	if len(c.Tools) != 2 || c.Tools[0].Name != "CodeQL" || c.Tools[1].Name != "semgrep" {
		t.Errorf("tools = %+v, want [CodeQL semgrep]", c.Tools)
	}

	// byLevel: r1 error, r2 warning, r3 note (resolved from rule), run1 warning.
	// the suppressed r5 (level error) and the pass-kind r4 are excluded.
	bl := c.Summary.ByLevel
	if bl.Error != 1 || bl.Warning != 2 || bl.Note != 1 || bl.None != 0 || bl.Total != 4 {
		t.Errorf("byLevel = %+v, want error1 warning2 note1 none0 total4", bl)
	}

	// bySecuritySeverity: 9.8 critical, 7.0 high, 5.5 medium, unused-var none.
	bs := c.Summary.BySecuritySeverity
	if bs.Critical != 1 || bs.High != 1 || bs.Medium != 1 || bs.Low != 0 || bs.None != 1 || bs.Total != 4 {
		t.Errorf("bySecuritySeverity = %+v, want crit1 high1 med1 low0 none1 total4", bs)
	}

	if c.Summary.Suppressed != 1 {
		t.Errorf("suppressed = %d, want 1", c.Summary.Suppressed)
	}
	// new + updated = 2 (unchanged is not counted)
	if c.Summary.New != 2 {
		t.Errorf("new = %d, want 2 (new + updated)", c.Summary.New)
	}
	// resultCount = byLevel.total + suppressed
	if c.ResultCount != 5 {
		t.Errorf("resultCount = %d, want 5", c.ResultCount)
	}
	if !c.Invocation.ExecutionSuccessful {
		t.Error("executionSuccessful = false, want true")
	}
	if c.ScanStartedOn != "2026-06-19T10:00:00Z" || c.ScanFinishedOn != "2026-06-19T10:05:00Z" {
		t.Errorf("scan window = %s..%s", c.ScanStartedOn, c.ScanFinishedOn)
	}
}

func TestNewCodeScan_FindingsExcludedByDefault(t *testing.T) {
	path := writeSARIF(t, realisticSARIF)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, Type: ArtifactTypeBlob})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if c.FindingsIncluded {
		t.Error("findingsIncluded = true, want false by default")
	}
	if c.Results != nil {
		t.Errorf("results = %+v, want nil (excluded by default)", c.Results)
	}
	if !c.Truncated {
		t.Error("truncated = false, want true when findings excluded with results present")
	}
	// summary must still be populated for gating without findings
	if c.Summary.ByLevel.Total == 0 {
		t.Error("summary must be populated even when findings excluded")
	}
}

func TestNewCodeScan_IncludeFindings(t *testing.T) {
	path := writeSARIF(t, realisticSARIF)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, Type: ArtifactTypeBlob, IncludeFindings: true})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if !c.FindingsIncluded || c.Truncated {
		t.Errorf("findingsIncluded=%v truncated=%v, want true/false", c.FindingsIncluded, c.Truncated)
	}
	// all five fail-kind findings (incl. the suppressed one), pass-kind excluded
	if len(c.Results) != 5 {
		t.Fatalf("results len = %d, want 5", len(c.Results))
	}
	// deterministic sort by ruleId then uri then line
	ids := make([]string, len(c.Results))
	for i, f := range c.Results {
		ids[i] = f.RuleID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by ruleId: %v", ids)
	}
	// the suppressed finding is present and flagged
	var sawSuppressed bool
	for _, f := range c.Results {
		if f.Suppressed {
			sawSuppressed = true
			if f.SuppressionKind != "external" {
				t.Errorf("suppressionKind = %q, want external", f.SuppressionKind)
			}
		}
	}
	if !sawSuppressed {
		t.Error("expected a suppressed finding in results")
	}
}

func TestNewCodeScan_MaxFindingsTruncates(t *testing.T) {
	path := writeSARIF(t, realisticSARIF)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, Type: ArtifactTypeBlob, IncludeFindings: true, MaxFindings: 2})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if len(c.Results) != 2 || !c.Truncated {
		t.Errorf("len=%d truncated=%v, want 2/true", len(c.Results), c.Truncated)
	}
	if c.ResultCount != 5 {
		t.Errorf("resultCount = %d, want 5 (full count despite truncation)", c.ResultCount)
	}
}

func TestNewCodeScan_IncompleteScan(t *testing.T) {
	sarif := `{"version":"2.1.0","runs":[
      {"tool":{"driver":{"name":"CodeQL"}},"invocations":[{"executionSuccessful":true}],"results":[]},
      {"tool":{"driver":{"name":"CodeQL"}},"invocations":[{"executionSuccessful":false}],"results":[]}
    ]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if c.Invocation.ExecutionSuccessful {
		t.Error("executionSuccessful = true, want false (one invocation failed)")
	}
}

func TestNewCodeScan_Empty(t *testing.T) {
	path := writeSARIF(t, `{"version":"2.1.0","runs":[]}`)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if c.ResultCount != 0 || c.Truncated {
		t.Errorf("empty: resultCount=%d truncated=%v, want 0/false", c.ResultCount, c.Truncated)
	}
	// arrays must be non-nil for clean JSON
	if c.Tools == nil || c.Configuration == nil {
		t.Error("tools/configuration must be non-nil empty arrays")
	}
	if !c.Invocation.ExecutionSuccessful {
		t.Error("empty scan should default executionSuccessful=true")
	}
}

func TestSecuritySeverityBucket(t *testing.T) {
	cases := map[string]string{
		"10":  sevCritical,
		"9.8": sevCritical,
		"9":   sevCritical,
		"8.9": sevHigh,
		"7":   sevHigh,
		"6.9": sevMedium,
		"4":   sevMedium,
		"3.9": sevLow,
		"0.1": sevLow,
		"0":   sevNone,
		"-1":  sevNone,
		"":    sevNone,
		"abc": sevNone,
	}
	for in, want := range cases {
		if got := securitySeverityBucket(in); got != want {
			t.Errorf("securitySeverityBucket(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewCodeScan_BoundsUntrustedText(t *testing.T) {
	long := strings.Repeat("A", 1000)
	fps := strings.Builder{}
	for i := range 40 {
		if i > 0 {
			fps.WriteString(",")
		}
		fps.WriteString(`"k` + string(rune('a'+i%26)) + string(rune('0'+i/26)) + `":"v"`)
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[
      {"ruleId":"x","kind":"fail","message":{"text":"` + long + `"},"partialFingerprints":{` + fps.String() + `}}
    ]}]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, IncludeFindings: true})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if len(c.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(c.Results))
	}
	if got := len([]rune(c.Results[0].Message)); got != maxMessageRunes {
		t.Errorf("message len = %d, want %d (capped)", got, maxMessageRunes)
	}
	if got := len(c.Results[0].PartialFingerprints); got > maxFingerprintEntries {
		t.Errorf("fingerprints = %d, want <= %d", got, maxFingerprintEntries)
	}
}

func TestNewCodeScan_DropsUnknownBaselineState(t *testing.T) {
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[
      {"ruleId":"x","kind":"fail","baselineState":"bogus","message":{"text":"m"}}
    ]}]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, IncludeFindings: true})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if c.Results[0].BaselineState != "" {
		t.Errorf("baselineState = %q, want empty (unknown dropped)", c.Results[0].BaselineState)
	}
}

func TestCodeScan_GenerateValidatesAgainstSchema(t *testing.T) {
	path := writeSARIF(t, realisticSARIF)

	for _, include := range []bool{false, true} {
		c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, Type: ArtifactTypeBlob, IncludeFindings: include, ConfigURI: "https://ci/scan.yml@sha"})
		if err != nil {
			t.Fatalf("NewCodeScan(include=%v): %v", include, err)
		}
		out, err := c.Generate()
		if err != nil {
			t.Fatalf("Generate(include=%v): %v", include, err)
		}
		if err := ValidateCodeScan(out); err != nil {
			t.Errorf("ValidateCodeScan(include=%v): %v", include, err)
		}
	}
}

func TestNewCodeScan_NormalizesLevel(t *testing.T) {
	// "critical" is not a SARIF level -> falls back to warning; "ERROR" folds to
	// error (severity preserved); a bogus rule default also falls back.
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"X","rules":[
        {"id":"r3","defaultConfiguration":{"level":"blocker"}}
      ]}},"results":[
        {"ruleId":"r1","kind":"fail","level":"critical","message":{"text":"a"}},
        {"ruleId":"r2","kind":"fail","level":"ERROR","message":{"text":"b"}},
        {"ruleId":"r3","kind":"fail","message":{"text":"c"}}
      ]}]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, IncludeFindings: true})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	// r2 "ERROR" -> error; r1 "critical" and r3 "blocker" -> warning
	if c.Summary.ByLevel.Error != 1 || c.Summary.ByLevel.Warning != 2 {
		t.Errorf("byLevel = %+v, want error1 warning2", c.Summary.ByLevel)
	}
	for _, f := range c.Results {
		switch f.Level {
		case levelError, levelWarning, levelNote, levelNone:
		default:
			t.Errorf("finding %s has non-enum level %q", f.RuleID, f.Level)
		}
	}
	// crucially, the bogus levels must not break schema validation
	out, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ValidateCodeScan(out); err != nil {
		t.Errorf("ValidateCodeScan with non-enum input levels: %v", err)
	}
}

func TestNewCodeScan_SuppressionStatus(t *testing.T) {
	// a rejected suppression must NOT suppress (the finding stays gated).
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"X","rules":[
        {"id":"r","defaultConfiguration":{"level":"error"},"properties":{"security-severity":"9.5"}}
      ]}},"results":[
        {"ruleId":"r","kind":"fail","message":{"text":"rejected"},"suppressions":[{"kind":"inSource","status":"rejected"}]},
        {"ruleId":"r","kind":"fail","message":{"text":"underReview"},"suppressions":[{"kind":"inSource","status":"underReview"}]},
        {"ruleId":"r","kind":"fail","message":{"text":"accepted"},"suppressions":[{"kind":"external","status":"accepted"}]},
        {"ruleId":"r","kind":"fail","message":{"text":"nostatus"},"suppressions":[{"kind":"external"}]}
      ]}]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	// rejected + underReview are NOT suppressed -> 2 critical/error counted;
	// accepted + absent-status ARE suppressed -> suppressed = 2.
	if c.Summary.BySecuritySeverity.Critical != 2 || c.Summary.ByLevel.Error != 2 {
		t.Errorf("counts = sev %+v level %+v, want 2 critical / 2 error", c.Summary.BySecuritySeverity, c.Summary.ByLevel)
	}
	if c.Summary.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", c.Summary.Suppressed)
	}
	if c.ResultCount != 4 {
		t.Errorf("resultCount = %d, want 4", c.ResultCount)
	}
}

func TestNewCodeScan_ClampsNegativeLines(t *testing.T) {
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"X"}},"results":[
        {"ruleId":"r","kind":"fail","message":{"text":"m"},
         "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":-5,"endLine":-2}}}]}
      ]}]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, IncludeFindings: true})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if c.Results[0].Location == nil || c.Results[0].Location.URI != "a.go" {
		t.Fatalf("location = %+v, want uri a.go", c.Results[0].Location)
	}
	if c.Results[0].Location.StartLine != 0 || c.Results[0].Location.EndLine != 0 {
		t.Errorf("lines = %d/%d, want 0/0 (negatives dropped)", c.Results[0].Location.StartLine, c.Results[0].Location.EndLine)
	}
	out, _ := c.Generate()
	if err := ValidateCodeScan(out); err != nil {
		t.Errorf("ValidateCodeScan with negative region: %v", err)
	}
}

func TestNewCodeScan_BoundsRuleIDAndTool(t *testing.T) {
	bigName := strings.Repeat("T", 5000)
	bigRule := strings.Repeat("R", 5000)
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + bigName + `"}},"results":[
        {"ruleId":"` + bigRule + `","kind":"fail","message":{"text":"m"}}
      ]}]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path, IncludeFindings: true})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if got := len([]rune(c.Tools[0].Name)); got > maxToolFieldLen {
		t.Errorf("tool name len = %d, want <= %d", got, maxToolFieldLen)
	}
	if got := len([]rune(c.Results[0].RuleID)); got > maxRuleIDLen {
		t.Errorf("ruleId len = %d, want <= %d", got, maxRuleIDLen)
	}
	out, _ := c.Generate()
	if err := ValidateCodeScan(out); err != nil {
		t.Errorf("ValidateCodeScan with oversized strings: %v", err)
	}
}

func TestNewCodeScan_DedupesTools(t *testing.T) {
	// three CodeQL runs (per-language) collapse to one tool entry.
	sarif := `{"version":"2.1.0","runs":[
        {"tool":{"driver":{"name":"CodeQL","version":"2.16.0"}},"results":[]},
        {"tool":{"driver":{"name":"CodeQL","version":"2.16.0"}},"results":[]},
        {"tool":{"driver":{"name":"CodeQL","version":"2.16.0"}},"results":[]}
      ]}`
	path := writeSARIF(t, sarif)
	c, err := NewCodeScan(CodeScanOptions{ResultsPath: path})
	if err != nil {
		t.Fatalf("NewCodeScan: %v", err)
	}
	if len(c.Tools) != 1 {
		t.Errorf("tools = %d, want 1 (deduped)", len(c.Tools))
	}
}

func TestNewCodeScan_MissingFile(t *testing.T) {
	if _, err := NewCodeScan(CodeScanOptions{ResultsPath: "/nonexistent.sarif"}); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNewCodeScan_InvalidJSON(t *testing.T) {
	path := writeSARIF(t, `not json`)
	if _, err := NewCodeScan(CodeScanOptions{ResultsPath: path}); err == nil {
		t.Error("expected error for invalid SARIF")
	}
}

// TestCodeScan_PredicateTypeConsistency locks the predicate type URI across the
// Go const, the embedded schema const, and the verify-side registry. A drift in
// any one of these silently breaks gating, so it must fail the build.
func TestCodeScan_PredicateTypeConsistency(t *testing.T) {
	const want = "https://autogov.dev/attestation/code-scan/v0.1"

	if CodeScanPredicateTypeURI != want {
		t.Errorf("CodeScanPredicateTypeURI = %q, want %q", CodeScanPredicateTypeURI, want)
	}
	if attestations.PredicateTypeAutogovCodeScan != want {
		t.Errorf("registry const = %q, want %q", attestations.PredicateTypeAutogovCodeScan, want)
	}
	info, ok := attestations.PredicateTypeRegistry[want]
	if !ok || info.ShortName != "AutoGov Code Scan" {
		t.Errorf("registry entry = %+v (ok=%v), want ShortName 'AutoGov Code Scan'", info, ok)
	}

	// schema predicateType const
	var schema map[string]any
	if err := json.Unmarshal([]byte(getEmbeddedSchema("code-scan-schema.json")), &schema); err != nil {
		t.Fatalf("parse embedded schema: %v", err)
	}
	props := schema["properties"].(map[string]any)
	pt := props["predicateType"].(map[string]any)
	if pt["const"] != want {
		t.Errorf("schema predicateType const = %v, want %q", pt["const"], want)
	}
}
