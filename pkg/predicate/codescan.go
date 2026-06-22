package predicate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// SARIF result.kind values. Only "fail" denotes an actual finding; the others
// describe a rule that ran without producing a defect and must NOT be counted
// or gated. "fail" is also the SARIF default when kind is absent.
const (
	sarifKindFail = "fail"
)

// SARIF result.level values (also used by autogov byLevel buckets).
const (
	levelError   = "error"
	levelWarning = "warning"
	levelNote    = "note"
	levelNone    = "none"
)

// security-severity buckets. Boundaries are half-open per GitHub code-scanning
// convention: critical [9,10], high [7,9), medium [4,7), low (0,4). A fail-kind
// finding with no numeric security-severity is bucketed as "none".
const (
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
	sevNone     = "none"
)

// caps that bound untrusted scanner free-text in a signed, public attestation.
const (
	maxMessageRunes        = 512
	maxFingerprintEntries  = 16
	maxFingerprintKeyLen   = 128
	maxFingerprintValueLen = 256
	maxSuppressionKindLen  = 64
	maxSecuritySeverityLen = 32
	maxRuleIDLen           = 256
	maxToolFieldLen        = 256
	maxTimestampLen        = 64
	maxTools               = 64
	defaultMaxFindings     = 1000
)

// CodeScanLevelCounts counts fail-kind findings by resolved SARIF level.
type CodeScanLevelCounts struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Note    int `json:"note"`
	None    int `json:"none"`
	Total   int `json:"total"`
}

// CodeScanSeverityCounts counts fail-kind findings by security-severity bucket.
// None counts fail-kind findings lacking a numeric security-severity property.
type CodeScanSeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
	Total    int `json:"total"`
}

// CodeScanSummary aggregates findings. byLevel and bySecuritySeverity count the
// SAME set (non-suppressed fail-kind findings) on two independent axes, so their
// totals are equal. suppressed counts fail-kind findings that were suppressed.
// new counts non-suppressed fail-kind findings whose baselineState is new or
// updated (the set gate_new_only would act on).
type CodeScanSummary struct {
	ByLevel            CodeScanLevelCounts    `json:"byLevel"`
	BySecuritySeverity CodeScanSeverityCounts `json:"bySecuritySeverity"`
	Suppressed         int                    `json:"suppressed"`
	New                int                    `json:"new,omitempty"`
}

// CodeScanTool identifies a scanner (one per SARIF run driver).
type CodeScanTool struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
}

// CodeScanInvocation reports whether every SARIF invocation completed.
// executionSuccessful is the AND of all invocations; absent invocations are
// treated as successful (no evidence of an incomplete scan).
type CodeScanInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// CodeScanLocation is the primary physical location of a finding.
type CodeScanLocation struct {
	URI       string `json:"uri,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
}

// CodeScanContext records the scanned source context.
type CodeScanContext struct {
	CommitSHA string `json:"commitSha,omitempty"`
	Ref       string `json:"ref,omitempty"`
	URL       string `json:"url,omitempty"`
}

// CodeScanFinding is a normalized SARIF result. Emitted only when findings are
// explicitly included (--include-findings); off by default so file paths, line
// numbers, and scanner messages are not baked into a permanent public artifact.
type CodeScanFinding struct {
	RuleID                string            `json:"ruleId"`
	Tool                  string            `json:"tool,omitempty"`
	Level                 string            `json:"level"`
	Kind                  string            `json:"kind"`
	SecuritySeverity      string            `json:"securitySeverity,omitempty"`
	SecuritySeverityLevel string            `json:"securitySeverityLevel,omitempty"`
	Message               string            `json:"message,omitempty"`
	Location              *CodeScanLocation `json:"location,omitempty"`
	BaselineState         string            `json:"baselineState,omitempty"`
	Suppressed            bool              `json:"suppressed"`
	SuppressionKind       string            `json:"suppressionKind,omitempty"`
	PartialFingerprints   map[string]string `json:"partialFingerprints,omitempty"`
}

// CodeScan is the predicate portion of an autogov code-scan attestation built
// from a SARIF 2.1.0 report (https://autogov.dev/attestation/code-scan/v0.1).
type CodeScan struct {
	// subject-binding fields, not part of the predicate body
	Type        ArtifactType `json:"-"`
	SubjectName string       `json:"-"`
	SubjectPath string       `json:"-"`
	Digest      string       `json:"-"`

	Tools         []CodeScanTool       `json:"tools"`
	Summary       CodeScanSummary      `json:"summary"`
	Configuration []ResourceDescriptor `json:"configuration"`
	Invocation    CodeScanInvocation   `json:"invocation"`
	// FindingsIncluded is true when results[] is authoritative (every fail-kind
	// finding is present). A policy may recompute over results[] only when
	// findingsIncluded is true AND truncated is false; otherwise it must fall
	// back to the summary counts.
	FindingsIncluded bool `json:"findingsIncluded"`
	// Truncated is true when results[] omits findings (excluded by default, or
	// capped by --max-findings).
	Truncated bool `json:"truncated"`
	// ResultCount is the total number of fail-kind findings discovered, equal to
	// summary.byLevel.total + summary.suppressed, regardless of how many findings
	// are emitted in results[].
	ResultCount int `json:"resultCount"`

	Results        []CodeScanFinding `json:"results,omitempty"`
	ScanContext    *CodeScanContext  `json:"scanContext,omitempty"`
	ScanStartedOn  string            `json:"scanStartedOn,omitempty"`
	ScanFinishedOn string            `json:"scanFinishedOn,omitempty"`
}

// CodeScanOptions contains options for creating a code-scan predicate.
type CodeScanOptions struct {
	Type            ArtifactType
	SubjectName     string
	SubjectPath     string
	Digest          string
	ResultsPath     string
	IncludeFindings bool
	MaxFindings     int
	ConfigURI       string
	CommitSHA       string
	Ref             string
	URL             string
}

// --- SARIF 2.1.0 parsing structs (only the fields autogov consumes) ---

type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver     sarifDriver   `json:"driver"`
	Extensions []sarifDriver `json:"extensions"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string `json:"id"`
	DefaultConfiguration *struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties *struct {
		SecuritySeverity string `json:"security-severity"`
	} `json:"properties"`
}

type sarifInvocation struct {
	ExecutionSuccessful *bool  `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc"`
	EndTimeUTC          string `json:"endTimeUtc"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           *int               `json:"ruleIndex"`
	Level               string             `json:"level"`
	Kind                string             `json:"kind"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	BaselineState       string             `json:"baselineState"`
	Suppressions        []sarifSuppression `json:"suppressions"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *struct {
		ArtifactLocation *struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *struct {
			StartLine int `json:"startLine"`
			EndLine   int `json:"endLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type sarifSuppression struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

// ruleLevel returns the rule's defaultConfiguration.level, or "" if unset.
func (r sarifRule) ruleLevel() string {
	if r.DefaultConfiguration != nil {
		return r.DefaultConfiguration.Level
	}
	return ""
}

// ruleSecuritySeverity returns the rule's security-severity property, or "".
func (r sarifRule) ruleSecuritySeverity() string {
	if r.Properties != nil {
		return r.Properties.SecuritySeverity
	}
	return ""
}

// securitySeverityBucket maps a numeric security-severity to a bucket using
// half-open intervals. A non-numeric or non-positive value yields "none".
func securitySeverityBucket(raw string) string {
	if raw == "" {
		return sevNone
	}
	s, err := strconv.ParseFloat(raw, 64)
	if err != nil || s <= 0 {
		return sevNone
	}
	switch {
	case s >= 9:
		return sevCritical
	case s >= 7:
		return sevHigh
	case s >= 4:
		return sevMedium
	default:
		return sevLow
	}
}

// normalizeBaselineState keeps only the four SARIF baselineState values; any
// other (or absent) value is dropped so the locked schema never sees garbage.
func normalizeBaselineState(s string) string {
	switch s {
	case "new", "unchanged", "updated", "absent":
		return s
	default:
		return ""
	}
}

// normalizeLevel constrains an untrusted SARIF level to the four-value enum.
// Case is folded (a non-lowercasing converter emitting "ERROR" keeps its
// severity); an absent or unrecognized value falls back to "warning", the SARIF
// default. This guarantees both results[].level (schema enum) and the byLevel
// bucket agree on a valid value.
func normalizeLevel(s string) string {
	switch strings.ToLower(s) {
	case levelError:
		return levelError
	case levelNote:
		return levelNote
	case levelNone:
		return levelNone
	default:
		return levelWarning
	}
}

// isSuppressed applies the SARIF rule: a result is suppressed only when it has
// at least one suppression AND none of them is rejected or underReview. An
// absent status defaults to accepted.
func isSuppressed(supps []sarifSuppression) bool {
	if len(supps) == 0 {
		return false
	}
	for _, s := range supps {
		if s.Status == "rejected" || s.Status == "underReview" {
			return false
		}
	}
	return true
}

// truncateRunes caps a string to n runes (multibyte-safe).
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// boundFingerprints copies at most maxFingerprintEntries entries, truncating
// keys and values to their caps. Returns nil when the input is empty.
func boundFingerprints(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	// deterministic selection: sort keys, then take the first N.
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxFingerprintEntries {
		keys = keys[:maxFingerprintEntries]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[truncateRunes(k, maxFingerprintKeyLen)] = truncateRunes(in[k], maxFingerprintValueLen)
	}
	return out
}

// NewCodeScan builds a code-scan predicate from a SARIF 2.1.0 report.
func NewCodeScan(opts CodeScanOptions) (*CodeScan, error) {
	data, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF: %w", err)
	}

	maxFindings := opts.MaxFindings
	if maxFindings <= 0 {
		maxFindings = defaultMaxFindings
	}

	c := &CodeScan{
		Type:             opts.Type,
		SubjectName:      opts.SubjectName,
		SubjectPath:      opts.SubjectPath,
		Digest:           opts.Digest,
		Tools:            []CodeScanTool{},
		Configuration:    []ResourceDescriptor{},
		FindingsIncluded: opts.IncludeFindings,
		Invocation:       CodeScanInvocation{ExecutionSuccessful: true},
	}

	if opts.ConfigURI != "" {
		c.Configuration = append(c.Configuration, ResourceDescriptor{URI: opts.ConfigURI})
	}
	if opts.CommitSHA != "" || opts.Ref != "" || opts.URL != "" {
		c.ScanContext = &CodeScanContext{CommitSHA: opts.CommitSHA, Ref: opts.Ref, URL: opts.URL}
	}

	var findings []CodeScanFinding
	startedOn, finishedOn := "", ""
	seenTools := map[string]bool{}

	for _, run := range log.Runs {
		tool := CodeScanTool{
			Name:           truncateRunes(run.Tool.Driver.Name, maxToolFieldLen),
			Version:        truncateRunes(run.Tool.Driver.Version, maxToolFieldLen),
			InformationURI: truncateRunes(run.Tool.Driver.InformationURI, maxToolFieldLen),
		}
		// dedupe identical tools (CodeQL emits one run per language) and cap the
		// slice so a crafted multi-run SARIF cannot bloat the signed artifact.
		toolKey := tool.Name + "\x00" + tool.Version + "\x00" + tool.InformationURI
		if !seenTools[toolKey] && len(c.Tools) < maxTools {
			seenTools[toolKey] = true
			c.Tools = append(c.Tools, tool)
		}

		// rule lookup by id across driver + extensions; ruleIndex into driver as
		// a fallback when ruleId is absent. CodeQL always sets ruleId.
		rulesByID := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			rulesByID[r.ID] = r
		}
		for _, ext := range run.Tool.Extensions {
			for _, r := range ext.Rules {
				if _, ok := rulesByID[r.ID]; !ok {
					rulesByID[r.ID] = r
				}
			}
		}

		// invocation: AND of every executionSuccessful; capture scan window.
		for _, inv := range run.Invocations {
			if inv.ExecutionSuccessful != nil && !*inv.ExecutionSuccessful {
				c.Invocation.ExecutionSuccessful = false
			}
			if inv.StartTimeUTC != "" && (startedOn == "" || inv.StartTimeUTC < startedOn) {
				startedOn = inv.StartTimeUTC
			}
			if inv.EndTimeUTC != "" && inv.EndTimeUTC > finishedOn {
				finishedOn = inv.EndTimeUTC
			}
		}

		for _, res := range run.Results {
			kind := res.Kind
			if kind == "" {
				kind = sarifKindFail
			}
			// only fail-kind results are findings (M2). pass/open/informational/
			// notApplicable/review are excluded from every count.
			if kind != sarifKindFail {
				continue
			}

			rule := resolveRule(rulesByID, run.Tool.Driver.Rules, res)

			// resolve level: result -> rule default -> "warning"; then constrain
			// the untrusted value to the schema enum.
			level := res.Level
			if level == "" {
				level = rule.ruleLevel()
			}
			level = normalizeLevel(level)

			sevRaw := rule.ruleSecuritySeverity()
			suppressed := isSuppressed(res.Suppressions)
			finding := CodeScanFinding{
				RuleID:                truncateRunes(res.RuleID, maxRuleIDLen),
				Tool:                  tool.Name,
				Level:                 level,
				Kind:                  kind,
				SecuritySeverity:      truncateRunes(sevRaw, maxSecuritySeverityLen),
				SecuritySeverityLevel: securitySeverityBucket(sevRaw),
				Message:               truncateRunes(res.Message.Text, maxMessageRunes),
				BaselineState:         normalizeBaselineState(res.BaselineState),
				Suppressed:            suppressed,
				PartialFingerprints:   boundFingerprints(res.PartialFingerprints),
			}
			if suppressed && res.Suppressions[0].Kind != "" {
				finding.SuppressionKind = truncateRunes(res.Suppressions[0].Kind, maxSuppressionKindLen)
			}
			if loc := primaryLocation(res.Locations); loc != nil {
				finding.Location = loc
			}

			findings = append(findings, finding)
		}
	}

	c.ScanStartedOn = truncateRunes(startedOn, maxTimestampLen)
	c.ScanFinishedOn = truncateRunes(finishedOn, maxTimestampLen)

	summarize(c, findings)

	if opts.IncludeFindings {
		// deterministic order so the signed predicate is reproducible.
		sortFindings(findings)
		if len(findings) > maxFindings {
			c.Results = findings[:maxFindings]
			c.Truncated = true
		} else {
			c.Results = findings
		}
	} else {
		// findings excluded by default (privacy); summary still gates.
		c.Truncated = c.ResultCount > 0
	}

	return c, nil
}

// resolveRule finds the rule for a result by ruleId, falling back to ruleIndex.
func resolveRule(byID map[string]sarifRule, driverRules []sarifRule, res sarifResult) sarifRule {
	if res.RuleID != "" {
		if r, ok := byID[res.RuleID]; ok {
			return r
		}
	}
	if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(driverRules) {
		return driverRules[*res.RuleIndex]
	}
	return sarifRule{}
}

// primaryLocation extracts the first physical location, if any.
func primaryLocation(locs []sarifLocation) *CodeScanLocation {
	for _, l := range locs {
		if l.PhysicalLocation == nil {
			continue
		}
		out := &CodeScanLocation{}
		if al := l.PhysicalLocation.ArtifactLocation; al != nil {
			out.URI = al.URI
		}
		// SARIF lines are 1-based; drop non-positive values (the schema requires
		// >= 0 and omitempty already elides 0).
		if reg := l.PhysicalLocation.Region; reg != nil {
			if reg.StartLine > 0 {
				out.StartLine = reg.StartLine
			}
			if reg.EndLine > 0 {
				out.EndLine = reg.EndLine
			}
		}
		if out.URI == "" && out.StartLine == 0 && out.EndLine == 0 {
			return nil
		}
		return out
	}
	return nil
}

// summarize fills c.Summary and c.ResultCount from the full finding set.
// byLevel and bySecuritySeverity count non-suppressed fail-kind findings;
// suppressed counts the rest. ResultCount is the total of both.
func summarize(c *CodeScan, findings []CodeScanFinding) {
	for _, f := range findings {
		if f.Suppressed {
			c.Summary.Suppressed++
			continue
		}
		switch f.Level {
		case levelError:
			c.Summary.ByLevel.Error++
		case levelNote:
			c.Summary.ByLevel.Note++
		case levelNone:
			c.Summary.ByLevel.None++
		default:
			c.Summary.ByLevel.Warning++
		}
		switch f.SecuritySeverityLevel {
		case sevCritical:
			c.Summary.BySecuritySeverity.Critical++
		case sevHigh:
			c.Summary.BySecuritySeverity.High++
		case sevMedium:
			c.Summary.BySecuritySeverity.Medium++
		case sevLow:
			c.Summary.BySecuritySeverity.Low++
		default:
			c.Summary.BySecuritySeverity.None++
		}
		if f.BaselineState == "new" || f.BaselineState == "updated" {
			c.Summary.New++
		}
	}
	c.Summary.ByLevel.Total = c.Summary.ByLevel.Error + c.Summary.ByLevel.Warning +
		c.Summary.ByLevel.Note + c.Summary.ByLevel.None
	c.Summary.BySecuritySeverity.Total = c.Summary.BySecuritySeverity.Critical +
		c.Summary.BySecuritySeverity.High + c.Summary.BySecuritySeverity.Medium +
		c.Summary.BySecuritySeverity.Low + c.Summary.BySecuritySeverity.None
	c.ResultCount = c.Summary.ByLevel.Total + c.Summary.Suppressed
}

// sortFindings orders findings deterministically (ruleId, uri, startLine).
func sortFindings(findings []CodeScanFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		au, bu := "", ""
		al, bl := 0, 0
		if a.Location != nil {
			au, al = a.Location.URI, a.Location.StartLine
		}
		if b.Location != nil {
			bu, bl = b.Location.URI, b.Location.StartLine
		}
		if au != bu {
			return au < bu
		}
		return al < bl
	})
}

// Generate produces the JSON representation of the code-scan predicate.
func (c *CodeScan) Generate() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// GenerateCodeScan generates and validates a code-scan attestation predicate.
func GenerateCodeScan(opts CodeScanOptions, outputFile string) error {
	c, err := NewCodeScan(opts)
	if err != nil {
		return err
	}

	output, err := c.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate predicate: %w", err)
	}

	if err := ValidateCodeScan(output); err != nil {
		return fmt.Errorf("failed to validate code-scan: %w", err)
	}

	return writeOutput(output, outputFile)
}
