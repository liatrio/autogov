package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
)

// AgentGovernanceDeploymentPredicateTypeURI is the custom autogov predicate type
// for runtime-neutral agent-governance deployment evidence. The URI is locked:
// incompatible semantic changes require a new URI, never a mutation of v0.1.
const AgentGovernanceDeploymentPredicateTypeURI = "https://autogov.dev/attestation/agent-governance-deployment/v0.1"

// Locked schema constants for the v0.1 agent-governance deployment predicate.
const (
	// AgentGovernanceSchemaVersion is the const schemaVersion field value.
	AgentGovernanceSchemaVersion = "0.1"
	// AgentGovernanceContractVersion is the const neutral adapter contract version.
	AgentGovernanceContractVersion = "0.1"
	// AgentGovernanceControlledToolName is the only governed tool in this experiment.
	AgentGovernanceControlledToolName = "write-marker"
	// AgentGovernanceControlledToolActionClass is the only governed action class.
	AgentGovernanceControlledToolActionClass = "filesystem.write.marker"
	// AgentGovernanceMaxPredicateBytes bounds the deterministic JSON output size.
	AgentGovernanceMaxPredicateBytes = 65536
	// agentGovernanceMaxCaseDuration bounds a single conformance case interval.
	agentGovernanceMaxCaseDuration = 5 * time.Minute
	// agentGovernanceTimestampLayout is the canonical UTC-seconds timestamp form.
	agentGovernanceTimestampLayout = "2006-01-02T15:04:05Z"
)

// Case kinds (exactly four mandatory kinds; unique within a predicate).
const (
	AgentGovernanceCaseAllowedAction  = "allowed-action"
	AgentGovernanceCaseDeniedAction   = "denied-action"
	AgentGovernanceCaseAdapterBypass  = "adapter-bypass"
	AgentGovernanceCaseNoPolicyLoaded = "no-policy-loaded"
)

// Decision and outcome states. A decision proves a decision attempt, not an
// external result; an unknown outcome can never satisfy a verified-outcome
// requirement.
const (
	AgentGovernanceDecisionObserved    = "observed"
	AgentGovernanceDecisionNotObserved = "not-observed"
	AgentGovernanceVerdictAllow        = "allow"
	AgentGovernanceVerdictDeny         = "deny"
	AgentGovernanceVerdictUnknown      = "unknown"
	AgentGovernanceOutcomeVerified     = "verified"
	AgentGovernanceOutcomeUnknown      = "unknown"
	AgentGovernanceResultOccurred      = "occurred"
	AgentGovernanceResultBlocked       = "blocked"
	AgentGovernanceResultUnknown       = "unknown"
)

// agentGovernanceCaseKindOrder is the deterministic case sort order.
var agentGovernanceCaseKindOrder = map[string]int{
	AgentGovernanceCaseAllowedAction:  0,
	AgentGovernanceCaseDeniedAction:   1,
	AgentGovernanceCaseAdapterBypass:  2,
	AgentGovernanceCaseNoPolicyLoaded: 3,
}

var (
	agentGovernanceDigestRe      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	agentGovernanceLooseDigestRe = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	agentGovernanceIDRe          = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)
	agentGovernanceRedactedIDRe  = regexp.MustCompile(`^redacted:[A-Za-z0-9._~-]{1,112}$`)
)

// AgentGovernanceArtifactReference is an immutable non-secret artifact
// reference: a required absolute https/oci/urn URI plus a canonical digest.
type AgentGovernanceArtifactReference struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

// AgentGovernanceRedactedReference is a bounded redacted reference: a
// pseudonymous identifier plus the digest of the redacted record it names.
type AgentGovernanceRedactedReference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// AgentGovernanceAgent identifies the agent artifact under governance. The
// signing helper and admission policy cross-check name/artifactDigest against
// the signed in-toto statement subject; the command emits only the body.
type AgentGovernanceAgent struct {
	Name           string `json:"name"`
	URI            string `json:"uri"`
	ArtifactDigest string `json:"artifactDigest"`
}

// AgentGovernanceRuntime identifies the agent runtime by immutable artifact.
type AgentGovernanceRuntime struct {
	Name      string                           `json:"name"`
	Version   string                           `json:"version"`
	Framework string                           `json:"framework,omitempty"`
	Artifact  AgentGovernanceArtifactReference `json:"artifact"`
}

// AgentGovernanceAdapter identifies the evidence-emitting adapter.
type AgentGovernanceAdapter struct {
	Name            string                           `json:"name"`
	Artifact        AgentGovernanceArtifactReference `json:"artifact"`
	ContractVersion string                           `json:"contractVersion"`
	RuntimeDigest   string                           `json:"runtimeDigest"`
}

// AgentGovernanceRuntimePolicy describes the runtime policy configuration.
// Its artifact digest identifies the policy governing the agent at runtime and
// is distinct from the AutoGov admission-policy digest recorded in a VSA.
type AgentGovernanceRuntimePolicy struct {
	Engine   string                           `json:"engine"`
	Artifact AgentGovernanceArtifactReference `json:"artifact"`
	Count    int                              `json:"count"`
	Loaded   bool                             `json:"loaded"`
}

// AgentGovernanceEnforcement separates declared/required intervention points
// from observed/exercised ones; the latter is never inferred from the former.
type AgentGovernanceEnforcement struct {
	Mode                       string   `json:"mode"`
	DefaultBehavior            string   `json:"defaultBehavior"`
	RequiredInterventionPoints []string `json:"requiredInterventionPoints"`
	ObservedInterventionPoints []string `json:"observedInterventionPoints"`
}

// AgentGovernanceIdentity references the workload/agent identity without
// embedding credentials, tokens, or raw identity claims.
type AgentGovernanceIdentity struct {
	ProviderURI string                           `json:"providerUri"`
	SubjectKind string                           `json:"subjectKind"`
	Subject     AgentGovernanceRedactedReference `json:"subject"`
}

// AgentGovernanceAudit describes the configured audit sink without claiming
// tamper resistance and without raw logs or credential-bearing references.
type AgentGovernanceAudit struct {
	SinkKind            string                           `json:"sinkKind"`
	Sink                AgentGovernanceRedactedReference `json:"sink"`
	ConfigurationDigest string                           `json:"configurationDigest"`
}

// AgentGovernanceFixture identifies the producing fixture.
type AgentGovernanceFixture struct {
	ID       string `json:"id"`
	Producer string `json:"producer"`
}

// AgentGovernanceControlledTool is the single consequential controlled tool.
type AgentGovernanceControlledTool struct {
	Name        string                           `json:"name"`
	ActionClass string                           `json:"actionClass"`
	Artifact    AgentGovernanceArtifactReference `json:"artifact"`
}

// AgentGovernanceDecision records an observed (or explicitly not-observed)
// pre-action policy decision. Reference and ObservedAt are present only when
// the state is observed; they are never emitted empty.
type AgentGovernanceDecision struct {
	State      string                            `json:"state"`
	Verdict    string                            `json:"verdict"`
	Reference  *AgentGovernanceRedactedReference `json:"reference,omitempty"`
	ObservedAt string                            `json:"observedAt,omitempty"`
}

// AgentGovernanceOutcome records the bounded external outcome observation.
// State unknown never satisfies a verified-outcome requirement.
type AgentGovernanceOutcome struct {
	State      string                            `json:"state"`
	Result     string                            `json:"result"`
	Reference  *AgentGovernanceRedactedReference `json:"reference,omitempty"`
	ObservedAt string                            `json:"observedAt,omitempty"`
}

// AgentGovernanceTestResultRef links a case to its separately signed standard
// in-toto test-result statement (exact DSSE payload byte digest).
type AgentGovernanceTestResultRef struct {
	PredicateType   string `json:"predicateType"`
	TestID          string `json:"testId"`
	StatementDigest string `json:"statementDigest"`
}

// AgentGovernanceCase is one bounded conformance case.
type AgentGovernanceCase struct {
	ID            string                       `json:"id"`
	Kind          string                       `json:"kind"`
	CorrelationID string                       `json:"correlationId"`
	StartedAt     string                       `json:"startedAt"`
	CompletedAt   string                       `json:"completedAt"`
	Decision      AgentGovernanceDecision      `json:"decision"`
	Outcome       AgentGovernanceOutcome       `json:"outcome"`
	TestResult    AgentGovernanceTestResultRef `json:"testResult"`
}

// AgentGovernanceConformance groups the fixture, controlled tool, and cases.
type AgentGovernanceConformance struct {
	Fixture        AgentGovernanceFixture        `json:"fixture"`
	ControlledTool AgentGovernanceControlledTool `json:"controlledTool"`
	Cases          []AgentGovernanceCase         `json:"cases"`
}

// AgentGovernanceDeployment is the predicate body of the agent-governance
// deployment attestation. The command emits and validates only this body; the
// signing helper wraps it in exactly one in-toto Statement.
type AgentGovernanceDeployment struct {
	SchemaVersion string                       `json:"schemaVersion"`
	Agent         AgentGovernanceAgent         `json:"agent"`
	Runtime       AgentGovernanceRuntime       `json:"runtime"`
	Adapter       AgentGovernanceAdapter       `json:"adapter"`
	RuntimePolicy AgentGovernanceRuntimePolicy `json:"runtimePolicy"`
	Enforcement   AgentGovernanceEnforcement   `json:"enforcement"`
	Identity      AgentGovernanceIdentity      `json:"identity"`
	Audit         AgentGovernanceAudit         `json:"audit"`
	Conformance   AgentGovernanceConformance   `json:"conformance"`
	Extensions    map[string]json.RawMessage   `json:"extensions,omitempty"`
}

// ParseAgentGovernanceEvidence strictly decodes normalized evidence input into
// the typed predicate model. Unknown fields fail closed so an adapter-supplied
// aggregate verdict (e.g. "passed"/"compliant") can never smuggle into the
// body, and trailing data is rejected.
func ParseAgentGovernanceEvidence(data []byte) (*AgentGovernanceDeployment, error) {
	if len(data) > AgentGovernanceMaxPredicateBytes {
		return nil, fmt.Errorf("agent-governance evidence exceeds the %d byte input bound", AgentGovernanceMaxPredicateBytes)
	}
	if err := validateAgentGovernanceEvidencePresence(data); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var d AgentGovernanceDeployment
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("invalid agent-governance evidence: %w", err)
	}
	// reject trailing content after the JSON document (dec.More alone misses
	// trailing '}'/']' bytes, so read the next token and require EOF)
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid agent-governance evidence: trailing data after JSON document")
	}
	return &d, nil
}

// ReadAgentGovernanceEvidenceFile reads at most one bounded evidence document.
// The companion CLI and demonstration helper share this adapter so neither can
// allocate an unbounded producer-controlled file before parsing it.
func ReadAgentGovernanceEvidenceFile(evidencePath string) ([]byte, error) {
	file, err := os.Open(evidencePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read evidence file: %w", err)
	}
	data, readErr := readBoundedAgentGovernanceEvidence(file)
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("failed to read evidence file: %w", err)
	}
	return data, nil
}

func readBoundedAgentGovernanceEvidence(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, AgentGovernanceMaxPredicateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > AgentGovernanceMaxPredicateBytes {
		return nil, fmt.Errorf("agent-governance evidence exceeds the %d byte input bound", AgentGovernanceMaxPredicateBytes)
	}
	return data, nil
}

// validateAgentGovernanceEvidencePresence rejects omitted required members
// before decoding into Go structs. in particular, a missing false/zero member
// must not become a fabricated no-policy observation through Go's zero-value
// decoding. the demonstration signing helper is the sole exception: it adds
// case.testResult.statementDigest after building the separately signed
// test-result payload, so that one member may be absent at this boundary.
func validateAgentGovernanceEvidencePresence(data []byte) error {
	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("invalid agent-governance evidence: %w", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(embeddedAgentGovernanceDeploymentSchema), &schema); err != nil {
		return fmt.Errorf("invalid embedded agent-governance schema: %w", err)
	}
	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid embedded agent-governance schema: predicate properties missing")
	}
	predicateSchema, ok := properties["predicate"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid embedded agent-governance schema: predicate schema missing")
	}
	definitions, _ := schema["definitions"].(map[string]interface{})
	return validateRequiredEvidenceMembers(value, predicateSchema, definitions, "evidence")
}

func validateRequiredEvidenceMembers(value interface{}, schema, definitions map[string]interface{}, path string) error {
	if value == nil {
		return fmt.Errorf("invalid agent-governance evidence: %s must not be null", path)
	}
	if ref, ok := schema["$ref"].(string); ok {
		const definitionsPrefix = "#/definitions/"
		if !strings.HasPrefix(ref, definitionsPrefix) {
			return fmt.Errorf("invalid embedded agent-governance schema: unsupported reference %q", ref)
		}
		resolved, ok := definitions[strings.TrimPrefix(ref, definitionsPrefix)].(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid embedded agent-governance schema: unresolved reference %q", ref)
		}
		return validateRequiredEvidenceMembers(value, resolved, definitions, path)
	}

	switch schema["type"] {
	case "object":
		object, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid agent-governance evidence: %s must be an object", path)
		}
		required, _ := schema["required"].([]interface{})
		for _, rawName := range required {
			name, ok := rawName.(string)
			if !ok {
				return fmt.Errorf("invalid embedded agent-governance schema: non-string required member")
			}
			if _, present := object[name]; !present && !deferredEvidenceMember(path, name) {
				return fmt.Errorf("invalid agent-governance evidence: missing required member %s.%s", path, name)
			}
		}
		properties, _ := schema["properties"].(map[string]interface{})
		for name, rawChildSchema := range properties {
			child, present := object[name]
			if !present {
				continue
			}
			childSchema, ok := rawChildSchema.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid embedded agent-governance schema: invalid schema for %s.%s", path, name)
			}
			if err := validateRequiredEvidenceMembers(child, childSchema, definitions, path+"."+name); err != nil {
				return err
			}
		}
	case "array":
		array, ok := value.([]interface{})
		if !ok {
			return fmt.Errorf("invalid agent-governance evidence: %s must be an array", path)
		}
		itemSchema, ok := schema["items"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid embedded agent-governance schema: items schema missing for %s", path)
		}
		for i, item := range array {
			if err := validateRequiredEvidenceMembers(item, itemSchema, definitions, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func deferredEvidenceMember(path, name string) bool {
	return name == "statementDigest" && strings.HasSuffix(path, ".testResult")
}

// Normalize brings the predicate into canonical form before validation and
// output: digests lowercased, timestamps re-emitted as UTC whole seconds,
// intervention-point arrays deduplicated and bytewise sorted, cases sorted by
// fixed kind order then id, and extension values canonicalized.
func (d *AgentGovernanceDeployment) Normalize() error {
	type labeledField struct {
		label string
		value *string
	}
	digests := []labeledField{
		{"agent.artifactDigest", &d.Agent.ArtifactDigest},
		{"runtime.artifact.digest", &d.Runtime.Artifact.Digest},
		{"adapter.artifact.digest", &d.Adapter.Artifact.Digest},
		{"adapter.runtimeDigest", &d.Adapter.RuntimeDigest},
		{"runtimePolicy.artifact.digest", &d.RuntimePolicy.Artifact.Digest},
		{"identity.subject.digest", &d.Identity.Subject.Digest},
		{"audit.sink.digest", &d.Audit.Sink.Digest},
		{"audit.configurationDigest", &d.Audit.ConfigurationDigest},
		{"conformance.controlledTool.artifact.digest", &d.Conformance.ControlledTool.Artifact.Digest},
	}
	for i := range d.Conformance.Cases {
		c := &d.Conformance.Cases[i]
		prefix := fmt.Sprintf("conformance.cases[%d]", i)
		digests = append(digests,
			labeledField{prefix + ".correlationId", &c.CorrelationID},
			labeledField{prefix + ".testResult.statementDigest", &c.TestResult.StatementDigest},
		)
		if c.Decision.Reference != nil {
			digests = append(digests, labeledField{prefix + ".decision.reference.digest", &c.Decision.Reference.Digest})
		}
		if c.Outcome.Reference != nil {
			digests = append(digests, labeledField{prefix + ".outcome.reference.digest", &c.Outcome.Reference.Digest})
		}
	}
	for _, f := range digests {
		normalized, err := normalizeAgentGovernanceDigest(*f.value)
		if err != nil {
			return fmt.Errorf("%s: %w", f.label, err)
		}
		*f.value = normalized
	}

	d.Enforcement.RequiredInterventionPoints = dedupeSortStrings(d.Enforcement.RequiredInterventionPoints)
	d.Enforcement.ObservedInterventionPoints = dedupeSortStrings(d.Enforcement.ObservedInterventionPoints)

	for i := range d.Conformance.Cases {
		c := &d.Conformance.Cases[i]
		prefix := fmt.Sprintf("conformance.cases[%d]", i)
		timestamps := []labeledField{
			{prefix + ".startedAt", &c.StartedAt},
			{prefix + ".completedAt", &c.CompletedAt},
		}
		if c.Decision.ObservedAt != "" {
			timestamps = append(timestamps, labeledField{prefix + ".decision.observedAt", &c.Decision.ObservedAt})
		}
		if c.Outcome.ObservedAt != "" {
			timestamps = append(timestamps, labeledField{prefix + ".outcome.observedAt", &c.Outcome.ObservedAt})
		}
		for _, f := range timestamps {
			normalized, err := normalizeAgentGovernanceTimestamp(*f.value)
			if err != nil {
				return fmt.Errorf("%s: %w", f.label, err)
			}
			*f.value = normalized
		}
	}

	sort.SliceStable(d.Conformance.Cases, func(i, j int) bool {
		a, b := d.Conformance.Cases[i], d.Conformance.Cases[j]
		ao, aok := agentGovernanceCaseKindOrder[a.Kind]
		bo, bok := agentGovernanceCaseKindOrder[b.Kind]
		if aok != bok {
			// known kinds sort before unknown ones (validation rejects unknown
			// kinds later; this keeps the ordering strict regardless)
			return aok
		}
		if aok && ao != bo {
			return ao < bo
		}
		return a.ID < b.ID
	})

	if err := d.normalizeExtensions(); err != nil {
		return err
	}
	return nil
}

// normalizeExtensions canonicalizes every extension value (sorted object keys,
// preserved number literals) so equivalent inputs emit identical bytes.
func (d *AgentGovernanceDeployment) normalizeExtensions() error {
	if len(d.Extensions) == 0 {
		d.Extensions = nil
		return nil
	}
	for key, raw := range d.Extensions {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v interface{}
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("extensions: value is not valid JSON: %w", err)
		}
		canonical, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("extensions: failed to canonicalize value: %w", err)
		}
		d.Extensions[key] = canonical
	}
	return nil
}

// normalizeAgentGovernanceDigest lowercases a sha256:<hex> digest and rejects
// every other form (bare hex, other algorithms, wrong length) rather than
// guessing what the producer meant.
func normalizeAgentGovernanceDigest(digest string) (string, error) {
	if !agentGovernanceLooseDigestRe.MatchString(digest) {
		return "", fmt.Errorf("invalid digest: must match ^sha256:[0-9a-f]{64}$ (canonical lowercase sha256)")
	}
	return strings.ToLower(digest), nil
}

// normalizeAgentGovernanceTimestamp parses an RFC3339 timestamp, requires an
// exact whole second, converts it to UTC, and re-emits it canonically. a
// fractional input must not be truncated because that could move an observed
// event inside a bounded case interval.
func normalizeAgentGovernanceTimestamp(ts string) (string, error) {
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp: must be RFC3339 (canonical form %s)", agentGovernanceTimestampLayout)
	}
	if parsed.Nanosecond() != 0 {
		return "", fmt.Errorf("invalid timestamp: fractional seconds are not allowed (canonical form %s)", agentGovernanceTimestampLayout)
	}
	return parsed.UTC().Format(agentGovernanceTimestampLayout), nil
}

// dedupeSortStrings deduplicates and bytewise-sorts a string slice, returning
// an empty (non-nil) slice for empty input so required arrays are never null.
func dedupeSortStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Validate enforces every cross-field semantic rule of the v0.1 schema
// contract. It assumes Normalize has run and fails closed on the first
// violation with a bounded, field-specific error that never echoes sensitive
// payload content.
func (d *AgentGovernanceDeployment) Validate() error {
	validators := []func() error{
		d.validateRoot,
		d.validateRuntimeAdapter,
		d.validateRuntimePolicy,
		d.validateEnforcement,
		d.validateIdentityAudit,
		d.validateConformance,
		d.validateExtensions,
	}
	for _, v := range validators {
		if err := v(); err != nil {
			return err
		}
	}
	return nil
}

func (d *AgentGovernanceDeployment) validateRoot() error {
	if d.SchemaVersion != AgentGovernanceSchemaVersion {
		return fmt.Errorf("schemaVersion: must be the const %q", AgentGovernanceSchemaVersion)
	}
	if err := validateBoundedText("agent.name", d.Agent.Name, 256); err != nil {
		return err
	}
	if err := validateAbsoluteURI("agent.uri", d.Agent.URI, nil); err != nil {
		return err
	}
	return validateCanonicalDigest("agent.artifactDigest", d.Agent.ArtifactDigest)
}

func (d *AgentGovernanceDeployment) validateRuntimeAdapter() error {
	if err := validateBoundedText("runtime.name", d.Runtime.Name, 128); err != nil {
		return err
	}
	if err := validateBoundedText("runtime.version", d.Runtime.Version, 128); err != nil {
		return err
	}
	if d.Runtime.Framework != "" {
		if err := validateBoundedText("runtime.framework", d.Runtime.Framework, 128); err != nil {
			return err
		}
	}
	if err := validateArtifactReference("runtime.artifact", d.Runtime.Artifact); err != nil {
		return err
	}
	if err := validateBoundedText("adapter.name", d.Adapter.Name, 128); err != nil {
		return err
	}
	if err := validateArtifactReference("adapter.artifact", d.Adapter.Artifact); err != nil {
		return err
	}
	if d.Adapter.ContractVersion != AgentGovernanceContractVersion {
		return fmt.Errorf("adapter.contractVersion: must be the const %q", AgentGovernanceContractVersion)
	}
	if err := validateCanonicalDigest("adapter.runtimeDigest", d.Adapter.RuntimeDigest); err != nil {
		return err
	}
	if d.Adapter.RuntimeDigest != d.Runtime.Artifact.Digest {
		return fmt.Errorf("adapter.runtimeDigest: must equal runtime.artifact.digest (runtime linkage mismatch)")
	}
	return nil
}

func (d *AgentGovernanceDeployment) validateRuntimePolicy() error {
	if err := validateAgentGovernanceID("runtimePolicy.engine", d.RuntimePolicy.Engine); err != nil {
		return err
	}
	if err := validateArtifactReference("runtimePolicy.artifact", d.RuntimePolicy.Artifact); err != nil {
		return err
	}
	if d.RuntimePolicy.Count < 0 || d.RuntimePolicy.Count > 64 {
		return fmt.Errorf("runtimePolicy.count: must be an integer in [0, 64]")
	}
	if d.RuntimePolicy.Loaded != (d.RuntimePolicy.Count >= 1) {
		return fmt.Errorf("runtimePolicy.loaded: contradicts runtimePolicy.count (loaded must be true iff count >= 1)")
	}
	return nil
}

func (d *AgentGovernanceDeployment) validateEnforcement() error {
	switch d.Enforcement.Mode {
	case "enforce", "monitor":
	default:
		return fmt.Errorf("enforcement.mode: must be one of enforce, monitor")
	}
	switch d.Enforcement.DefaultBehavior {
	case AgentGovernanceVerdictAllow, AgentGovernanceVerdictDeny:
	default:
		return fmt.Errorf("enforcement.defaultBehavior: must be one of allow, deny")
	}
	if len(d.Enforcement.RequiredInterventionPoints) < 1 || len(d.Enforcement.RequiredInterventionPoints) > 32 {
		return fmt.Errorf("enforcement.requiredInterventionPoints: must contain 1-32 unique IDs")
	}
	if len(d.Enforcement.ObservedInterventionPoints) > 32 {
		return fmt.Errorf("enforcement.observedInterventionPoints: must contain 0-32 unique IDs")
	}
	for _, p := range d.Enforcement.RequiredInterventionPoints {
		if err := validateAgentGovernanceID("enforcement.requiredInterventionPoints[]", p); err != nil {
			return err
		}
	}
	for _, p := range d.Enforcement.ObservedInterventionPoints {
		if err := validateAgentGovernanceID("enforcement.observedInterventionPoints[]", p); err != nil {
			return err
		}
	}
	return nil
}

func (d *AgentGovernanceDeployment) validateIdentityAudit() error {
	if err := validateAbsoluteURI("identity.providerUri", d.Identity.ProviderURI, nil); err != nil {
		return err
	}
	switch d.Identity.SubjectKind {
	case "agent", "workload":
	default:
		return fmt.Errorf("identity.subjectKind: must be one of agent, workload")
	}
	if err := validateRedactedReference("identity.subject", d.Identity.Subject); err != nil {
		return err
	}
	if err := validateAgentGovernanceID("audit.sinkKind", d.Audit.SinkKind); err != nil {
		return err
	}
	if err := validateRedactedReference("audit.sink", d.Audit.Sink); err != nil {
		return err
	}
	return validateCanonicalDigest("audit.configurationDigest", d.Audit.ConfigurationDigest)
}

func (d *AgentGovernanceDeployment) validateConformance() error {
	if err := validateAgentGovernanceID("conformance.fixture.id", d.Conformance.Fixture.ID); err != nil {
		return err
	}
	switch d.Conformance.Fixture.Producer {
	case "agt", "non-agt":
	default:
		return fmt.Errorf("conformance.fixture.producer: must be one of agt, non-agt")
	}
	if d.Conformance.ControlledTool.Name != AgentGovernanceControlledToolName {
		return fmt.Errorf("conformance.controlledTool.name: must be the const %q", AgentGovernanceControlledToolName)
	}
	if d.Conformance.ControlledTool.ActionClass != AgentGovernanceControlledToolActionClass {
		return fmt.Errorf("conformance.controlledTool.actionClass: must be the const %q", AgentGovernanceControlledToolActionClass)
	}
	if err := validateArtifactReference("conformance.controlledTool.artifact", d.Conformance.ControlledTool.Artifact); err != nil {
		return err
	}
	if len(d.Conformance.Cases) < 1 || len(d.Conformance.Cases) > 4 {
		return fmt.Errorf("conformance.cases: must contain 1-4 cases")
	}
	seenIDs := make(map[string]struct{}, len(d.Conformance.Cases))
	seenKinds := make(map[string]struct{}, len(d.Conformance.Cases))
	for i := range d.Conformance.Cases {
		c := &d.Conformance.Cases[i]
		if _, dup := seenIDs[c.ID]; dup {
			return fmt.Errorf("conformance.cases[%d].id: duplicate case id", i)
		}
		seenIDs[c.ID] = struct{}{}
		if _, dup := seenKinds[c.Kind]; dup {
			return fmt.Errorf("conformance.cases[%d].kind: duplicate case kind", i)
		}
		seenKinds[c.Kind] = struct{}{}
		if err := d.validateCase(i, c); err != nil {
			return err
		}
	}
	return nil
}

// validateCase enforces the per-case field, conditional-member, interval, and
// contradiction rules.
func (d *AgentGovernanceDeployment) validateCase(index int, c *AgentGovernanceCase) error {
	label := fmt.Sprintf("conformance.cases[%d]", index)
	if err := validateAgentGovernanceID(label+".id", c.ID); err != nil {
		return err
	}
	if _, known := agentGovernanceCaseKindOrder[c.Kind]; !known {
		return fmt.Errorf("%s.kind: must be one of allowed-action, denied-action, adapter-bypass, no-policy-loaded", label)
	}
	if err := validateCanonicalDigest(label+".correlationId", c.CorrelationID); err != nil {
		return err
	}
	started, completed, err := validateCaseInterval(label, c)
	if err != nil {
		return err
	}
	if err := validateCaseDecision(label, c, started, completed); err != nil {
		return err
	}
	if err := validateCaseOutcome(label, c, started, completed); err != nil {
		return err
	}
	if err := validateCaseTestResult(label, c); err != nil {
		return err
	}
	return d.validateCaseKindConsistency(label, c)
}

// validateCaseInterval parses and bounds the case interval.
func validateCaseInterval(label string, c *AgentGovernanceCase) (time.Time, time.Time, error) {
	started, err := time.Parse(agentGovernanceTimestampLayout, c.StartedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%s.startedAt: must be canonical UTC seconds (%s)", label, agentGovernanceTimestampLayout)
	}
	completed, err := time.Parse(agentGovernanceTimestampLayout, c.CompletedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%s.completedAt: must be canonical UTC seconds (%s)", label, agentGovernanceTimestampLayout)
	}
	if completed.Before(started) {
		return time.Time{}, time.Time{}, fmt.Errorf("%s: completedAt must not be earlier than startedAt", label)
	}
	if completed.Sub(started) > agentGovernanceMaxCaseDuration {
		return time.Time{}, time.Time{}, fmt.Errorf("%s: case duration must be at most five minutes", label)
	}
	return started, completed, nil
}

// validateCaseDecision enforces decision state/verdict consistency and the
// conditional reference/observedAt members.
func validateCaseDecision(label string, c *AgentGovernanceCase, started, completed time.Time) error {
	switch c.Decision.State {
	case AgentGovernanceDecisionObserved:
		if c.Decision.Verdict != AgentGovernanceVerdictAllow && c.Decision.Verdict != AgentGovernanceVerdictDeny {
			return fmt.Errorf("%s.decision.verdict: observed decision requires allow or deny", label)
		}
		if c.Decision.Reference == nil {
			return fmt.Errorf("%s.decision.reference: required when decision is observed", label)
		}
		if err := validateRedactedReference(label+".decision.reference", *c.Decision.Reference); err != nil {
			return err
		}
		if err := validateObservedAt(label+".decision.observedAt", c.Decision.ObservedAt, started, completed); err != nil {
			return err
		}
	case AgentGovernanceDecisionNotObserved:
		if c.Decision.Verdict != AgentGovernanceVerdictUnknown {
			return fmt.Errorf("%s.decision.verdict: must be unknown when the decision was not observed", label)
		}
		if c.Decision.Reference != nil || c.Decision.ObservedAt != "" {
			return fmt.Errorf("%s.decision: reference and observedAt must be omitted when not observed", label)
		}
	default:
		return fmt.Errorf("%s.decision.state: must be one of observed, not-observed", label)
	}
	return nil
}

// validateCaseOutcome enforces outcome state/result consistency and the
// conditional reference/observedAt members.
func validateCaseOutcome(label string, c *AgentGovernanceCase, started, completed time.Time) error {
	switch c.Outcome.State {
	case AgentGovernanceOutcomeVerified:
		if c.Outcome.Result != AgentGovernanceResultOccurred && c.Outcome.Result != AgentGovernanceResultBlocked {
			return fmt.Errorf("%s.outcome.result: verified outcome requires occurred or blocked", label)
		}
		if c.Outcome.Reference == nil {
			return fmt.Errorf("%s.outcome.reference: required when the outcome is verified", label)
		}
		if err := validateRedactedReference(label+".outcome.reference", *c.Outcome.Reference); err != nil {
			return err
		}
		if err := validateObservedAt(label+".outcome.observedAt", c.Outcome.ObservedAt, started, completed); err != nil {
			return err
		}
	case AgentGovernanceOutcomeUnknown:
		if c.Outcome.Result != AgentGovernanceResultUnknown {
			return fmt.Errorf("%s.outcome.result: must be unknown when the outcome state is unknown", label)
		}
		if c.Outcome.Reference != nil || c.Outcome.ObservedAt != "" {
			return fmt.Errorf("%s.outcome: reference and observedAt must be omitted when the outcome is unknown", label)
		}
	default:
		return fmt.Errorf("%s.outcome.state: must be one of verified, unknown", label)
	}
	return nil
}

// validateCaseTestResult enforces the standard test-result linkage reference.
func validateCaseTestResult(label string, c *AgentGovernanceCase) error {
	if c.TestResult.PredicateType != TestResultPredicateTypeURI {
		return fmt.Errorf("%s.testResult.predicateType: must be the standard %q", label, TestResultPredicateTypeURI)
	}
	if c.TestResult.TestID != c.ID {
		return fmt.Errorf("%s.testResult.testId: must equal the case id", label)
	}
	return validateCanonicalDigest(label+".testResult.statementDigest", c.TestResult.StatementDigest)
}

// validateCaseKindConsistency rejects case labels that contradict the recorded
// facts. Admission is derived by the local policy gate from facts, never from
// the kind label; these checks only refuse to emit self-contradictory evidence.
func (d *AgentGovernanceDeployment) validateCaseKindConsistency(label string, c *AgentGovernanceCase) error {
	switch c.Kind {
	case AgentGovernanceCaseAllowedAction:
		if c.Decision.State != AgentGovernanceDecisionObserved || c.Decision.Verdict != AgentGovernanceVerdictAllow {
			return fmt.Errorf("%s: allowed-action contradicts the decision observation (requires an observed allow)", label)
		}
	case AgentGovernanceCaseDeniedAction:
		if c.Decision.State != AgentGovernanceDecisionObserved || c.Decision.Verdict != AgentGovernanceVerdictDeny {
			return fmt.Errorf("%s: denied-action contradicts the decision observation (requires an observed deny)", label)
		}
	case AgentGovernanceCaseAdapterBypass:
		requiredExercised := stringSubset(d.Enforcement.RequiredInterventionPoints, d.Enforcement.ObservedInterventionPoints)
		if c.Decision.State == AgentGovernanceDecisionObserved && requiredExercised {
			return fmt.Errorf("%s: adapter-bypass contradicts an observed decision with all required points exercised", label)
		}
	case AgentGovernanceCaseNoPolicyLoaded:
		if d.RuntimePolicy.Loaded {
			return fmt.Errorf("%s: no-policy-loaded contradicts runtimePolicy.loaded=true", label)
		}
	}
	return nil
}

// validateExtensions bounds the optional, non-authoritative extensions object:
// at most 8 absolute-URI keys (<=256 chars), 4096 canonical bytes per value,
// 16384 bytes total, nesting depth 4, and 16 members/items per container.
// Extension data can never override core fields or satisfy admission rules.
func (d *AgentGovernanceDeployment) validateExtensions() error {
	if len(d.Extensions) == 0 {
		return nil
	}
	if len(d.Extensions) > 8 {
		return fmt.Errorf("extensions: at most 8 keys are allowed")
	}
	total := 0
	keys := make([]string, 0, len(d.Extensions))
	for key := range d.Extensions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(key) > 256 {
			return fmt.Errorf("extensions: key exceeds 256 bytes")
		}
		if err := validateAbsoluteURI("extensions key", key, nil); err != nil {
			return err
		}
		value := d.Extensions[key]
		if len(value) > 4096 {
			return fmt.Errorf("extensions: value exceeds 4096 canonical JSON bytes")
		}
		total += len(value)
		var v interface{}
		dec := json.NewDecoder(bytes.NewReader(value))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("extensions: invalid JSON value: %w", err)
		}
		if err := validateExtensionDepth(v, 1); err != nil {
			return err
		}
	}
	if total > 16384 {
		return fmt.Errorf("extensions: total value size exceeds 16384 bytes")
	}
	return nil
}

// validateExtensionDepth bounds extension nesting depth (4) and container size (16).
func validateExtensionDepth(v interface{}, depth int) error {
	switch t := v.(type) {
	case map[string]interface{}:
		if depth > 4 {
			return fmt.Errorf("extensions: nesting depth exceeds 4")
		}
		if len(t) > 16 {
			return fmt.Errorf("extensions: object exceeds 16 members")
		}
		for _, child := range t {
			if err := validateExtensionDepth(child, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		if depth > 4 {
			return fmt.Errorf("extensions: nesting depth exceeds 4")
		}
		if len(t) > 16 {
			return fmt.Errorf("extensions: array exceeds 16 items")
		}
		for _, child := range t {
			if err := validateExtensionDepth(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateObservedAt requires a canonical timestamp within the case interval.
func validateObservedAt(label, value string, started, completed time.Time) error {
	if value == "" {
		return fmt.Errorf("%s: required for this state", label)
	}
	observed, err := time.Parse(agentGovernanceTimestampLayout, value)
	if err != nil {
		return fmt.Errorf("%s: must be canonical UTC seconds (%s)", label, agentGovernanceTimestampLayout)
	}
	if observed.Before(started) || observed.After(completed) {
		return fmt.Errorf("%s: must be within the case interval", label)
	}
	return nil
}

// validateBoundedText enforces a 1..max byte bound (stricter than counting
// code points, so multi-byte input can never exceed the schema's character
// bound) and rejects control characters. It never echoes the offending value.
func validateBoundedText(label, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("%s: required (1-%d bytes)", label, maxLen)
	}
	if len(value) > maxLen {
		return fmt.Errorf("%s: exceeds %d bytes", label, maxLen)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s: control characters are not allowed", label)
		}
	}
	return nil
}

// validateAbsoluteURI requires an absolute 1..2048 char URI without control
// characters. When schemes is non-nil, the scheme must be in the allowlist.
func validateAbsoluteURI(label, value string, schemes []string) error {
	if err := validateBoundedText(label, value, 2048); err != nil {
		return err
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isHexByte(value[i+1]) || !isHexByte(value[i+2]) {
			return fmt.Errorf("%s: contains invalid URI percent-encoding", label)
		}
		i += 2
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() {
		return fmt.Errorf("%s: must be an absolute URI", label)
	}
	if (parsed.Scheme == "https" || parsed.Scheme == "oci") && parsed.Host == "" {
		return fmt.Errorf("%s: URI scheme %q requires an authority", label, parsed.Scheme)
	}
	if schemes != nil && !slices.Contains(schemes, parsed.Scheme) {
		return fmt.Errorf("%s: URI scheme must be one of %s", label, strings.Join(schemes, ", "))
	}
	return nil
}

func isHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

// validateCanonicalDigest requires the canonical lowercase sha256:<64-hex> form.
func validateCanonicalDigest(label, value string) error {
	if !agentGovernanceDigestRe.MatchString(value) {
		return fmt.Errorf("%s: must match ^sha256:[0-9a-f]{64}$", label)
	}
	return nil
}

// validateAgentGovernanceID requires the bounded lowercase ID form.
func validateAgentGovernanceID(label, value string) error {
	if !agentGovernanceIDRe.MatchString(value) {
		return fmt.Errorf("%s: must match ^[a-z0-9][a-z0-9._:/-]{0,127}$", label)
	}
	return nil
}

// validateArtifactReference requires an absolute https/oci/urn URI plus a
// canonical digest and nothing else.
func validateArtifactReference(label string, ref AgentGovernanceArtifactReference) error {
	if err := validateAbsoluteURI(label+".uri", ref.URI, []string{"https", "oci", "urn"}); err != nil {
		return err
	}
	schemeEnd := strings.IndexByte(ref.URI, ':')
	if schemeEnd < 0 || ref.URI[:schemeEnd] != strings.ToLower(ref.URI[:schemeEnd]) {
		return fmt.Errorf("%s.uri: artifact URI scheme must be lowercase", label)
	}
	return validateCanonicalDigest(label+".digest", ref.Digest)
}

// validateRedactedReference requires a bounded redacted id plus the digest of
// the redacted record it names.
func validateRedactedReference(label string, ref AgentGovernanceRedactedReference) error {
	if !agentGovernanceRedactedIDRe.MatchString(ref.ID) {
		return fmt.Errorf("%s.id: must match ^redacted:[A-Za-z0-9._~-]{1,112}$", label)
	}
	return validateCanonicalDigest(label+".digest", ref.Digest)
}

// stringSubset reports whether every element of subset appears in set.
func stringSubset(subset, set []string) bool {
	for _, s := range subset {
		if !slices.Contains(set, s) {
			return false
		}
	}
	return true
}

// Generate normalizes, semantically validates, schema-validates, and emits the
// deterministic JSON predicate body. Equivalent inputs (shuffled collections,
// uppercase digests, zoned timestamps) produce byte-identical output.
func (d *AgentGovernanceDeployment) Generate() ([]byte, error) {
	if err := d.Normalize(); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}

	// required arrays are emitted as arrays, never null: Normalize's
	// dedupeSortStrings already guarantees both intervention-point slices are
	// non-nil, so no extra defaulting is needed here

	output, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to generate agent-governance predicate: %w", err)
	}
	if len(output) > AgentGovernanceMaxPredicateBytes {
		return nil, fmt.Errorf("predicate exceeds the %d byte bound", AgentGovernanceMaxPredicateBytes)
	}
	if err := ValidateAgentGovernanceDeployment(output); err != nil {
		return nil, fmt.Errorf("failed to validate agent-governance predicate: %w", err)
	}
	return output, nil
}

// GenerateAgentGovernanceDeployment reads normalized evidence input from
// evidencePath and writes the validated deterministic predicate body to
// outputFile (or stdout when empty). Invalid evidence is rejected before an
// output file is opened.
func GenerateAgentGovernanceDeployment(evidencePath, outputFile string) error {
	data, err := ReadAgentGovernanceEvidenceFile(evidencePath)
	if err != nil {
		return err
	}

	d, err := ParseAgentGovernanceEvidence(data)
	if err != nil {
		return err
	}

	output, err := d.Generate()
	if err != nil {
		return err
	}

	return writeOutput(output, outputFile)
}
