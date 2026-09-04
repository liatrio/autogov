package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hex64 builds a 64-char hex digest from a repeating seed character.
func hex64(seed byte) string {
	return strings.Repeat(string(seed), 64)
}

func agDigest(seed byte) string {
	return "sha256:" + hex64(seed)
}

// validAgentGovernanceDeployment returns a fully valid single-case predicate
// matching the schema contract's example shapes.
func validAgentGovernanceDeployment() *AgentGovernanceDeployment {
	return &AgentGovernanceDeployment{
		SchemaVersion: AgentGovernanceSchemaVersion,
		Agent: AgentGovernanceAgent{
			Name:           "agent-image",
			URI:            "urn:example:agent:write-marker",
			ArtifactDigest: agDigest('0'),
		},
		Runtime: AgentGovernanceRuntime{
			Name:    "example-runtime",
			Version: "1.2.3",
			Artifact: AgentGovernanceArtifactReference{
				URI:    "urn:example:runtime:1.2.3",
				Digest: agDigest('1'),
			},
		},
		Adapter: AgentGovernanceAdapter{
			Name: "non-agt-fixture",
			Artifact: AgentGovernanceArtifactReference{
				URI:    "urn:example:adapter:non-agt",
				Digest: agDigest('2'),
			},
			ContractVersion: AgentGovernanceContractVersion,
			RuntimeDigest:   agDigest('1'),
		},
		RuntimePolicy: AgentGovernanceRuntimePolicy{
			Engine: "opa",
			Artifact: AgentGovernanceArtifactReference{
				URI:    "urn:example:runtime-policy:fixture",
				Digest: agDigest('3'),
			},
			Count:  1,
			Loaded: true,
		},
		Enforcement: AgentGovernanceEnforcement{
			Mode:                       "enforce",
			DefaultBehavior:            "deny",
			RequiredInterventionPoints: []string{"tool.pre"},
			ObservedInterventionPoints: []string{"tool.pre"},
		},
		Identity: AgentGovernanceIdentity{
			ProviderURI: "urn:example:identity-provider",
			SubjectKind: "workload",
			Subject: AgentGovernanceRedactedReference{
				ID:     "redacted:fixture-workload",
				Digest: agDigest('4'),
			},
		},
		Audit: AgentGovernanceAudit{
			SinkKind: "file",
			Sink: AgentGovernanceRedactedReference{
				ID:     "redacted:fixture-audit-sink",
				Digest: agDigest('5'),
			},
			ConfigurationDigest: agDigest('6'),
		},
		Conformance: AgentGovernanceConformance{
			Fixture: AgentGovernanceFixture{ID: "non-agt-allowed-001", Producer: "non-agt"},
			ControlledTool: AgentGovernanceControlledTool{
				Name:        AgentGovernanceControlledToolName,
				ActionClass: AgentGovernanceControlledToolActionClass,
				Artifact: AgentGovernanceArtifactReference{
					URI:    "urn:autogov:fixture:write-marker",
					Digest: agDigest('7'),
				},
			},
			Cases: []AgentGovernanceCase{validAllowedCase()},
		},
	}
}

func validAllowedCase() AgentGovernanceCase {
	return AgentGovernanceCase{
		ID:            "allowed-action-001",
		Kind:          AgentGovernanceCaseAllowedAction,
		CorrelationID: agDigest('8'),
		StartedAt:     "2026-08-26T20:00:00Z",
		CompletedAt:   "2026-08-26T20:00:01Z",
		Decision: AgentGovernanceDecision{
			State:   AgentGovernanceDecisionObserved,
			Verdict: AgentGovernanceVerdictAllow,
			Reference: &AgentGovernanceRedactedReference{
				ID:     "redacted:decision-001",
				Digest: agDigest('9'),
			},
			ObservedAt: "2026-08-26T20:00:00Z",
		},
		Outcome: AgentGovernanceOutcome{
			State:  AgentGovernanceOutcomeVerified,
			Result: AgentGovernanceResultOccurred,
			Reference: &AgentGovernanceRedactedReference{
				ID:     "redacted:outcome-001",
				Digest: agDigest('a'),
			},
			ObservedAt: "2026-08-26T20:00:01Z",
		},
		TestResult: AgentGovernanceTestResultRef{
			PredicateType:   TestResultPredicateTypeURI,
			TestID:          "allowed-action-001",
			StatementDigest: agDigest('b'),
		},
	}
}

func mustGenerate(t *testing.T, d *AgentGovernanceDeployment) []byte {
	t.Helper()
	out, err := d.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	return out
}

func TestAgentGovernanceDeploymentGenerateValid(t *testing.T) {
	out := mustGenerate(t, validAgentGovernanceDeployment())

	var round map[string]interface{}
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if round["schemaVersion"] != "0.1" {
		t.Errorf("schemaVersion = %v, want 0.1", round["schemaVersion"])
	}
	// the command emits only the predicate body — never envelope fields
	for _, forbidden := range []string{"_type", "subject", "predicateType"} {
		if _, exists := round[forbidden]; exists {
			t.Errorf("predicate body must not contain envelope field %q", forbidden)
		}
	}
	if len(out) > AgentGovernanceMaxPredicateBytes {
		t.Errorf("output exceeds %d bytes", AgentGovernanceMaxPredicateBytes)
	}
}

// equivalent inputs — shuffled arrays, uppercase digest hex, non-UTC zoned
// timestamps — must generate byte-identical output.
func TestAgentGovernanceDeploymentGenerateDeterministic(t *testing.T) {
	canonical := mustGenerate(t, validAgentGovernanceDeployment())

	shuffled := validAgentGovernanceDeployment()
	shuffled.Enforcement.RequiredInterventionPoints = []string{"tool.pre", "tool.pre"}
	shuffled.Enforcement.ObservedInterventionPoints = []string{"tool.pre"}
	shuffled.Agent.ArtifactDigest = "sha256:" + strings.ToUpper(hex64('0'))
	shuffled.Conformance.Cases[0].StartedAt = "2026-08-26T22:00:00+02:00"
	shuffled.Conformance.Cases[0].Decision.ObservedAt = "2026-08-26T22:00:00+02:00"

	out := mustGenerate(t, shuffled)
	if !bytes.Equal(canonical, out) {
		t.Errorf("equivalent inputs produced different bytes:\n%s\n---\n%s", canonical, out)
	}
}

// four cases must sort into the fixed kind order regardless of input order.
func TestAgentGovernanceDeploymentCaseOrdering(t *testing.T) {
	d := validAgentGovernanceDeployment()

	denied := validAllowedCase()
	denied.ID = "denied-action-001"
	denied.Kind = AgentGovernanceCaseDeniedAction
	denied.Decision.Verdict = AgentGovernanceVerdictDeny
	denied.Outcome.Result = AgentGovernanceResultBlocked
	denied.TestResult.TestID = denied.ID

	bypass := validAllowedCase()
	bypass.ID = "adapter-bypass-001"
	bypass.Kind = AgentGovernanceCaseAdapterBypass
	bypass.Decision = AgentGovernanceDecision{State: AgentGovernanceDecisionNotObserved, Verdict: AgentGovernanceVerdictUnknown}
	bypass.TestResult.TestID = bypass.ID

	d.Conformance.Cases = []AgentGovernanceCase{bypass, denied, validAllowedCase()}
	// bypass contradiction check needs the required point to not be exercised
	// for the bypass case; on a multi-case predicate the not-observed decision
	// is already sufficient (decision not observed => no contradiction).
	out := mustGenerate(t, d)

	var round struct {
		Conformance struct {
			Cases []struct {
				Kind string `json:"kind"`
			} `json:"cases"`
		} `json:"conformance"`
	}
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := make([]string, 0, len(round.Conformance.Cases))
	for _, c := range round.Conformance.Cases {
		got = append(got, c.Kind)
	}
	want := []string{"allowed-action", "denied-action", "adapter-bypass"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("case order = %v, want %v", got, want)
	}
}

func TestAgentGovernanceDeploymentGenerateDeterministicCollectionsAndExtensions(t *testing.T) {
	buildEquivalent := func(reverse bool) *AgentGovernanceDeployment {
		d := validAgentGovernanceDeployment()
		denied := validAllowedCase()
		denied.ID = "denied-action-001"
		denied.Kind = AgentGovernanceCaseDeniedAction
		denied.Decision.Verdict = AgentGovernanceVerdictDeny
		denied.Outcome.Result = AgentGovernanceResultBlocked
		denied.TestResult.TestID = denied.ID
		if reverse {
			d.Conformance.Cases = []AgentGovernanceCase{denied, validAllowedCase()}
			d.Enforcement.RequiredInterventionPoints = []string{"tool.z", "tool.pre"}
			d.Enforcement.ObservedInterventionPoints = []string{"tool.z", "tool.pre"}
			d.Extensions = map[string]json.RawMessage{
				"https://example.com/extensions/a": json.RawMessage(`{"b":2,"a":1}`),
				"https://example.com/extensions/b": json.RawMessage(`[{"z":0,"a":1}]`),
			}
		} else {
			d.Conformance.Cases = []AgentGovernanceCase{validAllowedCase(), denied}
			d.Enforcement.RequiredInterventionPoints = []string{"tool.pre", "tool.z"}
			d.Enforcement.ObservedInterventionPoints = []string{"tool.pre", "tool.z"}
			d.Extensions = map[string]json.RawMessage{
				"https://example.com/extensions/b": json.RawMessage(`[{"a":1,"z":0}]`),
				"https://example.com/extensions/a": json.RawMessage(`{"a":1,"b":2}`),
			}
		}
		return d
	}

	left := mustGenerate(t, buildEquivalent(false))
	right := mustGenerate(t, buildEquivalent(true))
	if !bytes.Equal(left, right) {
		t.Errorf("equivalent shuffled collections/extensions produced different bytes:\n%s\n---\n%s", left, right)
	}
}

func TestAgentGovernanceDeploymentSemanticRejections(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AgentGovernanceDeployment)
		wantErr string
	}{
		{
			name:    "wrong schema version",
			mutate:  func(d *AgentGovernanceDeployment) { d.SchemaVersion = "0.2" },
			wantErr: "schemaVersion",
		},
		{
			name:    "runtime linkage mismatch",
			mutate:  func(d *AgentGovernanceDeployment) { d.Adapter.RuntimeDigest = agDigest('f') },
			wantErr: "runtime linkage mismatch",
		},
		{
			name:    "loaded contradicts count",
			mutate:  func(d *AgentGovernanceDeployment) { d.RuntimePolicy.Count = 0 },
			wantErr: "runtimePolicy.loaded",
		},
		{
			name:    "count over bound",
			mutate:  func(d *AgentGovernanceDeployment) { d.RuntimePolicy.Count = 65 },
			wantErr: "runtimePolicy.count",
		},
		{
			name:    "malformed digest",
			mutate:  func(d *AgentGovernanceDeployment) { d.Agent.ArtifactDigest = hex64('0') },
			wantErr: "invalid digest",
		},
		{
			name:    "non-allowlisted artifact scheme",
			mutate:  func(d *AgentGovernanceDeployment) { d.Runtime.Artifact.URI = "ftp://example.com/runtime" },
			wantErr: "scheme",
		},
		{
			name:    "authority-less artifact URI",
			mutate:  func(d *AgentGovernanceDeployment) { d.Runtime.Artifact.URI = "https:runtime" },
			wantErr: "authority",
		},
		{
			name: "duplicate case ids",
			mutate: func(d *AgentGovernanceDeployment) {
				dup := validAllowedCase()
				dup.Kind = AgentGovernanceCaseDeniedAction
				dup.Decision.Verdict = AgentGovernanceVerdictDeny
				dup.Outcome.Result = AgentGovernanceResultBlocked
				d.Conformance.Cases = append(d.Conformance.Cases, dup)
			},
			wantErr: "duplicate case id",
		},
		{
			name: "duplicate case kinds",
			mutate: func(d *AgentGovernanceDeployment) {
				dup := validAllowedCase()
				dup.ID = "allowed-action-002"
				dup.TestResult.TestID = dup.ID
				d.Conformance.Cases = append(d.Conformance.Cases, dup)
			},
			wantErr: "duplicate case kind",
		},
		{
			name: "time reversal",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].StartedAt = "2026-08-26T20:00:02Z"
			},
			wantErr: "completedAt must not be earlier",
		},
		{
			name: "overlong duration",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].CompletedAt = "2026-08-26T20:06:00Z"
				d.Conformance.Cases[0].Outcome.ObservedAt = "2026-08-26T20:00:01Z"
			},
			wantErr: "at most five minutes",
		},
		{
			name: "decision observedAt outside interval",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Decision.ObservedAt = "2026-08-26T19:59:59Z"
			},
			wantErr: "within the case interval",
		},
		{
			name: "fractional observedAt cannot be truncated into interval",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Decision.ObservedAt = "2026-08-26T20:00:01.500Z"
			},
			wantErr: "fractional seconds",
		},
		{
			name: "unknown verdict with observed state",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Decision.Verdict = AgentGovernanceVerdictUnknown
			},
			wantErr: "observed decision requires allow or deny",
		},
		{
			name: "not-observed decision keeps a reference",
			mutate: func(d *AgentGovernanceDeployment) {
				c := &d.Conformance.Cases[0]
				c.Kind = AgentGovernanceCaseAdapterBypass
				c.Decision.State = AgentGovernanceDecisionNotObserved
				c.Decision.Verdict = AgentGovernanceVerdictUnknown
				c.Decision.ObservedAt = ""
				// reference left set: conditional members must be omitted
			},
			wantErr: "must be omitted when not observed",
		},
		{
			name: "unknown outcome with verified result",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Outcome.State = AgentGovernanceOutcomeUnknown
			},
			wantErr: "must be unknown when the outcome state is unknown",
		},
		{
			name: "verified outcome missing reference",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Outcome.Reference = nil
			},
			wantErr: "outcome.reference",
		},
		{
			name: "testId mismatch",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].TestResult.TestID = "other-case"
			},
			wantErr: "testId",
		},
		{
			name: "allowed-action contradicts observed deny",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Decision.Verdict = AgentGovernanceVerdictDeny
			},
			wantErr: "allowed-action contradicts",
		},
		{
			name: "denied-action contradicts observed allow",
			mutate: func(d *AgentGovernanceDeployment) {
				c := &d.Conformance.Cases[0]
				c.Kind = AgentGovernanceCaseDeniedAction
				c.Decision.Verdict = AgentGovernanceVerdictAllow
				c.Outcome.Result = AgentGovernanceResultBlocked
			},
			wantErr: "denied-action contradicts",
		},
		{
			name: "no-policy-loaded contradicts loaded policy",
			mutate: func(d *AgentGovernanceDeployment) {
				c := &d.Conformance.Cases[0]
				c.Kind = AgentGovernanceCaseNoPolicyLoaded
			},
			wantErr: "no-policy-loaded contradicts",
		},
		{
			name: "adapter-bypass contradicts observed decision with exercised points",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Conformance.Cases[0].Kind = AgentGovernanceCaseAdapterBypass
			},
			wantErr: "adapter-bypass contradicts",
		},
		{
			name: "oversized free text",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Runtime.Version = strings.Repeat("v", 129)
			},
			wantErr: "exceeds 128 bytes",
		},
		{
			name: "control characters in name",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Runtime.Name = "bad\nname"
			},
			wantErr: "control characters",
		},
		{
			name: "unicode control characters in name",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Runtime.Name = "bad\u0085name"
			},
			wantErr: "control characters",
		},
		{
			name: "invalid redacted reference",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Identity.Subject.ID = "workload-1"
			},
			wantErr: "identity.subject.id",
		},
		{
			name: "invalid percent escape in artifact URI",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Runtime.Artifact.URI = "urn:%zz"
			},
			wantErr: "percent-encoding",
		},
		{
			name: "malformed bracketed artifact authority",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Runtime.Artifact.URI = "https://[broken"
			},
			wantErr: "absolute URI",
		},
		{
			name: "uppercase artifact URI scheme",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Runtime.Artifact.URI = "HTTPS://registry.example/runtime"
			},
			wantErr: "lowercase",
		},
		{
			name: "extensions too many keys",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{}
				for i := 0; i < 9; i++ {
					d.Extensions[fmt.Sprintf("https://example.com/ext/%d", i)] = json.RawMessage(`1`)
				}
			},
			wantErr: "at most 8 keys",
		},
		{
			name: "extensions non-uri key",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{"notauri": json.RawMessage(`1`)}
			},
			wantErr: "extensions key",
		},
		{
			name: "extensions value too deep",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{
					"https://example.com/ext": json.RawMessage(`{"a":{"b":{"c":{"d":{"e":1}}}}}`),
				}
			},
			wantErr: "nesting depth",
		},
		{
			name: "extensions value too large",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{
					"https://example.com/ext": json.RawMessage(`"` + strings.Repeat("x", 4200) + `"`),
				}
			},
			wantErr: "4096",
		},
		{
			name: "extensions total value size too large",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{}
				for i := 0; i < 5; i++ {
					d.Extensions[fmt.Sprintf("https://example.com/ext/%d", i)] = json.RawMessage(`"` + strings.Repeat("x", 3300) + `"`)
				}
			},
			wantErr: "16384",
		},
		{
			name: "extensions object too wide",
			mutate: func(d *AgentGovernanceDeployment) {
				members := make([]string, 17)
				for i := range members {
					members[i] = fmt.Sprintf(`"k%d":%d`, i, i)
				}
				d.Extensions = map[string]json.RawMessage{
					"https://example.com/ext": json.RawMessage(`{` + strings.Join(members, ",") + `}`),
				}
			},
			wantErr: "16 members",
		},
		{
			name: "extensions array too wide",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{
					"https://example.com/ext": json.RawMessage(`[` + strings.Repeat("0,", 16) + `0]`),
				}
			},
			wantErr: "16 items",
		},
		{
			name: "extensions key too long",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{
					"https://example.com/" + strings.Repeat("x", 240): json.RawMessage(`1`),
				}
			},
			wantErr: "256 bytes",
		},
		{
			name: "extensions malformed raw JSON",
			mutate: func(d *AgentGovernanceDeployment) {
				d.Extensions = map[string]json.RawMessage{
					"https://example.com/ext": json.RawMessage(`{"broken":`),
				}
			},
			wantErr: "valid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := validAgentGovernanceDeployment()
			tt.mutate(d)
			_, err := d.Generate()
			if err == nil {
				t.Fatalf("Generate() succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Generate() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// an adapter-supplied aggregate verdict (or any unknown field) fails closed at
// parse time.
func TestParseAgentGovernanceEvidenceRejectsAggregateClaims(t *testing.T) {
	base := validAgentGovernanceDeployment()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["passed"] = true
	withAggregate, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseAgentGovernanceEvidence(withAggregate); err == nil {
		t.Error("expected an unknown-field error for an adapter-supplied aggregate 'passed' claim")
	}

	if _, err := ParseAgentGovernanceEvidence(append(raw, []byte("{}")...)); err == nil {
		t.Error("expected a trailing-data error")
	}
	// a bare trailing '}' is invisible to Decoder.More and must still fail
	if _, err := ParseAgentGovernanceEvidence(append(raw, '}')); err == nil {
		t.Error("expected a trailing-data error for a trailing '}'")
	}
}

// producer evidence is decoded before the signing helper fills the one
// deferred linkage field (testResult.statementDigest). every other required
// member must be present: Go's zero values must not fabricate a no-policy
// observation when a producer omitted count or loaded.
func TestParseAgentGovernanceEvidenceRejectsMissingRequiredMembers(t *testing.T) {
	base := validAgentGovernanceDeployment()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"count", "loaded"} {
		t.Run("runtimePolicy."+field, func(t *testing.T) {
			var body map[string]interface{}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			delete(body["runtimePolicy"].(map[string]interface{}), field)
			mutated, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseAgentGovernanceEvidence(mutated); err == nil {
				t.Errorf("missing runtimePolicy.%s was accepted", field)
			}
		})
	}

	t.Run("null runtimePolicy facts", func(t *testing.T) {
		var body map[string]interface{}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		policy := body["runtimePolicy"].(map[string]interface{})
		policy["count"] = nil
		policy["loaded"] = nil
		mutated, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentGovernanceEvidence(mutated); err == nil {
			t.Error("null runtimePolicy facts were decoded as fabricated zero values")
		}
	})

	t.Run("null required array", func(t *testing.T) {
		var body map[string]interface{}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		body["enforcement"].(map[string]interface{})["observedInterventionPoints"] = nil
		mutated, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentGovernanceEvidence(mutated); err == nil {
			t.Error("null required array was accepted")
		}
	})
}

func TestAgentGovernanceExtensionDepthAllowsFourContainers(t *testing.T) {
	d := validAgentGovernanceDeployment()
	d.Extensions = map[string]json.RawMessage{
		"https://example.com/ext": json.RawMessage(`{"a":{"b":{"c":{"d":1}}}}`),
	}
	if _, err := d.Generate(); err != nil {
		t.Fatalf("four nested extension containers were rejected: %v", err)
	}
}

func TestAgentGovernanceValidationDoesNotEchoUnvalidatedCaseID(t *testing.T) {
	d := validAgentGovernanceDeployment()
	secret := "untrusted\ncase-id"
	d.Conformance.Cases[0].ID = secret
	d.Conformance.Cases[0].TestResult.TestID = secret
	_, err := d.Generate()
	if err == nil {
		t.Fatal("invalid case id was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("validation error echoed the unvalidated case id: %q", err)
	}
}

// the JSON schema independently rejects structural violations.
func TestAgentGovernanceSchemaRejections(t *testing.T) {
	valid := mustGenerate(t, validAgentGovernanceDeployment())

	mutate := func(t *testing.T, f func(map[string]interface{})) []byte {
		t.Helper()
		var m map[string]interface{}
		if err := json.Unmarshal(valid, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"missing required field", func(m map[string]interface{}) { delete(m, "agent") }},
		{"extra core property", func(m map[string]interface{}) { m["compliant"] = true }},
		{"invalid enum", func(m map[string]interface{}) {
			m["enforcement"].(map[string]interface{})["mode"] = "advisory"
		}},
		{"malformed digest", func(m map[string]interface{}) {
			m["agent"].(map[string]interface{})["artifactDigest"] = "sha1:1234"
		}},
		{"malformed timestamp", func(m map[string]interface{}) {
			cases := m["conformance"].(map[string]interface{})["cases"].([]interface{})
			cases[0].(map[string]interface{})["startedAt"] = "2026-08-26 20:00:00"
		}},
		{"malformed agent URI", func(m map[string]interface{}) {
			m["agent"].(map[string]interface{})["uri"] = "not a URI"
		}},
		{"hostless https agent URI", func(m map[string]interface{}) {
			m["agent"].(map[string]interface{})["uri"] = "https:anything"
		}},
		{"malformed identity provider URI", func(m map[string]interface{}) {
			m["identity"].(map[string]interface{})["providerUri"] = "not a URI"
		}},
		{"hostless oci identity provider URI", func(m map[string]interface{}) {
			m["identity"].(map[string]interface{})["providerUri"] = "oci:anything"
		}},
		{"hostless https artifact URI", func(m map[string]interface{}) {
			m["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})["uri"] = "https:runtime"
		}},
		{"control character in artifact URI", func(m map[string]interface{}) {
			m["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})["uri"] = "urn:runtime\x00injected"
		}},
		{"invalid percent escape in artifact URI", func(m map[string]interface{}) {
			m["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})["uri"] = "urn:%zz"
		}},
		{"malformed bracketed artifact authority", func(m map[string]interface{}) {
			m["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})["uri"] = "https://[broken"
		}},
		{"uppercase artifact URI scheme", func(m map[string]interface{}) {
			m["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})["uri"] = "HTTPS://registry.example/runtime"
		}},
		{"unicode control character in runtime name", func(m map[string]interface{}) {
			m["runtime"].(map[string]interface{})["name"] = "runtime\u0085injected"
		}},
		{"non-URI extension key", func(m map[string]interface{}) {
			m["extensions"] = map[string]interface{}{"notauri": map[string]interface{}{}}
		}},
		{"over-bound cases array", func(m map[string]interface{}) {
			conformance := m["conformance"].(map[string]interface{})
			cases := conformance["cases"].([]interface{})
			c := cases[0]
			conformance["cases"] = []interface{}{c, c, c, c, c}
		}},
		{"wrong controlled tool const", func(m map[string]interface{}) {
			tool := m["conformance"].(map[string]interface{})["controlledTool"].(map[string]interface{})
			tool["name"] = "delete-everything"
		}},
	}

	if err := ValidateAgentGovernanceDeployment(valid); err != nil {
		t.Fatalf("valid predicate failed schema validation: %v", err)
	}
	validPercentEscape := mutate(t, func(m map[string]interface{}) {
		m["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})["uri"] = "https://registry.example:443/runtime%20artifact"
	})
	if err := ValidateAgentGovernanceDeployment(validPercentEscape); err != nil {
		t.Fatalf("valid percent-encoded artifact URI failed schema validation: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAgentGovernanceDeployment(mutate(t, tt.mutate)); err == nil {
				t.Error("expected schema validation to reject the mutation")
			}
		})
	}
}

// no partial output file may exist after a failed generation.
func TestGenerateAgentGovernanceDeploymentNoPartialFile(t *testing.T) {
	dir := t.TempDir()

	bad := validAgentGovernanceDeployment()
	bad.Agent.ArtifactDigest = "not-a-digest"
	raw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(evidencePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(dir, "predicate.json")
	if err := GenerateAgentGovernanceDeployment(evidencePath, outputPath); err == nil {
		t.Fatal("expected generation to fail for a malformed digest")
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Errorf("expected no partial predicate file, stat err = %v", err)
	}

	// a failed run must also preserve an existing caller-owned output rather
	// than truncating it before all parsing and validation succeeds.
	const existing = "previous valid output\n"
	if err := os.WriteFile(outputPath, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	if err := GenerateAgentGovernanceDeployment(evidencePath, outputPath); err == nil {
		t.Fatal("expected generation to fail for a malformed digest with an existing output")
	}
	unchanged, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != existing {
		t.Errorf("failed generation changed existing output to %q", unchanged)
	}

	// and the happy path writes a file that parses
	good := validAgentGovernanceDeployment()
	rawGood, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, rawGood, 0600); err != nil {
		t.Fatal(err)
	}
	if err := GenerateAgentGovernanceDeployment(evidencePath, outputPath); err != nil {
		t.Fatalf("generation failed: %v", err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgentGovernanceDeployment(content); err != nil {
		t.Errorf("written predicate failed schema validation: %v", err)
	}
}

func TestGenerateAgentGovernanceDeploymentInputBoundIsInclusive(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	outputPath := filepath.Join(dir, "predicate.json")
	raw, err := json.Marshal(validAgentGovernanceDeployment())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= AgentGovernanceMaxPredicateBytes {
		t.Fatalf("valid fixture is %d bytes, cannot pad it to the input boundary", len(raw))
	}
	exact := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), AgentGovernanceMaxPredicateBytes-len(raw))...)
	if _, err := ParseAgentGovernanceEvidence(exact); err != nil {
		t.Fatalf("parser rejected evidence at the exact %d-byte limit: %v", AgentGovernanceMaxPredicateBytes, err)
	}
	if err := os.WriteFile(evidencePath, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := GenerateAgentGovernanceDeployment(evidencePath, outputPath); err != nil {
		t.Fatalf("generator rejected evidence at the exact %d-byte limit: %v", AgentGovernanceMaxPredicateBytes, err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	want := mustGenerate(t, validAgentGovernanceDeployment())
	if !bytes.Equal(got, want) {
		t.Fatal("boundary padding changed valid predicate bytes")
	}

	oversized := append(append([]byte(nil), exact...), ' ')
	if err := os.WriteFile(evidencePath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedOutputPath := filepath.Join(dir, "oversized-predicate.json")

	err = GenerateAgentGovernanceDeployment(evidencePath, oversizedOutputPath)
	if err == nil || !strings.Contains(err.Error(), "input bound") {
		t.Fatalf("oversized evidence error = %v, want bounded-input rejection", err)
	}
	if _, err := os.Stat(oversizedOutputPath); !os.IsNotExist(err) {
		t.Fatalf("oversized evidence created output: %v", err)
	}
	if _, err := ParseAgentGovernanceEvidence(oversized); err == nil {
		t.Fatal("direct parser accepted oversized evidence")
	}
}

type boundedReadProbe struct {
	remaining int
	overRead  bool
}

func (r *boundedReadProbe) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		r.overRead = true
		return 0, fmt.Errorf("read after the allowed probe boundary")
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.remaining -= len(p)
	return len(p), nil
}

func TestBoundedEvidenceReaderDoesNotReadPastLimitPlusOne(t *testing.T) {
	probe := &boundedReadProbe{remaining: AgentGovernanceMaxPredicateBytes + 1}
	_, err := readBoundedAgentGovernanceEvidence(probe)
	if err == nil || !strings.Contains(err.Error(), "input bound") {
		t.Fatalf("bounded reader error = %v, want input-bound rejection", err)
	}
	if probe.overRead {
		t.Fatal("bounded reader requested bytes after consuming limit plus one")
	}
	if probe.remaining != 0 {
		t.Fatalf("bounded reader left %d probe bytes unread, want exactly limit plus one consumed", probe.remaining)
	}
}

// URI lockstep: the self-contained companion constant and embedded schema
// agree on the locked URI. AutoGov owns its registry/documentation lockstep.
func TestAgentGovernanceURILockstep(t *testing.T) {
	const wantURI = "https://autogov.dev/attestation/agent-governance-deployment/v0.1"
	if AgentGovernanceDeploymentPredicateTypeURI != wantURI {
		t.Errorf("companion predicate constant = %q, want %q", AgentGovernanceDeploymentPredicateTypeURI, wantURI)
	}
	if !strings.Contains(embeddedAgentGovernanceDeploymentSchema, `"const": "`+wantURI+`"`) {
		t.Error("embedded schema does not lock the predicateType const to the URI")
	}
}
