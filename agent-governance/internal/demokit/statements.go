// Package demokit is the demonstration/signing layer of the agent-governance
// evidence spike. It owns everything the runtime fixtures must not do: it
// completes producer evidence with the signed test-result statement digest,
// generates the deterministic deployment predicate body through the
// companion-owned evidence package,
// wraps both predicate bodies in single-subject in-toto Statements, and signs
// them into offline-verifiable Sigstore bundles with a local demonstration CA.
//
// demokit is example/test tooling only: it is not part of the autogov
// production binary and the runtime fixtures never import it — they stop at
// redacted JSON evidence.
package demokit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	pred "github.com/liatrio/autogov/agent-governance/internal/evidence"
)

// InTotoStatementType is the in-toto v1 statement envelope type.
const InTotoStatementType = "https://in-toto.io/Statement/v1"

// ConformanceDescriptorName names the single test-result configuration
// descriptor carrying the agent-governance linkage annotations.
const ConformanceDescriptorName = "agent-governance-conformance-v0.1"

// ConformanceDescriptorURI is that descriptor's URI.
const ConformanceDescriptorURI = pred.AgentGovernanceDeploymentPredicateTypeURI + "#conformance"

// Statement is a minimal single-subject in-toto v1 statement envelope with a
// deterministic field order.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject is one in-toto statement subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// BuiltCase holds one conformance case's completed artifacts: the validated
// deployment predicate body and the exact statement bytes that become the
// signed DSSE payloads.
type BuiltCase struct {
	Evidence            *pred.AgentGovernanceDeployment
	PredicateBody       []byte
	DeploymentStatement []byte
	TestResultStatement []byte
	AgentName           string
	AgentDigestHex      string
}

func annKey(suffix string) string {
	return pred.AgentGovernanceDeploymentPredicateTypeURI + "#" + suffix
}

// BuildCase reads one producer evidence file (a predicate body whose
// case.testResult.statementDigest is not yet bound), builds the paired
// standard test-result statement, binds its exact payload digest into the
// evidence, generates the validated deterministic predicate body, and wraps
// it in the deployment statement.
func BuildCase(evidencePath string) (*BuiltCase, error) {
	data, err := pred.ReadAgentGovernanceEvidenceFile(evidencePath)
	if err != nil {
		return nil, err
	}

	evidence, err := pred.ParseAgentGovernanceEvidence(data)
	if err != nil {
		return nil, err
	}
	if len(evidence.Conformance.Cases) != 1 {
		return nil, fmt.Errorf("demo evidence must carry exactly one case, found %d", len(evidence.Conformance.Cases))
	}
	if evidence.Conformance.Cases[0].TestResult.StatementDigest != "" {
		return nil, fmt.Errorf("demo evidence must omit testResult.statementDigest until the signing helper builds the test-result statement")
	}

	// the producer may use equivalent, non-canonical input encodings. normalize
	// those facts before deriving the separately signed test-result subject and
	// annotations. Normalize requires a digest-shaped linkage value, so reserve
	// a temporary canonical placeholder until the exact payload digest exists.
	evidence.Conformance.Cases[0].TestResult.StatementDigest = "sha256:" + strings.Repeat("0", 64)
	if err := evidence.Normalize(); err != nil {
		return nil, err
	}
	evidence.Conformance.Cases[0].TestResult.StatementDigest = ""

	testResultStatement, err := BuildTestResultStatement(evidence, evidence.Conformance.Cases[0])
	if err != nil {
		return nil, err
	}

	// bind the exact signed DSSE payload bytes of the test-result statement
	digest := sha256.Sum256(testResultStatement)
	evidence.Conformance.Cases[0].TestResult.StatementDigest = "sha256:" + hex.EncodeToString(digest[:])

	body, err := evidence.Generate()
	if err != nil {
		return nil, err
	}

	deploymentStatement, err := BuildDeploymentStatement(evidence, body)
	if err != nil {
		return nil, err
	}

	return &BuiltCase{
		Evidence:            evidence,
		PredicateBody:       body,
		DeploymentStatement: deploymentStatement,
		TestResultStatement: testResultStatement,
		AgentName:           evidence.Agent.Name,
		AgentDigestHex:      strings.TrimPrefix(evidence.Agent.ArtifactDigest, "sha256:"),
	}, nil
}

// BuildDeploymentStatement wraps a generated predicate body in exactly one
// in-toto Statement and performs the envelope cross-check the command itself
// cannot: the sole subject equals the predicate's agent name and digest.
func BuildDeploymentStatement(evidence *pred.AgentGovernanceDeployment, body []byte) ([]byte, error) {
	var check struct {
		Agent struct {
			Name           string `json:"name"`
			ArtifactDigest string `json:"artifactDigest"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(body, &check); err != nil {
		return nil, fmt.Errorf("predicate body is not valid JSON: %w", err)
	}
	if check.Agent.Name != evidence.Agent.Name || check.Agent.ArtifactDigest != evidence.Agent.ArtifactDigest {
		return nil, fmt.Errorf("predicate body agent identity does not match the evidence subject")
	}

	return json.Marshal(Statement{
		Type:          InTotoStatementType,
		Subject:       []Subject{agentSubject(evidence)},
		PredicateType: pred.AgentGovernanceDeploymentPredicateTypeURI,
		Predicate:     json.RawMessage(body),
	})
}

// BuildTestResultStatement builds the separately signed standard in-toto
// test-result statement for one case, following the spike's strict linkage
// profile: same single agent subject, exactly one conformance descriptor
// bound to the controlled-tool artifact, the namespaced annotation set for
// the case facts, and the bounded result profile (PASSED/[case] for a
// verified observation, WARNED/[case] for the unknown-outcome negative). The
// aggregate result records only that the observation harness completed —
// never a deployment-admission verdict.
func BuildTestResultStatement(evidence *pred.AgentGovernanceDeployment, c pred.AgentGovernanceCase) ([]byte, error) {
	annotations := map[string]any{
		annKey("agentDigest"):     evidence.Agent.ArtifactDigest,
		annKey("caseId"):          c.ID,
		annKey("correlationId"):   c.CorrelationID,
		annKey("decisionState"):   c.Decision.State,
		annKey("decisionVerdict"): c.Decision.Verdict,
		annKey("outcomeState"):    c.Outcome.State,
		annKey("outcomeResult"):   c.Outcome.Result,
	}
	if c.Decision.State == pred.AgentGovernanceDecisionObserved {
		if c.Decision.Reference == nil {
			return nil, fmt.Errorf("case %s: observed decision without a reference", c.ID)
		}
		annotations[annKey("decisionDigest")] = c.Decision.Reference.Digest
	}

	predicate := pred.TestResult{
		Configuration: []pred.ResourceDescriptor{{
			Name: ConformanceDescriptorName,
			URI:  ConformanceDescriptorURI,
			Digest: map[string]string{
				"sha256": strings.TrimPrefix(evidence.Conformance.ControlledTool.Artifact.Digest, "sha256:"),
			},
			Annotations: annotations,
		}},
		PassedTests: []string{},
		WarnedTests: []string{},
		FailedTests: []string{},
	}

	switch c.Outcome.State {
	case pred.AgentGovernanceOutcomeVerified:
		if c.Outcome.Reference == nil {
			return nil, fmt.Errorf("case %s: verified outcome without a reference", c.ID)
		}
		annotations[annKey("resultArtifactDigest")] = c.Outcome.Reference.Digest
		predicate.Result = pred.TestResultPassed
		predicate.PassedTests = []string{c.ID}
	case pred.AgentGovernanceOutcomeUnknown:
		predicate.Result = pred.TestResultWarned
		predicate.WarnedTests = []string{c.ID}
	default:
		return nil, fmt.Errorf("case %s: unsupported outcome state", c.ID)
	}

	body, err := json.Marshal(&predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal test-result predicate: %w", err)
	}
	if err := pred.ValidateEmbeddedTestResult(body); err != nil {
		return nil, fmt.Errorf("test-result predicate failed schema validation: %w", err)
	}

	return json.Marshal(Statement{
		Type:          InTotoStatementType,
		Subject:       []Subject{agentSubject(evidence)},
		PredicateType: pred.TestResultPredicateTypeURI,
		Predicate:     json.RawMessage(body),
	})
}

func agentSubject(evidence *pred.AgentGovernanceDeployment) Subject {
	return Subject{
		Name: evidence.Agent.Name,
		Digest: map[string]string{
			"sha256": strings.TrimPrefix(evidence.Agent.ArtifactDigest, "sha256:"),
		},
	}
}
