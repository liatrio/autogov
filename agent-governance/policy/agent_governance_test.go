package policy_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liatrio/autogov/agent-governance/internal/demokit"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

const inTotoPayloadType = "application/vnd.in-toto+json"

type policyResult struct {
	allow      bool
	violations []string
}

func TestAgentGovernancePolicyStrictCompile(t *testing.T) {
	source, err := os.ReadFile("agent_governance.rego")
	if err != nil {
		t.Fatal(err)
	}
	module, err := ast.ParseModule("agent_governance.rego", string(source))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	compiler := ast.NewCompiler().WithStrict(true)
	compiler.Compile(map[string]*ast.Module{"agent_governance.rego": module})
	if compiler.Failed() {
		t.Fatalf("strict policy compilation failed: %v", compiler.Errors)
	}
}

// evaluatePolicy compiles and evaluates the checked-in local gate through the
// same OPA Go library used by Auto Gov. this makes its linkage rules
// load-bearing in go test without adding an OPA CLI or changing CI.
func evaluatePolicy(t *testing.T, statements ...[]byte) policyResult {
	t.Helper()
	module, err := os.ReadFile("agent_governance.rego")
	if err != nil {
		t.Fatal(err)
	}
	return evaluatePolicySource(t, string(module), statements...)
}

func evaluatePolicySource(t *testing.T, source string, statements ...[]byte) policyResult {
	t.Helper()
	input := make([]interface{}, 0, len(statements))
	for _, statement := range statements {
		input = append(input, map[string]interface{}{
			"dsseEnvelope": map[string]interface{}{
				"payload":     base64.StdEncoding.EncodeToString(statement),
				"payloadType": inTotoPayloadType,
			},
		})
	}
	results, err := rego.New(
		rego.Query("data.governance"),
		rego.Module("agent_governance.rego", source),
		rego.Input(input),
	).Eval(context.Background())
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		t.Fatalf("unexpected policy result: %#v", results)
	}
	value, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		t.Fatalf("governance document = %#v, want object", results[0].Expressions[0].Value)
	}
	allow, _ := value["allow"].(bool)
	return policyResult{allow: allow, violations: policyViolations(value)}
}

func policyViolations(document map[string]interface{}) []string {
	violations, _ := document["violations"].(map[string]interface{})
	rows, _ := violations["agent_governance"].([]interface{})
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if message, ok := row.(string); ok {
			out = append(out, message)
		}
	}
	return out
}

func requireAllowed(t *testing.T, result policyResult) {
	t.Helper()
	if !result.allow {
		t.Fatalf("policy denied valid evidence: %v", result.violations)
	}
}

func requireDenied(t *testing.T, result policyResult) {
	t.Helper()
	if result.allow {
		t.Fatal("policy admitted adversarial evidence")
	}
}

func requireViolation(t *testing.T, result policyResult, want string) {
	t.Helper()
	for _, violation := range result.violations {
		if strings.Contains(violation, want) {
			return
		}
	}
	t.Fatalf("violations %q do not contain %q", result.violations, want)
}

func builtCase(t *testing.T, name string) *demokit.BuiltCase {
	t.Helper()
	built, err := demokit.BuildCase(filepath.Join("..", "fixtures", "evidence", "non-agt", name+".json"))
	if err != nil {
		t.Fatalf("build %s: %v", name, err)
	}
	return built
}

func object(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var value map[string]interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func jsonBytes(t *testing.T, value interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func deploymentPredicate(t *testing.T, statement []byte) map[string]interface{} {
	t.Helper()
	return object(t, statement)["predicate"].(map[string]interface{})
}

func caseAt(t *testing.T, predicate map[string]interface{}, index int) map[string]interface{} {
	t.Helper()
	cases := predicate["conformance"].(map[string]interface{})["cases"].([]interface{})
	return cases[index].(map[string]interface{})
}

// relinkDeployment returns a hand-built deployment statement whose first case
// is bound to testResult's exact payload digest. the policy test deliberately
// preserves this linkage before changing another fact, so a generic digest
// mismatch cannot hide the rule under test.
func relinkDeployment(t *testing.T, built *demokit.BuiltCase, testResult []byte, mutate func(map[string]interface{})) []byte {
	t.Helper()
	statement := object(t, built.DeploymentStatement)
	predicate := statement["predicate"].(map[string]interface{})
	sum := sha256.Sum256(testResult)
	caseAt(t, predicate, 0)["testResult"].(map[string]interface{})["statementDigest"] = "sha256:" + hex.EncodeToString(sum[:])
	if mutate != nil {
		mutate(predicate)
	}
	return jsonBytes(t, statement)
}

func mutatedTestResult(t *testing.T, built *demokit.BuiltCase, mutate func(map[string]interface{})) (deployment, testResult []byte) {
	t.Helper()
	return mutatedTestResultStatement(t, built, func(statement map[string]interface{}) {
		mutate(statement["predicate"].(map[string]interface{}))
	})
}

func mutatedTestResultStatement(t *testing.T, built *demokit.BuiltCase, mutate func(map[string]interface{})) (deployment, testResult []byte) {
	t.Helper()
	statement := object(t, built.TestResultStatement)
	if mutate != nil {
		mutate(statement)
	}
	testResult = jsonBytes(t, statement)
	return relinkDeployment(t, built, testResult, nil), testResult
}

func TestAgentGovernanceGateLinkageRules(t *testing.T) {
	built := builtCase(t, "allowed-action")

	t.Run("valid signed payload facts admit", func(t *testing.T) {
		requireAllowed(t, evaluatePolicy(t, built.DeploymentStatement, built.TestResultStatement))
	})

	t.Run("conformance descriptor remains load-bearing", func(t *testing.T) {
		deployment, testResult := mutatedTestResult(t, built, func(predicate map[string]interface{}) {
			configuration := predicate["configuration"].([]interface{})
			configuration[0].(map[string]interface{})["name"] = "other-descriptor"
		})
		requireDenied(t, evaluatePolicy(t, deployment, testResult))
	})

	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{
			name: "referenced statement digest",
			mutate: func(predicate map[string]interface{}) {
				caseAt(t, predicate, 0)["testResult"].(map[string]interface{})["statementDigest"] = "sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name: "referenced test id",
			mutate: func(predicate map[string]interface{}) {
				caseAt(t, predicate, 0)["testResult"].(map[string]interface{})["testId"] = "other-test"
			},
		},
	} {
		t.Run(tc.name+" remains load-bearing", func(t *testing.T) {
			deployment := relinkDeployment(t, built, built.TestResultStatement, tc.mutate)
			result := evaluatePolicy(t, deployment, built.TestResultStatement)
			requireDenied(t, result)
			requireViolation(t, result, "fails cross-binding")
		})
	}

	annotationKey := func(suffix string) string {
		return "https://autogov.dev/attestation/agent-governance-deployment/v0.1#" + suffix
	}
	descriptor := func(statement map[string]interface{}) map[string]interface{} {
		predicate := statement["predicate"].(map[string]interface{})
		configuration := predicate["configuration"].([]interface{})
		return configuration[0].(map[string]interface{})
	}
	annotations := func(statement map[string]interface{}) map[string]interface{} {
		return descriptor(statement)["annotations"].(map[string]interface{})
	}

	for _, tc := range []struct {
		name          string
		violation     string
		mutatePayload func(map[string]interface{})
	}{
		{
			name:      "test-result predicate type",
			violation: "no verified test-result",
			mutatePayload: func(statement map[string]interface{}) {
				statement["predicateType"] = "https://example.test/other/v1"
			},
		},
		{
			name:      "test-result statement type",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				statement["_type"] = "https://example.test/OtherStatement/v1"
			},
		},
		{
			name:      "single test-result subject",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				subjects := statement["subject"].([]interface{})
				statement["subject"] = append(subjects, subjects[0])
			},
		},
		{
			name:      "test-result subject name",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				subjects := statement["subject"].([]interface{})
				subjects[0].(map[string]interface{})["name"] = "other-agent"
			},
		},
		{
			name:      "test-result subject digest",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				subjects := statement["subject"].([]interface{})
				digest := subjects[0].(map[string]interface{})["digest"].(map[string]interface{})
				digest["sha256"] = strings.Repeat("f", 64)
			},
		},
		{
			name:      "single conformance descriptor",
			violation: "no verified test-result",
			mutatePayload: func(statement map[string]interface{}) {
				predicate := statement["predicate"].(map[string]interface{})
				configuration := predicate["configuration"].([]interface{})
				predicate["configuration"] = append(configuration, configuration[0])
			},
		},
		{
			name:      "conformance descriptor URI",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				descriptor(statement)["uri"] = "https://example.test/other#conformance"
			},
		},
		{
			name:      "controlled-tool descriptor digest",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				digest := descriptor(statement)["digest"].(map[string]interface{})
				digest["sha256"] = strings.Repeat("f", 64)
			},
		},
		{
			name:      "case-id pairing annotation",
			violation: "no verified test-result",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("caseId")] = "other-case"
			},
		},
		{
			name:      "agent-digest annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("agentDigest")] = "sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name:      "unexpected descriptor annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("unexpected")] = "attacker-defined"
			},
		},
		{
			name:      "correlation-id annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("correlationId")] = "sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name:      "decision-state annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("decisionState")] = "not-observed"
			},
		},
		{
			name:      "decision-verdict annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("decisionVerdict")] = "deny"
			},
		},
		{
			name:      "outcome-state annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("outcomeState")] = "unknown"
			},
		},
		{
			name:      "outcome-result annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("outcomeResult")] = "blocked"
			},
		},
		{
			name:      "decision-digest annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("decisionDigest")] = "sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name:      "result-artifact-digest annotation",
			violation: "fails cross-binding",
			mutatePayload: func(statement map[string]interface{}) {
				annotations(statement)[annotationKey("resultArtifactDigest")] = "sha256:" + strings.Repeat("f", 64)
			},
		},
	} {
		t.Run(tc.name+" remains load-bearing", func(t *testing.T) {
			deployment, testResult := mutatedTestResultStatement(t, built, tc.mutatePayload)
			result := evaluatePolicy(t, deployment, testResult)
			requireDenied(t, result)
			requireViolation(t, result, tc.violation)
		})
	}

	t.Run("descriptor annotations remain load-bearing", func(t *testing.T) {
		deployment, testResult := mutatedTestResult(t, built, func(predicate map[string]interface{}) {
			configuration := predicate["configuration"].([]interface{})
			annotations := configuration[0].(map[string]interface{})["annotations"].(map[string]interface{})
			delete(annotations, "https://autogov.dev/attestation/agent-governance-deployment/v0.1#agentDigest")
		})
		requireDenied(t, evaluatePolicy(t, deployment, testResult))
	})

	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "aggregate result", mutate: func(predicate map[string]interface{}) { predicate["result"] = "WARNED" }},
		{name: "passed test list", mutate: func(predicate map[string]interface{}) { predicate["passedTests"] = []interface{}{} }},
		{name: "warned test list", mutate: func(predicate map[string]interface{}) { predicate["warnedTests"] = []interface{}{"unexpected"} }},
		{name: "failed test list", mutate: func(predicate map[string]interface{}) { predicate["failedTests"] = []interface{}{"unexpected"} }},
	} {
		t.Run("test-result "+tc.name+" remains load-bearing", func(t *testing.T) {
			deployment, testResult := mutatedTestResult(t, built, tc.mutate)
			result := evaluatePolicy(t, deployment, testResult)
			requireDenied(t, result)
			requireViolation(t, result, "fails cross-binding")
		})
	}

	for _, url := range []interface{}{false, nil, "https:", "https:anything"} {
		name, _ := json.Marshal(url)
		t.Run("test-result URL "+string(name), func(t *testing.T) {
			deployment, testResult := mutatedTestResult(t, built, func(predicate map[string]interface{}) {
				predicate["url"] = url
			})
			requireDenied(t, evaluatePolicy(t, deployment, testResult))
		})
	}

	t.Run("byte-identical duplicate test-result stays visible", func(t *testing.T) {
		requireDenied(t, evaluatePolicy(t, built.DeploymentStatement, built.TestResultStatement, built.TestResultStatement))
	})
}

func TestAgentGovernanceGateContractDefenses(t *testing.T) {
	built := builtCase(t, "allowed-action")

	t.Run("deployment subject cardinality remains load-bearing", func(t *testing.T) {
		statement := object(t, built.DeploymentStatement)
		subjects := statement["subject"].([]interface{})
		statement["subject"] = append(subjects, subjects[0])
		result := evaluatePolicy(t, jsonBytes(t, statement), built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "exactly one subject")
	})

	t.Run("deployment subject name remains bound to predicate agent", func(t *testing.T) {
		testResultStatement := object(t, built.TestResultStatement)
		testResultSubjects := testResultStatement["subject"].([]interface{})
		testResultSubjects[0].(map[string]interface{})["name"] = "other-agent"
		testResult := jsonBytes(t, testResultStatement)

		deploymentStatement := object(t, built.DeploymentStatement)
		deploymentSubjects := deploymentStatement["subject"].([]interface{})
		deploymentSubjects[0].(map[string]interface{})["name"] = "other-agent"
		predicate := deploymentStatement["predicate"].(map[string]interface{})
		sum := sha256.Sum256(testResult)
		caseAt(t, predicate, 0)["testResult"].(map[string]interface{})["statementDigest"] = "sha256:" + hex.EncodeToString(sum[:])

		result := evaluatePolicy(t, jsonBytes(t, deploymentStatement), testResult)
		requireDenied(t, result)
		requireViolation(t, result, "subject name")
	})

	t.Run("all mandatory roots are present", func(t *testing.T) {
		for _, root := range []string{"runtime", "adapter", "identity", "audit"} {
			root := root
			t.Run(root, func(t *testing.T) {
				deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
					delete(predicate, root)
				})
				result := evaluatePolicy(t, deployment, built.TestResultStatement)
				requireDenied(t, result)
				requireViolation(t, result, "missing required core fields")
			})
		}
	})

	t.Run("valid percent-encoded artifact URI remains admissible", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			artifact := predicate["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})
			artifact["uri"] = "https://registry.example:443/runtime%20artifact"
		})
		requireAllowed(t, evaluatePolicy(t, deployment, built.TestResultStatement))
	})

	t.Run("nested core shape remains load-bearing", func(t *testing.T) {
		cases := []struct {
			name       string
			mutate     func(map[string]interface{})
			wantAbsent string
		}{
			{
				name: "empty identity",
				mutate: func(predicate map[string]interface{}) {
					predicate["identity"] = map[string]interface{}{}
				},
			},
			{
				name: "missing adapter artifact",
				mutate: func(predicate map[string]interface{}) {
					delete(predicate["adapter"].(map[string]interface{}), "artifact")
				},
			},
			{
				name: "unexpected nested claim",
				mutate: func(predicate map[string]interface{}) {
					predicate["identity"].(map[string]interface{})["compliant"] = true
				},
			},
			{
				name: "duplicate intervention points",
				mutate: func(predicate map[string]interface{}) {
					points := []interface{}{"tool.pre", "tool.pre"}
					enforcement := predicate["enforcement"].(map[string]interface{})
					enforcement["requiredInterventionPoints"] = points
					enforcement["observedInterventionPoints"] = points
				},
			},
			{
				name: "over-bound distinct intervention points",
				mutate: func(predicate map[string]interface{}) {
					points := make([]interface{}, 33)
					for i := range points {
						points[i] = fmt.Sprintf("tool.point-%02d", i)
					}
					enforcement := predicate["enforcement"].(map[string]interface{})
					enforcement["requiredInterventionPoints"] = points
					enforcement["observedInterventionPoints"] = points
				},
			},
			{
				name: "unknown identity subject kind",
				mutate: func(predicate map[string]interface{}) {
					predicate["identity"].(map[string]interface{})["subjectKind"] = "attacker-defined"
				},
			},
			{
				name: "unknown fixture producer",
				mutate: func(predicate map[string]interface{}) {
					fixture := predicate["conformance"].(map[string]interface{})["fixture"].(map[string]interface{})
					fixture["producer"] = "attacker-defined"
				},
			},
			{
				name: "hostless https agent uri",
				mutate: func(predicate map[string]interface{}) {
					predicate["agent"].(map[string]interface{})["uri"] = "https:anything"
				},
			},
			{
				name: "hostless oci identity provider uri",
				mutate: func(predicate map[string]interface{}) {
					predicate["identity"].(map[string]interface{})["providerUri"] = "oci:anything"
				},
			},
			{
				name:       "control character in runtime artifact uri",
				wantAbsent: "urn:runtime\x00injected",
				mutate: func(predicate map[string]interface{}) {
					artifact := predicate["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})
					artifact["uri"] = "urn:runtime\x00injected"
				},
			},
			{
				name:       "invalid percent escape in runtime artifact uri",
				wantAbsent: "urn:%zz",
				mutate: func(predicate map[string]interface{}) {
					artifact := predicate["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})
					artifact["uri"] = "urn:%zz"
				},
			},
			{
				name:       "malformed bracketed runtime artifact authority",
				wantAbsent: "https://[broken",
				mutate: func(predicate map[string]interface{}) {
					artifact := predicate["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})
					artifact["uri"] = "https://[broken"
				},
			},
			{
				name:       "uppercase runtime artifact scheme",
				wantAbsent: "HTTPS://registry.example/runtime",
				mutate: func(predicate map[string]interface{}) {
					artifact := predicate["runtime"].(map[string]interface{})["artifact"].(map[string]interface{})
					artifact["uri"] = "HTTPS://registry.example/runtime"
				},
			},
			{
				name:       "control character in agent name",
				wantAbsent: "agent\ninjected",
				mutate: func(predicate map[string]interface{}) {
					predicate["agent"].(map[string]interface{})["name"] = "agent\ninjected"
				},
			},
			{
				name:       "unicode control character in runtime name",
				wantAbsent: "runtime\u0085injected",
				mutate: func(predicate map[string]interface{}) {
					predicate["runtime"].(map[string]interface{})["name"] = "runtime\u0085injected"
				},
			},
			{
				name: "unknown case kind",
				mutate: func(predicate map[string]interface{}) {
					cases := predicate["conformance"].(map[string]interface{})["cases"].([]interface{})
					cases[0].(map[string]interface{})["kind"] = "attacker-defined"
				},
			},
			{
				name: "unknown decision state",
				mutate: func(predicate map[string]interface{}) {
					cases := predicate["conformance"].(map[string]interface{})["cases"].([]interface{})
					cases[0].(map[string]interface{})["decision"].(map[string]interface{})["state"] = "attacker-defined"
				},
			},
			{
				name: "unknown decision verdict",
				mutate: func(predicate map[string]interface{}) {
					cases := predicate["conformance"].(map[string]interface{})["cases"].([]interface{})
					cases[0].(map[string]interface{})["decision"].(map[string]interface{})["verdict"] = "attacker-defined"
				},
			},
			{
				name: "unknown outcome state",
				mutate: func(predicate map[string]interface{}) {
					cases := predicate["conformance"].(map[string]interface{})["cases"].([]interface{})
					cases[0].(map[string]interface{})["outcome"].(map[string]interface{})["state"] = "attacker-defined"
				},
			},
			{
				name: "unknown outcome result",
				mutate: func(predicate map[string]interface{}) {
					cases := predicate["conformance"].(map[string]interface{})["cases"].([]interface{})
					cases[0].(map[string]interface{})["outcome"].(map[string]interface{})["result"] = "attacker-defined"
				},
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				deployment := relinkDeployment(t, built, built.TestResultStatement, tc.mutate)
				result := evaluatePolicy(t, deployment, built.TestResultStatement)
				requireDenied(t, result)
				requireViolation(t, result, "nested core shape")
				if tc.wantAbsent != "" {
					for _, violation := range result.violations {
						if strings.Contains(violation, tc.wantAbsent) {
							t.Fatalf("violation echoed unvalidated evidence: %q", violation)
						}
					}
				}
			})
		}
	})

	t.Run("fixed controlled tool and digest are required", func(t *testing.T) {
		var testResult []byte
		statement := object(t, built.TestResultStatement)
		configuration := statement["predicate"].(map[string]interface{})["configuration"].([]interface{})
		configuration[0].(map[string]interface{})["digest"].(map[string]interface{})["sha256"] = strings.Repeat("f", 64)
		testResult = jsonBytes(t, statement)
		deployment := relinkDeployment(t, built, testResult, func(predicate map[string]interface{}) {
			tool := predicate["conformance"].(map[string]interface{})["controlledTool"].(map[string]interface{})
			tool["actionClass"] = "filesystem.write.anything"
			tool["artifact"].(map[string]interface{})["digest"] = "sha256:" + strings.Repeat("f", 64)
		})
		result := evaluatePolicy(t, deployment, testResult)
		requireDenied(t, result)
		requireViolation(t, result, "controlled tool")
	})

	t.Run("controlled tool digest cannot be an attacker-selected pair", func(t *testing.T) {
		statement := object(t, built.TestResultStatement)
		configuration := statement["predicate"].(map[string]interface{})["configuration"].([]interface{})
		configuration[0].(map[string]interface{})["digest"].(map[string]interface{})["sha256"] = strings.Repeat("e", 64)
		testResult := jsonBytes(t, statement)
		deployment := relinkDeployment(t, built, testResult, func(predicate map[string]interface{}) {
			tool := predicate["conformance"].(map[string]interface{})["controlledTool"].(map[string]interface{})
			tool["artifact"].(map[string]interface{})["digest"] = "sha256:" + strings.Repeat("e", 64)
		})
		result := evaluatePolicy(t, deployment, testResult)
		requireDenied(t, result)
		requireViolation(t, result, "controlled tool")
	})

	t.Run("adapter linkage and contract version are required", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			adapter := predicate["adapter"].(map[string]interface{})
			adapter["contractVersion"] = "0.2"
			adapter["runtimeDigest"] = "sha256:" + strings.Repeat("f", 64)
		})
		result := evaluatePolicy(t, deployment, built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "adapter")
	})

	t.Run("default behavior is constrained", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			predicate["enforcement"].(map[string]interface{})["defaultBehavior"] = "permit-all"
		})
		result := evaluatePolicy(t, deployment, built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "default behavior")
	})

	t.Run("monitor mode is not admitted", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			predicate["enforcement"].(map[string]interface{})["mode"] = "monitor"
		})
		requireDenied(t, evaluatePolicy(t, deployment, built.TestResultStatement))
	})

	t.Run("loaded count contradiction is attributed", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			policy := predicate["runtimePolicy"].(map[string]interface{})
			policy["count"] = float64(0)
			policy["loaded"] = true
		})
		result := evaluatePolicy(t, deployment, built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "runtime policy")
	})

	t.Run("consistent no-policy facts cannot enforce a positive case", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			policy := predicate["runtimePolicy"].(map[string]interface{})
			policy["count"] = float64(0)
			policy["loaded"] = false
		})
		result := evaluatePolicy(t, deployment, built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "loaded, enforcing, exercised control")
	})

	t.Run("case interval and observations are structural admission facts", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			c := caseAt(t, predicate, 0)
			c["completedAt"] = "2026-08-26T19:59:59Z"
			c["decision"].(map[string]interface{})["observedAt"] = "2026-08-26T20:00:00Z"
		})
		result := evaluatePolicy(t, deployment, built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "timestamps")
	})

	t.Run("required observed timestamp cannot be omitted", func(t *testing.T) {
		deployment := relinkDeployment(t, built, built.TestResultStatement, func(predicate map[string]interface{}) {
			delete(caseAt(t, predicate, 0)["decision"].(map[string]interface{}), "observedAt")
		})
		result := evaluatePolicy(t, deployment, built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "timestamps")
	})

	t.Run("invalid envelope has attribution", func(t *testing.T) {
		statement := object(t, built.DeploymentStatement)
		statement["_type"] = "unexpected"
		result := evaluatePolicy(t, jsonBytes(t, statement), built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "_type")
	})

	t.Run("empty conformance has attribution", func(t *testing.T) {
		statement := object(t, built.DeploymentStatement)
		statement["predicate"].(map[string]interface{})["conformance"].(map[string]interface{})["cases"] = []interface{}{}
		result := evaluatePolicy(t, jsonBytes(t, statement), built.TestResultStatement)
		requireDenied(t, result)
		requireViolation(t, result, "conformance cases")
	})
}

func TestAgentGovernanceGateAdmitsTwoPositiveCases(t *testing.T) {
	allowed := builtCase(t, "allowed-action")
	denied := builtCase(t, "denied-action")

	statement := object(t, allowed.DeploymentStatement)
	predicate := statement["predicate"].(map[string]interface{})
	deniedPredicate := deploymentPredicate(t, denied.DeploymentStatement)
	predicate["conformance"].(map[string]interface{})["cases"] = []interface{}{
		caseAt(t, predicate, 0),
		caseAt(t, deniedPredicate, 0),
	}

	requireAllowed(t, evaluatePolicy(t, jsonBytes(t, statement), allowed.TestResultStatement, denied.TestResultStatement))
}

// These in-test source mutants prove four security-critical positive rules are
// load-bearing. Mutants are materialized only under t.TempDir, outside the
// loadable and policy-digested directory.
func TestSecurityCriticalPolicySourceMutantsAreKilled(t *testing.T) {
	sourceBytes, err := os.ReadFile("agent_governance.rego")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	built := builtCase(t, "allowed-action")

	invalidTool := object(t, built.DeploymentStatement)
	invalidTool["predicate"].(map[string]interface{})["conformance"].(map[string]interface{})["controlledTool"].(map[string]interface{})["actionClass"] = "filesystem.write.anything"

	notExercised := object(t, built.DeploymentStatement)
	notExercised["predicate"].(map[string]interface{})["enforcement"].(map[string]interface{})["observedInterventionPoints"] = []interface{}{}

	badLinkage := object(t, built.DeploymentStatement)
	badLinkageCase := badLinkage["predicate"].(map[string]interface{})["conformance"].(map[string]interface{})["cases"].([]interface{})[0].(map[string]interface{})
	badLinkageCase["testResult"].(map[string]interface{})["statementDigest"] = "sha256:" + strings.Repeat("f", 64)

	badAnnotationDeployment, badAnnotationResult := mutatedTestResult(t, built, func(predicate map[string]interface{}) {
		configuration := predicate["configuration"].([]interface{})
		annotations := configuration[0].(map[string]interface{})["annotations"].(map[string]interface{})
		annotations["https://autogov.dev/attestation/agent-governance-deployment/v0.1#correlationId"] = "sha256:" + strings.Repeat("f", 64)
	})

	tests := []struct {
		name        string
		start       string
		next        string
		replacement string
		prepare     func(*testing.T, string) string
		statements  [][]byte
	}{
		{
			name:        "controlled_tool_valid",
			start:       "controlled_tool_valid(s) if {",
			next:        "adapter_valid(s) if {",
			replacement: "controlled_tool_valid(s) if {\n\tis_object(s)\n}",
			statements:  [][]byte{jsonBytes(t, invalidTool), built.TestResultStatement},
		},
		{
			name:        "deployment_enforcing",
			start:       "deployment_enforcing(s) if {",
			next:        "runtime_policy_consistent(s) if {",
			replacement: "deployment_enforcing(s) if {\n\tis_object(s)\n}",
			statements:  [][]byte{jsonBytes(t, notExercised), built.TestResultStatement},
		},
		{
			name:        "linkage_valid",
			start:       "linkage_valid(s, c) if {",
			next:        "tr_statement_valid(s, c, t) if {",
			replacement: "linkage_valid(s, c) if {\n\tis_object(s)\n\tis_object(c)\n}",
			prepare:     routeLinkageViolationThroughRule,
			statements:  [][]byte{jsonBytes(t, badLinkage), built.TestResultStatement},
		},
		{
			name:        "tr_annotations_valid",
			start:       "tr_annotations_valid(s, c, d) if {",
			next:        "expected_annotation_keys(c) :=",
			replacement: "tr_annotations_valid(s, c, d) if {\n\tis_object(s)\n\tis_object(c)\n\tis_object(d)\n}",
			statements:  [][]byte{badAnnotationDeployment, badAnnotationResult},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testSource := source
			if tc.prepare != nil {
				testSource = tc.prepare(t, testSource)
			}
			if result := evaluatePolicySource(t, testSource, tc.statements...); result.allow {
				t.Fatalf("checked-in %s accepted the adversarial input", tc.name)
			}
			mutant := replacePolicyRule(t, testSource, tc.start, tc.next, tc.replacement)
			mutantPath := filepath.Join(t.TempDir(), tc.name+".rego")
			if err := os.WriteFile(mutantPath, []byte(mutant), 0o600); err != nil {
				t.Fatal(err)
			}
			mutantBytes, err := os.ReadFile(mutantPath)
			if err != nil {
				t.Fatal(err)
			}
			if result := evaluatePolicySource(t, string(mutantBytes), tc.statements...); !result.allow {
				t.Fatalf("%s mutant did not change the final admission decision: %v", tc.name, result.violations)
			}
		})
	}
}

// The checked-in policy deliberately reports detailed linkage failures through
// tr_statement_valid as a defense redundant with linkage_valid. For the
// linkage mutation only, route that logically equivalent violation check
// through linkage_valid so the final allow decision proves the named rule is
// connected to admission rather than merely succeeding in isolation.
func routeLinkageViolationThroughRule(t *testing.T, source string) string {
	t.Helper()
	const original = `	trs := case_test_results(c)
	count(trs) == 1
	some t in trs
	not tr_statement_valid(s, c, t)`
	const replacement = `	count(case_test_results(c)) == 1
	not linkage_valid(s, c)`
	if strings.Count(source, original) != 1 {
		t.Fatalf("linkage violation block count = %d, want 1", strings.Count(source, original))
	}
	return strings.Replace(source, original, replacement, 1)
}

func replacePolicyRule(t *testing.T, source, start, next, replacement string) string {
	t.Helper()
	startIndex := strings.Index(source, start)
	if startIndex < 0 {
		t.Fatalf("policy rule %q not found", start)
	}
	nextOffset := strings.Index(source[startIndex:], "\n\n"+next)
	if nextOffset < 0 {
		t.Fatalf("rule following %q not found", start)
	}
	endIndex := startIndex + nextOffset
	return source[:startIndex] + replacement + source[endIndex:]
}
