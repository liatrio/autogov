package predicate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// minimal valid evidence document mirroring the schema contract example.
const agentGovernanceTestEvidence = `{
  "schemaVersion": "0.1",
  "agent": {
    "name": "agent-image",
    "uri": "urn:example:agent:write-marker",
    "artifactDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "runtime": {
    "name": "example-runtime",
    "version": "1.2.3",
    "artifact": {
      "uri": "urn:example:runtime:1.2.3",
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  },
  "adapter": {
    "name": "non-agt-fixture",
    "artifact": {
      "uri": "urn:example:adapter:non-agt",
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    },
    "contractVersion": "0.1",
    "runtimeDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  },
  "runtimePolicy": {
    "engine": "opa",
    "artifact": {
      "uri": "urn:example:runtime-policy:fixture",
      "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    },
    "count": 1,
    "loaded": true
  },
  "enforcement": {
    "mode": "enforce",
    "defaultBehavior": "deny",
    "requiredInterventionPoints": ["tool.pre"],
    "observedInterventionPoints": ["tool.pre"]
  },
  "identity": {
    "providerUri": "urn:example:identity-provider",
    "subjectKind": "workload",
    "subject": {
      "id": "redacted:fixture-workload",
      "digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    }
  },
  "audit": {
    "sinkKind": "file",
    "sink": {
      "id": "redacted:fixture-audit-sink",
      "digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    },
    "configurationDigest": "sha256:6666666666666666666666666666666666666666666666666666666666666666"
  },
  "conformance": {
    "fixture": {"id": "non-agt-allowed-001", "producer": "non-agt"},
    "controlledTool": {
      "name": "write-marker",
      "actionClass": "filesystem.write.marker",
      "artifact": {
        "uri": "urn:autogov:fixture:write-marker",
        "digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777"
      }
    },
    "cases": [{
      "id": "allowed-action-001",
      "kind": "allowed-action",
      "correlationId": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
      "startedAt": "2026-08-26T20:00:00Z",
      "completedAt": "2026-08-26T20:00:01Z",
      "decision": {
        "state": "observed",
        "verdict": "allow",
        "reference": {
          "id": "redacted:decision-001",
          "digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999"
        },
        "observedAt": "2026-08-26T20:00:00Z"
      },
      "outcome": {
        "state": "verified",
        "result": "occurred",
        "reference": {
          "id": "redacted:outcome-001",
          "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "observedAt": "2026-08-26T20:00:01Z"
      },
      "testResult": {
        "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
        "testId": "allowed-action-001",
        "statementDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      }
    }]
  }
}`

func runAgentGovernanceCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := agentGovernanceDeploymentCmd
	// reset flag state between runs
	agentGovernanceEvidencePath = ""
	agentGovernanceOutput = ""
	if err := cmd.Flags().Parse(args); err != nil {
		return err
	}
	return cmd.RunE(cmd, nil)
}

func TestAgentGovernanceDeploymentCommand(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	outputPath := filepath.Join(dir, "predicate.json")

	if err := os.WriteFile(evidencePath, []byte(agentGovernanceTestEvidence), 0600); err != nil {
		t.Fatal(err)
	}

	if err := runAgentGovernanceCmd(t, "--evidence-path", evidencePath, "--output", outputPath); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected output file: %v", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(content, &body); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	// the command emits only the predicate body
	if _, exists := body["predicateType"]; exists {
		t.Error("output must not contain envelope fields")
	}
	if body["schemaVersion"] != "0.1" {
		t.Errorf("schemaVersion = %v, want 0.1", body["schemaVersion"])
	}
}

func TestAgentGovernanceDeploymentCommandFailsClosed(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	outputPath := filepath.Join(dir, "predicate.json")

	// duplicate case id via a second identical case
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(agentGovernanceTestEvidence), &m); err != nil {
		t.Fatal(err)
	}
	conformance := m["conformance"].(map[string]interface{})
	cases := conformance["cases"].([]interface{})
	conformance["cases"] = append(cases, cases[0])
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	if err := runAgentGovernanceCmd(t, "--evidence-path", evidencePath, "--output", outputPath); err == nil {
		t.Fatal("expected the command to fail for duplicate case ids")
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Errorf("expected no partial output file, stat err = %v", err)
	}

	// missing evidence file
	if err := runAgentGovernanceCmd(t, "--evidence-path", filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected the command to fail for a missing evidence file")
	}
}
