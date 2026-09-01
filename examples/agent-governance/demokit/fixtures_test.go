package demokit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pred "github.com/liatrio/autogov/pkg/predicate"
)

// the committed producer evidence must stay bound to the committed fixture
// bytes: if a producer, runtime, policy, or the controlled tool changes, the
// evidence has to be regenerated (see examples/agent-governance/README.md).

func baseDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func loadEvidence(t *testing.T, producer, name string) *pred.AgentGovernanceDeployment {
	t.Helper()
	path := filepath.Join(baseDir(t), "fixtures", "evidence", producer, name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read evidence %s: %v", path, err)
	}
	evidence, err := pred.ParseAgentGovernanceEvidence(data)
	if err != nil {
		t.Fatalf("committed evidence %s no longer parses: %v", path, err)
	}
	return evidence
}

func TestCommittedEvidenceBindsCommittedFixtures(t *testing.T) {
	base := baseDir(t)
	agentDigest := fileDigest(t, filepath.Join(base, "fixtures", "agent", "agent-image.txt"))
	toolDigest := fileDigest(t, filepath.Join(base, "fixtures", "write_marker.py"))

	perProducer := map[string]struct {
		runtimeDigest string
		adapterDigest string
		policyDigest  string
	}{
		"non-agt": {
			runtimeDigest: fileDigest(t, filepath.Join(base, "adapters", "non-agt", "toy_runtime.py")),
			adapterDigest: fileDigest(t, filepath.Join(base, "adapters", "non-agt", "producer.py")),
			policyDigest:  fileDigest(t, filepath.Join(base, "adapters", "non-agt", "runtime_policy.json")),
		},
		"agt": {
			runtimeDigest: agtWheelDigest(t),
			adapterDigest: fileDigest(t, filepath.Join(base, "adapters", "agt", "producer.py")),
			policyDigest:  fileDigest(t, filepath.Join(base, "adapters", "agt", "runtime_policy.yaml")),
		},
	}

	for producer, want := range perProducer {
		for _, name := range []string{"allowed-action", "denied-action", "adapter-bypass", "no-policy-loaded", "unknown-outcome"} {
			evidence := loadEvidence(t, producer, name)

			if evidence.Agent.ArtifactDigest != agentDigest {
				t.Errorf("%s/%s: agent digest %s does not match the committed agent artifact %s", producer, name, evidence.Agent.ArtifactDigest, agentDigest)
			}
			if evidence.Conformance.ControlledTool.Artifact.Digest != toolDigest {
				t.Errorf("%s/%s: controlled tool digest does not match fixtures/write_marker.py — regenerate the evidence", producer, name)
			}
			if evidence.Runtime.Artifact.Digest != want.runtimeDigest {
				t.Errorf("%s/%s: runtime artifact digest does not match the committed runtime binding", producer, name)
			}
			if evidence.Adapter.Artifact.Digest != want.adapterDigest {
				t.Errorf("%s/%s: adapter digest does not match the committed producer script — regenerate the evidence", producer, name)
			}
			if name != "no-policy-loaded" && evidence.RuntimePolicy.Artifact.Digest != want.policyDigest {
				t.Errorf("%s/%s: runtime policy digest does not match the committed policy artifact", producer, name)
			}
			// the runtime-policy digest must never equal the Auto Gov
			// admission-policy digest semantics: it identifies the policy
			// governing the agent, bound to a producer-local artifact URI
			if evidence.RuntimePolicy.Artifact.URI == "" {
				t.Errorf("%s/%s: runtime policy artifact URI missing", producer, name)
			}
		}
	}
}

// agtWheelDigest reads the locked AGT wheel digest from pins.json.
func agtWheelDigest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(baseDir(t), "adapters", "agt", "pins.json"))
	if err != nil {
		t.Fatalf("failed to read pins.json: %v", err)
	}
	var pins struct {
		Wheel struct {
			SHA256 string `json:"sha256"`
		} `json:"wheel"`
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + pins.Wheel.SHA256
}

// BuildCase output must be deterministic: same evidence, same bytes.
func TestBuildCaseDeterministic(t *testing.T) {
	path := filepath.Join(baseDir(t), "fixtures", "evidence", "non-agt", "allowed-action.json")
	first, err := BuildCase(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCase(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.PredicateBody) != string(second.PredicateBody) {
		t.Error("predicate body generation is not deterministic")
	}
	if string(first.DeploymentStatement) != string(second.DeploymentStatement) {
		t.Error("deployment statement generation is not deterministic")
	}
	if string(first.TestResultStatement) != string(second.TestResultStatement) {
		t.Error("test-result statement generation is not deterministic")
	}
}
