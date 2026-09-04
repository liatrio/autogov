package demokit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pred "github.com/liatrio/autogov/agent-governance/internal/evidence"
)

const agtCoreWheelSHA256 = "e14a09eceaa88d3f5d572b09643138d95b1d6c349a6e23e5b222f3c0192cec1f"

// the committed producer evidence must stay bound to the committed fixture
// bytes: if a producer, runtime, policy, or the controlled tool changes, the
// evidence has to be regenerated (see agent-governance/README.md).

func baseDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", ".."))
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
			records := filepath.Join(base, "fixtures", "evidence", producer, "records")

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
			wantPolicyDigest := want.policyDigest
			if name == "no-policy-loaded" {
				wantPolicyDigest = fileDigest(t, filepath.Join(records, "no-policy.json"))
			}
			if evidence.RuntimePolicy.Artifact.Digest != wantPolicyDigest {
				t.Errorf("%s/%s: runtime policy digest does not match its committed policy record", producer, name)
			}
			// the runtime-policy digest must never equal the Auto Gov
			// admission-policy digest semantics: it identifies the policy
			// governing the agent, bound to a producer-local artifact URI
			if evidence.RuntimePolicy.Artifact.URI == "" {
				t.Errorf("%s/%s: runtime policy artifact URI missing", producer, name)
			}
			assertRecordDigest(t, producer, name, "identity", evidence.Identity.Subject.Digest, filepath.Join(records, "identity.json"))
			assertRecordDigest(t, producer, name, "audit sink", evidence.Audit.Sink.Digest, filepath.Join(records, "audit-sink.json"))
			assertRecordDigest(t, producer, name, "audit configuration", evidence.Audit.ConfigurationDigest, filepath.Join(records, "audit-config.json"))
			for _, c := range evidence.Conformance.Cases {
				if c.Decision.Reference != nil {
					assertRecordDigest(t, producer, name, "decision", c.Decision.Reference.Digest, filepath.Join(records, c.ID+"-decision.json"))
				}
				if c.Outcome.Reference != nil {
					assertRecordDigest(t, producer, name, "outcome", c.Outcome.Reference.Digest, filepath.Join(records, c.ID+"-outcome.json"))
				}
			}
		}
	}
}

func assertRecordDigest(t *testing.T, producer, name, label, got, path string) {
	t.Helper()
	if want := fileDigest(t, path); got != want {
		t.Errorf("%s/%s: %s digest %s does not match committed record %s", producer, name, label, got, path)
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
	if pins.Wheel.SHA256 != agtCoreWheelSHA256 {
		t.Fatalf("pins.json wheel sha256 = %s, want the contract-locked %s", pins.Wheel.SHA256, agtCoreWheelSHA256)
	}
	lock, err := os.ReadFile(filepath.Join(baseDir(t), "adapters", "agt", "requirements.lock.txt"))
	if err != nil {
		t.Fatalf("failed to read requirements.lock.txt: %v", err)
	}
	if !strings.Contains(string(lock), "agent-governance-toolkit-core==4.1.0 \\\n    --hash=sha256:"+agtCoreWheelSHA256) {
		t.Fatal("requirements.lock.txt does not bind the contract-locked AGT core wheel hash")
	}
	return "sha256:" + agtCoreWheelSHA256
}

func TestAGTProducerVerifiesPinnedFilesBeforeImport(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(baseDir(t), "adapters", "agt", "producer.py"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	mainStart := strings.Index(text, "def main() -> None:")
	if mainStart < 0 {
		t.Fatal("AGT producer main function is missing")
	}
	mainBody := text[mainStart:]
	verifyAt := strings.Index(mainBody, "pins, verified_files, core_module_roots = load_pins()")
	importAt := strings.Index(mainBody, "policy_document_type, policy_evaluator_type = load_agt_policy_types(")
	if verifyAt < 0 || importAt < 0 || verifyAt > importAt {
		t.Fatal("AGT policy code is imported before the pinned installation is verified")
	}
	loaderAt := strings.Index(text, "def load_agt_policy_types(")
	agtImportAt := strings.Index(text, "from agent_os.policies import PolicyDocument, PolicyEvaluator")
	if loaderAt < 0 || agtImportAt < loaderAt {
		t.Fatal("AGT policy import must remain deferred inside the post-verification loader")
	}
	if !strings.Contains(text, "with zipfile.ZipFile(wheel) as archive:") {
		t.Fatal("installed AGT files are not checked against RECORD from the verified wheel")
	}
	if strings.Contains(text, "installed.read_text(\"RECORD\")") {
		t.Fatal("AGT verification trusts the mutable installed RECORD")
	}
	if !strings.Contains(text, "sys.pycache_prefix = _IMPORT_PYCACHE.name") {
		t.Fatal("AGT import does not isolate itself from unverified installed bytecode")
	}
	if !strings.Contains(text, "VerifiedCoreFinder(verified_files, core_module_roots)") {
		t.Fatal("AGT imports are not bound to files from the verified core wheel")
	}
}

func TestAGTProducerPinnedFileVerificationIsLoadBearing(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the AGT producer provenance test")
	}

	dir := t.TempDir()
	installedSource := filepath.Join(dir, "synthetic_pkg", "__init__.py")
	installedRecord := filepath.Join(dir, "synthetic_core-1.0.dist-info", "RECORD")
	if err := os.MkdirAll(filepath.Dir(installedSource), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(installedRecord), 0700); err != nil {
		t.Fatal(err)
	}
	trusted := []byte("VALUE = 'trusted'\n")
	if err := os.WriteFile(installedSource, trusted, 0600); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(trusted)
	wheelRecord := fmt.Sprintf(
		"synthetic_pkg/__init__.py,sha256=%s,%d\nsynthetic_core-1.0.dist-info/RECORD,,\n",
		base64.RawURLEncoding.EncodeToString(sum[:]), len(trusted),
	)
	wheel := filepath.Join(dir, "synthetic_core-1.0-py3-none-any.whl")
	wheelFile, err := os.Create(wheel)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(wheelFile)
	for name, body := range map[string][]byte{
		"synthetic_pkg/__init__.py":           trusted,
		"synthetic_core-1.0.dist-info/RECORD": []byte(wheelRecord),
	} {
		entry, createErr := zw.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write(body); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wheelFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pins.json"), []byte(`{"package":"synthetic-core","version":"1.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installedRecord, []byte("attacker-controlled installed RECORD\n"), 0600); err != nil {
		t.Fatal(err)
	}

	producer := filepath.Join(baseDir(t), "adapters", "agt", "producer.py")
	check := `
import pathlib
import runpy
import sys

namespace = runpy.run_path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
wheel = pathlib.Path(sys.argv[3])

class Installed:
    version = "1.0"

    def locate_file(self, path):
        return root / path

producer_globals = namespace["load_pins"].__globals__
producer_globals["HERE"] = root
producer_globals["distribution"] = lambda package: Installed()
producer_globals["verify_core_wheel"] = lambda pins: wheel
namespace["load_pins"]()
`
	run := func() ([]byte, error) {
		cmd := exec.Command(python, "-c", check, producer, dir, wheel)
		return cmd.CombinedOutput()
	}
	if output, err := run(); err != nil {
		t.Fatalf("pristine installed source failed verified-wheel check: %v\n%s", err, output)
	}

	tampered := []byte("VALUE = 'evil!!!'\n")
	if len(tampered) != len(trusted) {
		t.Fatal("test fixture must preserve source size to exercise its hash binding")
	}
	if err := os.WriteFile(installedSource, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	tamperedSum := sha256.Sum256(tampered)
	mutableRecord := fmt.Sprintf(
		"synthetic_pkg/__init__.py,sha256=%s,%d\nsynthetic_core-1.0.dist-info/RECORD,,\n",
		base64.RawURLEncoding.EncodeToString(tamperedSum[:]), len(tampered),
	)
	if err := os.WriteFile(installedRecord, []byte(mutableRecord), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := run()
	if err == nil {
		t.Fatalf("tampered source passed after mutable installed RECORD blessed it:\n%s", output)
	}
	if !strings.Contains(string(output), "does not match verified wheel RECORD") {
		t.Fatalf("tampered source failed for the wrong reason: %v\n%s", err, output)
	}
}

func TestAGTProducerIgnoresUnverifiedInstalledBytecode(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the AGT producer bytecode test")
	}
	producer := filepath.Join(baseDir(t), "adapters", "agt", "producer.py")
	script := `
import os
import pathlib
import py_compile
import runpy
import sys

namespace = runpy.run_path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
package = root / "agent_os" / "policies"
package.mkdir(parents=True)
(package.parent / "__init__.py").write_text("", encoding="utf-8")
source = package / "__init__.py"
verified = "class PolicyDocument:\n    origin = 'source'\nclass PolicyEvaluator:\n    origin = 'source'\n"
malicious = "class PolicyDocument:\n    origin = 'pyc!!!'\nclass PolicyEvaluator:\n    origin = 'pyc!!!'\n"
assert len(verified) == len(malicious)
stamp = 1_700_000_000
source.write_text(malicious, encoding="utf-8")
os.utime(source, (stamp, stamp))
adjacent_pyc = source.parent / "__pycache__" / f"__init__.{sys.implementation.cache_tag}.pyc"
adjacent_pyc.parent.mkdir()
py_compile.compile(
    str(source),
    cfile=str(adjacent_pyc),
    doraise=True,
    invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
)
source.write_text(verified, encoding="utf-8")
os.utime(source, (stamp, stamp))
sys.path.insert(0, str(root))
verified_files = frozenset({(package.parent / "__init__.py").resolve(), source.resolve()})
policy_document, policy_evaluator = namespace["load_agt_policy_types"](
    verified_files, frozenset({"agent_os"})
)
assert policy_document.origin == "source", policy_document.origin
assert policy_evaluator.origin == "source", policy_evaluator.origin
`
	cmd := exec.Command(python, "-c", script, producer, t.TempDir())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("AGT loader executed unverified installed bytecode: %v\n%s", err, output)
	}
}

func TestAGTProducerRejectsShadowCorePackage(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the AGT producer shadow-package test")
	}
	producer := filepath.Join(baseDir(t), "adapters", "agt", "producer.py")
	script := `
import pathlib
import runpy
import sys

namespace = runpy.run_path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
trusted = root / "trusted"
shadow = root / "shadow"
marker = root / "shadow-executed"
for base in (trusted, shadow):
    (base / "agent_os" / "policies").mkdir(parents=True)
(trusted / "agent_os" / "__init__.py").write_text("", encoding="utf-8")
(trusted / "agent_os" / "policies" / "__init__.py").write_text(
    "class PolicyDocument: pass\nclass PolicyEvaluator: pass\n", encoding="utf-8"
)
(shadow / "agent_os" / "__init__.py").write_text(
    f"import pathlib\npathlib.Path({str(marker)!r}).write_text('executed')\n", encoding="utf-8"
)
(shadow / "agent_os" / "policies" / "__init__.py").write_text(
    "class PolicyDocument: pass\nclass PolicyEvaluator: pass\n", encoding="utf-8"
)
sys.path.insert(0, str(trusted))
sys.path.insert(0, str(shadow))
verified_files = frozenset({
    (trusted / "agent_os" / "__init__.py").resolve(),
    (trusted / "agent_os" / "policies" / "__init__.py").resolve(),
})
try:
    namespace["load_agt_policy_types"](verified_files, frozenset({"agent_os"}))
except ImportError:
    pass
else:
    raise AssertionError("shadow AGT package was imported")
assert not marker.exists(), "shadow AGT package executed before origin rejection"
`
	cmd := exec.Command(python, "-c", script, producer, t.TempDir())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("AGT loader did not reject a shadow core package: %v\n%s", err, output)
	}
}

func TestProducersIgnoreUnverifiedLocalFixtureBytecode(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the fixture bytecode test")
	}
	script := `
import os
import pathlib
import py_compile
import runpy
import shutil
import sys

source = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]) / "agent-governance"
files = [
    "adapters/agt/producer.py",
    "adapters/non-agt/producer.py",
    "adapters/non-agt/toy_runtime.py",
    "fixtures/write_marker.py",
]
for relative in files:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / relative, target)

def plant_timestamp_pyc(path, malicious_prefix):
    trusted = path.read_bytes()
    malicious = malicious_prefix.encode("utf-8")
    assert len(malicious) < len(trusted)
    malicious += b"#" + (b"x" * (len(trusted) - len(malicious) - 1))
    assert len(malicious) == len(trusted)
    stamp = 1_700_000_000
    path.write_bytes(malicious)
    os.utime(path, (stamp, stamp))
    pyc = path.parent / "__pycache__" / f"{path.stem}.{sys.implementation.cache_tag}.pyc"
    pyc.parent.mkdir(exist_ok=True)
    py_compile.compile(
        str(path),
        cfile=str(pyc),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )
    path.write_bytes(trusted)
    os.utime(path, (stamp, stamp))

plant_timestamp_pyc(root / "fixtures/write_marker.py", "PWNED = True\n")
plant_timestamp_pyc(
    root / "adapters/non-agt/toy_runtime.py",
    "PWNED = True\nINTERVENTION_POINT = 'evil'\nRUNTIME_NAME = 'evil'\nRUNTIME_VERSION = 'evil'\nclass ToyRuntime: pass\n",
)

non_agt = runpy.run_path(str(root / "adapters/non-agt/producer.py"))
assert not getattr(non_agt["write_marker"], "PWNED", False)
assert not getattr(non_agt["toy_runtime"], "PWNED", False)
assert pathlib.Path(non_agt["write_marker"].__file__).resolve() == (root / "fixtures/write_marker.py").resolve()
assert pathlib.Path(non_agt["toy_runtime"].__file__).resolve() == (root / "adapters/non-agt/toy_runtime.py").resolve()

agt = runpy.run_path(str(root / "adapters/agt/producer.py"))
assert not getattr(agt["write_marker"], "PWNED", False)
assert pathlib.Path(agt["write_marker"].__file__).resolve() == (root / "fixtures/write_marker.py").resolve()
`
	cmd := exec.Command(python, "-c", script, baseDir(t), t.TempDir())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("producer executed unverified local fixture bytecode: %v\n%s", err, output)
	}
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

func TestBuildCaseInputBoundIsInclusive(t *testing.T) {
	source := filepath.Join(baseDir(t), "fixtures", "evidence", "non-agt", "allowed-action.json")
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= pred.AgentGovernanceMaxPredicateBytes {
		t.Fatalf("fixture is %d bytes, cannot pad it to the evidence input boundary", len(raw))
	}
	want, err := BuildCase(source)
	if err != nil {
		t.Fatal(err)
	}

	exact := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), pred.AgentGovernanceMaxPredicateBytes-len(raw))...)
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := BuildCase(path)
	if err != nil {
		t.Fatalf("BuildCase rejected evidence at the exact %d-byte limit: %v", pred.AgentGovernanceMaxPredicateBytes, err)
	}
	if !bytes.Equal(got.PredicateBody, want.PredicateBody) ||
		!bytes.Equal(got.DeploymentStatement, want.DeploymentStatement) ||
		!bytes.Equal(got.TestResultStatement, want.TestResultStatement) {
		t.Fatal("boundary padding changed BuildCase artifact bytes")
	}

	if err := os.WriteFile(path, append(exact, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCase(path); err == nil || !strings.Contains(err.Error(), "input bound") {
		t.Fatalf("BuildCase limit-plus-one error = %v, want input-bound rejection", err)
	}
}

// producer evidence must be normalized before it derives any signed
// test-result subject or annotation. otherwise a harmless uppercase digest
// input produces a normalized deployment statement that cannot cross-bind to
// its own test-result statement.
func TestBuildCaseNormalizesBeforeBuildingTestResult(t *testing.T) {
	source := filepath.Join(baseDir(t), "fixtures", "evidence", "non-agt", "allowed-action.json")
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]interface{}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	evidence["agent"].(map[string]interface{})["artifactDigest"] = "sha256:" + strings.ToUpper(strings.Repeat("a", 64))
	caseBody := evidence["conformance"].(map[string]interface{})["cases"].([]interface{})[0].(map[string]interface{})
	caseBody["correlationId"] = "sha256:" + strings.ToUpper(strings.Repeat("b", 64))

	path := filepath.Join(t.TempDir(), "evidence.json")
	mutated, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mutated, 0600); err != nil {
		t.Fatal(err)
	}
	built, err := BuildCase(path)
	if err != nil {
		t.Fatal(err)
	}

	var testResult map[string]interface{}
	if err := json.Unmarshal(built.TestResultStatement, &testResult); err != nil {
		t.Fatal(err)
	}
	gotSubject := testResult["subject"].([]interface{})[0].(map[string]interface{})["digest"].(map[string]interface{})["sha256"].(string)
	if gotSubject != strings.Repeat("a", 64) {
		t.Errorf("test-result subject digest = %q, want normalized lowercase digest", gotSubject)
	}
	configuration := testResult["predicate"].(map[string]interface{})["configuration"].([]interface{})[0].(map[string]interface{})
	annotations := configuration["annotations"].(map[string]interface{})
	if got := annotations[pred.AgentGovernanceDeploymentPredicateTypeURI+"#correlationId"]; got != "sha256:"+strings.Repeat("b", 64) {
		t.Errorf("test-result correlation annotation = %q, want normalized lowercase digest", got)
	}
}

func TestStatementBuildersRejectIncoherentInputs(t *testing.T) {
	if _, err := BuildCase(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("BuildCase accepted a missing evidence file")
	}

	evidence := loadEvidence(t, "non-agt", "allowed-action")
	if _, err := BuildDeploymentStatement(evidence, []byte("{")); err == nil {
		t.Fatal("deployment statement accepted invalid predicate JSON")
	}
	mismatchedBody, err := json.Marshal(map[string]interface{}{
		"agent": map[string]interface{}{
			"name":           "different-agent",
			"artifactDigest": evidence.Agent.ArtifactDigest,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildDeploymentStatement(evidence, mismatchedBody); err == nil {
		t.Fatal("deployment statement accepted a mismatched subject")
	}

	baseCase := evidence.Conformance.Cases[0]
	missingDecisionReference := baseCase
	missingDecisionReference.Decision.Reference = nil
	if _, err := BuildTestResultStatement(evidence, missingDecisionReference); err == nil {
		t.Fatal("test-result accepted an observed decision without a reference")
	}
	missingOutcomeReference := baseCase
	missingOutcomeReference.Outcome.Reference = nil
	if _, err := BuildTestResultStatement(evidence, missingOutcomeReference); err == nil {
		t.Fatal("test-result accepted a verified outcome without a reference")
	}
	unsupportedOutcome := baseCase
	unsupportedOutcome.Outcome.State = "unsupported"
	if _, err := BuildTestResultStatement(evidence, unsupportedOutcome); err == nil {
		t.Fatal("test-result accepted an unsupported outcome state")
	}

	unknown := loadEvidence(t, "non-agt", "unknown-outcome")
	if _, err := BuildTestResultStatement(unknown, unknown.Conformance.Cases[0]); err != nil {
		t.Fatalf("unknown outcome did not produce its bounded WARNED test result: %v", err)
	}
}
