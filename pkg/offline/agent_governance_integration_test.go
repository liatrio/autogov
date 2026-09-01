package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liatrio/autogov/examples/agent-governance/demokit"
	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/liatrio/autogov/pkg/vsa"
	"github.com/spf13/viper"
)

// integration proof for the agent-governance evidence spike: separately
// signed deployment and standard test-result statements traverse the EXISTING
// offline seam (signed bundle -> Sigstore verification -> OPA -> unsigned VSA
// JSON) and produce the expected admission results, with the enforcing
// command failing non-zero AFTER writing the failed VSA JSON.
//
// this test drove the only production seam change of the spike: binding each
// verified statement's exact payload digest into the VSA inputAttestations
// (without it the generated VSA binds no runtime-policy/adapter/decision/
// outcome evidence digests at all).

const (
	agDemoIdentity = "agent-governance-demo@autogov.local"
	agDemoIssuer   = "https://demo.autogov.local/oidc"
)

var agCaseFiles = []struct {
	name       string
	wantResult string
}{
	{"allowed-action", "PASSED"},
	{"denied-action", "PASSED"},
	{"adapter-bypass", "FAILED"},
	{"no-policy-loaded", "FAILED"},
}

func agExamplesDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "examples", "agent-governance"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func agEvidencePath(t *testing.T, producer, name string) string {
	return filepath.Join(agExamplesDir(t), "fixtures", "evidence", producer, name+".json")
}

// writeBundleLines writes signed bundles as a JSONL attestations file.
func writeBundleLines(t *testing.T, path string, bundles ...[]byte) {
	t.Helper()
	var sb strings.Builder
	for _, b := range bundles {
		sb.Write(b)
		sb.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

// signBuiltCase signs the deployment and test-result statements separately.
func signBuiltCase(t *testing.T, signer *demokit.Signer, built *demokit.BuiltCase) (deployment, testResult []byte) {
	t.Helper()
	deployment, err := signer.SignStatement(built.DeploymentStatement)
	if err != nil {
		t.Fatalf("failed to sign deployment statement: %v", err)
	}
	testResult, err = signer.SignStatement(built.TestResultStatement)
	if err != nil {
		t.Fatalf("failed to sign test-result statement: %v", err)
	}
	return deployment, testResult
}

// runAgentGovernanceOffline drives the real offline command path with the
// local opt-in policy bundle and enforcing exit behavior.
func runAgentGovernanceOffline(t *testing.T, attestationsPath, trustedRootPath, imageDigest, vsaOutput string) error {
	t.Helper()
	// reset cross-run viper state used by the offline->VSA seam
	viper.Set("offline-attestations", nil)

	cmd := createTestCmd()
	for flag, value := range map[string]string{
		"attestations":         attestationsPath,
		"trusted-root":         trustedRootPath,
		"cert-identity":        agDemoIdentity,
		"cert-issuer":          agDemoIssuer,
		"image-digest":         imageDigest,
		"vsa-output":           vsaOutput,
		"policy-uri":           "https://github.com/liatrio/autogov/examples/agent-governance/policy",
		"policy-bundle-path":   filepath.Join(agExamplesDir(t), "policy"),
		"generate-vsa":         "true",
		"fail-on-policy-error": "true",
		"quiet":                "true",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("failed to set flag %s: %v", flag, err)
		}
	}
	return RunCommand(cmd, []string{})
}

func readVSA(t *testing.T, path string) *vsa.VSA {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected VSA JSON at %s: %v", path, err)
	}
	var v vsa.VSA
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("VSA JSON did not parse: %v", err)
	}
	return &v
}

func TestAgentGovernanceFourCaseAdmission(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatalf("failed to create demo signer: %v", err)
	}
	dir := t.TempDir()
	trustedRoot := filepath.Join(dir, "trusted-root.json")
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatalf("failed to export trusted root: %v", err)
	}
	if err := os.WriteFile(trustedRoot, rootJSON, 0600); err != nil {
		t.Fatal(err)
	}

	for _, producer := range []string{"non-agt", "agt"} {
		var results []string
		for _, tc := range agCaseFiles {
			t.Run(producer+"/"+tc.name, func(t *testing.T) {
				built, err := demokit.BuildCase(agEvidencePath(t, producer, tc.name))
				if err != nil {
					t.Fatalf("failed to build case: %v", err)
				}
				deployment, testResult := signBuiltCase(t, signer, built)

				attestations := filepath.Join(dir, producer+"-"+tc.name+".jsonl")
				writeBundleLines(t, attestations, deployment, testResult)
				vsaOut := filepath.Join(dir, producer+"-"+tc.name+"-vsa.json")

				runErr := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut)
				v := readVSA(t, vsaOut)
				results = append(results, v.Predicate.VerificationResult)

				if v.Predicate.VerificationResult != tc.wantResult {
					t.Errorf("VSA result = %s, want %s", v.Predicate.VerificationResult, tc.wantResult)
				}
				if tc.wantResult == "PASSED" {
					if runErr != nil {
						t.Errorf("enforcing command failed for an admissible case: %v", runErr)
					}
					assertVSABindings(t, v, built)
				} else {
					// the enforcing command exits non-zero AFTER writing the
					// failed VSA JSON
					if runErr == nil {
						t.Error("enforcing command succeeded for a non-admissible case")
					}
					assertViolationsPresent(t, v)
				}
			})
		}
		if want := []string{"PASSED", "PASSED", "FAILED", "FAILED"}; fmt.Sprint(results) != fmt.Sprint(want) {
			t.Errorf("%s producer VSA sequence = %v, want %v", producer, results, want)
		}
	}
}

// assertVSABindings checks that a PASSED VSA binds the signed subject and the
// exact payload digests of both verified input statements (which transitively
// bind the runtime policy, adapter, decision, and outcome digests inside the
// deployment statement).
func assertVSABindings(t *testing.T, v *vsa.VSA, built *demokit.BuiltCase) {
	t.Helper()

	foundSubject := false
	for _, s := range v.Subject {
		if s.Digest["sha256"] == built.AgentDigestHex {
			foundSubject = true
		}
	}
	if !foundSubject {
		t.Errorf("VSA subjects %v do not bind the signed agent digest %s", v.Subject, built.AgentDigestHex)
	}

	wantDigests := map[string]string{
		pred.AgentGovernanceDeploymentPredicateTypeURI: sha256Hex(built.DeploymentStatement),
		pred.TestResultPredicateTypeURI:                sha256Hex(built.TestResultStatement),
	}
	for uri, want := range wantDigests {
		found := false
		for _, ia := range v.Predicate.InputAttestations {
			if ia.URI == uri && ia.Digest["sha256"] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("VSA inputAttestations do not bind statement %s digest %s (got %+v)", uri, want, v.Predicate.InputAttestations)
		}
	}

	// the test-result statement digest in the VSA equals the deployment
	// predicate's cross-bound case.testResult.statementDigest
	wantLink := "sha256:" + sha256Hex(built.TestResultStatement)
	if got := built.Evidence.Conformance.Cases[0].TestResult.StatementDigest; got != wantLink {
		t.Errorf("case statementDigest %s does not match signed statement digest %s", got, wantLink)
	}
}

func assertViolationsPresent(t *testing.T, v *vsa.VSA) {
	t.Helper()
	eval, ok := v.Metadata["autogov.policy.evaluation"].(map[string]interface{})
	if !ok {
		t.Error("failed VSA carries no policy evaluation metadata")
		return
	}
	violations, ok := eval["violations"].([]interface{})
	if !ok || len(violations) == 0 {
		t.Errorf("failed VSA carries no violations: %v", eval["violations"])
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// the outcome-unknown negative fixture must fail admission for both
// producers: an unknown outcome is never promoted to verified.
func TestAgentGovernanceUnknownOutcomeFailsClosed(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trustedRoot := filepath.Join(dir, "trusted-root.json")
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRoot, rootJSON, 0600); err != nil {
		t.Fatal(err)
	}

	for _, producer := range []string{"non-agt", "agt"} {
		built, err := demokit.BuildCase(agEvidencePath(t, producer, "unknown-outcome"))
		if err != nil {
			t.Fatalf("failed to build unknown-outcome case: %v", err)
		}
		deployment, testResult := signBuiltCase(t, signer, built)
		attestations := filepath.Join(dir, producer+"-unknown.jsonl")
		writeBundleLines(t, attestations, deployment, testResult)
		vsaOut := filepath.Join(dir, producer+"-unknown-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
			t.Errorf("%s: unknown outcome was admitted", producer)
		}
		v := readVSA(t, vsaOut)
		if v.Predicate.VerificationResult != "FAILED" {
			t.Errorf("%s: unknown-outcome VSA = %s, want FAILED", producer, v.Predicate.VerificationResult)
		}
	}
}

// adversarial admission tests: subject substitution, linkage mismatch, and
// duplicate pairing must all fail closed.
func TestAgentGovernanceAdversarialEvidenceFailsClosed(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trustedRoot := filepath.Join(dir, "trusted-root.json")
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRoot, rootJSON, 0600); err != nil {
		t.Fatal(err)
	}

	built, err := demokit.BuildCase(agEvidencePath(t, "non-agt", "allowed-action"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("predicate agent digest differs from signed subject", func(t *testing.T) {
		// tamper the predicate body's agent digest while the signed subject
		// still matches the verified artifact: admission must fail with a
		// subject-attributed violation
		tampered := strings.Replace(
			string(built.PredicateBody),
			built.AgentDigestHex,
			strings.Repeat("d", 64),
			1, // only the first occurrence: predicate agent.artifactDigest
		)
		stmt, err := json.Marshal(demokit.Statement{
			Type:          demokit.InTotoStatementType,
			Subject:       []demokit.Subject{{Name: built.AgentName, Digest: map[string]string{"sha256": built.AgentDigestHex}}},
			PredicateType: pred.AgentGovernanceDeploymentPredicateTypeURI,
			Predicate:     json.RawMessage(tampered),
		})
		if err != nil {
			t.Fatal(err)
		}
		deployment, errSign := signer.SignStatement(stmt)
		if errSign != nil {
			t.Fatal(errSign)
		}
		testResult, errSign := signer.SignStatement(built.TestResultStatement)
		if errSign != nil {
			t.Fatal(errSign)
		}

		attestations := filepath.Join(dir, "subject-substitution.jsonl")
		writeBundleLines(t, attestations, deployment, testResult)
		vsaOut := filepath.Join(dir, "subject-substitution-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
			t.Error("subject substitution was admitted")
		}
		v := readVSA(t, vsaOut)
		if v.Predicate.VerificationResult != "FAILED" {
			t.Errorf("VSA = %s, want FAILED", v.Predicate.VerificationResult)
		}
		if !violationsContain(t, v, "does not match the predicate agent digest") {
			t.Error("expected a subject-attributed digest-mismatch violation")
		}
	})

	t.Run("signed subject differs from verified artifact digest", func(t *testing.T) {
		// the signed statements verify only against their own subject; binding
		// them to a different artifact digest fails Sigstore verification and
		// no VSA is produced at all
		deployment, testResult := signBuiltCase(t, signer, built)
		attestations := filepath.Join(dir, "wrong-artifact.jsonl")
		writeBundleLines(t, attestations, deployment, testResult)
		vsaOut := filepath.Join(dir, "wrong-artifact-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+strings.Repeat("e", 64), vsaOut); err == nil {
			t.Error("verification succeeded for a non-matching artifact digest")
		}
		if _, err := os.Stat(vsaOut); !os.IsNotExist(err) {
			t.Error("no VSA should be written when verification itself fails")
		}
	})

	t.Run("missing test-result pair", func(t *testing.T) {
		deployment, _ := signBuiltCase(t, signer, built)
		attestations := filepath.Join(dir, "missing-pair.jsonl")
		writeBundleLines(t, attestations, deployment)
		vsaOut := filepath.Join(dir, "missing-pair-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
			t.Error("missing test-result pair was admitted")
		}
		v := readVSA(t, vsaOut)
		if !violationsContain(t, v, "no verified test-result statement") {
			t.Error("expected a missing-pair violation")
		}
	})

	t.Run("duplicate test-result pair", func(t *testing.T) {
		deployment, testResult := signBuiltCase(t, signer, built)

		// a second, byte-different statement claiming the same case id
		var stmt map[string]interface{}
		if err := json.Unmarshal(built.TestResultStatement, &stmt); err != nil {
			t.Fatal(err)
		}
		stmt["predicate"].(map[string]interface{})["url"] = "https://example.com/duplicate"
		dupBytes, err := json.Marshal(stmt)
		if err != nil {
			t.Fatal(err)
		}
		duplicate, err := signer.SignStatement(dupBytes)
		if err != nil {
			t.Fatal(err)
		}

		attestations := filepath.Join(dir, "duplicate-pair.jsonl")
		writeBundleLines(t, attestations, deployment, testResult, duplicate)
		vsaOut := filepath.Join(dir, "duplicate-pair-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
			t.Error("duplicate test-result pairing was admitted")
		}
		v := readVSA(t, vsaOut)
		if !violationsContain(t, v, "multiple test-result statements") {
			t.Error("expected a duplicate-pair violation")
		}
	})

	t.Run("linkage digest mismatch", func(t *testing.T) {
		// pair the deployment with a test-result statement whose bytes differ
		// from the digest bound inside the predicate
		var stmt map[string]interface{}
		if err := json.Unmarshal(built.TestResultStatement, &stmt); err != nil {
			t.Fatal(err)
		}
		stmt["predicate"].(map[string]interface{})["url"] = "https://example.com/tampered"
		tamperedBytes, err := json.Marshal(stmt)
		if err != nil {
			t.Fatal(err)
		}

		deployment, _ := signBuiltCase(t, signer, built)
		tampered, err := signer.SignStatement(tamperedBytes)
		if err != nil {
			t.Fatal(err)
		}

		attestations := filepath.Join(dir, "linkage-mismatch.jsonl")
		writeBundleLines(t, attestations, deployment, tampered)
		vsaOut := filepath.Join(dir, "linkage-mismatch-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
			t.Error("linkage digest mismatch was admitted")
		}
		v := readVSA(t, vsaOut)
		if !violationsContain(t, v, "fails cross-binding") {
			t.Error("expected a cross-binding violation")
		}
	})

	t.Run("no required intervention points", func(t *testing.T) {
		// a rego `every` over an empty collection is vacuously true, so a
		// signed predicate declaring zero required points must not be able to
		// satisfy the enforcing check. the embedded schema's minItems bound
		// constrains the generator, not this gate, which evaluates statements
		// it did not produce.
		var body map[string]interface{}
		if err := json.Unmarshal(built.PredicateBody, &body); err != nil {
			t.Fatal(err)
		}
		enforcement, ok := body["enforcement"].(map[string]interface{})
		if !ok {
			t.Fatal("predicate body carries no enforcement object")
		}
		enforcement["requiredInterventionPoints"] = []string{}
		enforcement["observedInterventionPoints"] = []string{}
		tamperedBody, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}

		stmt, err := json.Marshal(demokit.Statement{
			Type:          demokit.InTotoStatementType,
			Subject:       []demokit.Subject{{Name: built.AgentName, Digest: map[string]string{"sha256": built.AgentDigestHex}}},
			PredicateType: pred.AgentGovernanceDeploymentPredicateTypeURI,
			Predicate:     json.RawMessage(tamperedBody),
		})
		if err != nil {
			t.Fatal(err)
		}
		deployment, err := signer.SignStatement(stmt)
		if err != nil {
			t.Fatal(err)
		}
		testResult, err := signer.SignStatement(built.TestResultStatement)
		if err != nil {
			t.Fatal(err)
		}

		attestations := filepath.Join(dir, "no-required-points.jsonl")
		writeBundleLines(t, attestations, deployment, testResult)
		vsaOut := filepath.Join(dir, "no-required-points-vsa.json")

		if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
			t.Error("a deployment declaring no required intervention points was admitted")
		}
		v := readVSA(t, vsaOut)
		if v.Predicate.VerificationResult != "FAILED" {
			t.Errorf("VSA = %s, want FAILED", v.Predicate.VerificationResult)
		}
		if !violationsContain(t, v, "loaded, enforcing, exercised control") {
			t.Error("expected an enforcement-facts violation")
		}
	})
}

func violationsContain(t *testing.T, v *vsa.VSA, substring string) bool {
	t.Helper()
	eval, ok := v.Metadata["autogov.policy.evaluation"].(map[string]interface{})
	if !ok {
		return false
	}
	violations, ok := eval["violations"].([]interface{})
	if !ok {
		return false
	}
	for _, raw := range violations {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if msg, ok := m["message"].(string); ok && strings.Contains(msg, substring) {
			return true
		}
	}
	return false
}

// runtime portability: both producers must project the same policy-semantic
// tuple per case kind while their producer-specific identities and evidence
// digests stay distinct and individually bound.
func TestAgentGovernanceRuntimePortabilityProjection(t *testing.T) {
	type projection struct {
		ToolName, ActionClass, ToolDigest string
		Kind, Mode, DefaultBehavior       string
		Required, Observed                []string
		Loaded                            bool
		CountZero                         bool
		DecisionState, DecisionVerdict    string
		OutcomeState, OutcomeResult       string
	}

	project := func(e *pred.AgentGovernanceDeployment) projection {
		c := e.Conformance.Cases[0]
		return projection{
			ToolName:        e.Conformance.ControlledTool.Name,
			ActionClass:     e.Conformance.ControlledTool.ActionClass,
			ToolDigest:      e.Conformance.ControlledTool.Artifact.Digest,
			Kind:            c.Kind,
			Mode:            e.Enforcement.Mode,
			DefaultBehavior: e.Enforcement.DefaultBehavior,
			Required:        e.Enforcement.RequiredInterventionPoints,
			Observed:        e.Enforcement.ObservedInterventionPoints,
			Loaded:          e.RuntimePolicy.Loaded,
			CountZero:       e.RuntimePolicy.Count == 0,
			DecisionState:   c.Decision.State,
			DecisionVerdict: c.Decision.Verdict,
			OutcomeState:    c.Outcome.State,
			OutcomeResult:   c.Outcome.Result,
		}
	}

	for _, tc := range agCaseFiles {
		t.Run(tc.name, func(t *testing.T) {
			nonAGT, err := demokit.BuildCase(agEvidencePath(t, "non-agt", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			agt, err := demokit.BuildCase(agEvidencePath(t, "agt", tc.name))
			if err != nil {
				t.Fatal(err)
			}

			left, right := project(nonAGT.Evidence), project(agt.Evidence)
			if fmt.Sprintf("%+v", left) != fmt.Sprintf("%+v", right) {
				t.Errorf("portability projection mismatch:\nnon-agt: %+v\nagt:     %+v", left, right)
			}

			// producer-specific identities and evidence digests stay distinct
			ne, ae := nonAGT.Evidence, agt.Evidence
			if ne.Runtime.Artifact.Digest == ae.Runtime.Artifact.Digest {
				t.Error("runtime artifact digests must differ between producers")
			}
			if ne.Adapter.Artifact.Digest == ae.Adapter.Artifact.Digest {
				t.Error("adapter artifact digests must differ between producers")
			}
			if ne.RuntimePolicy.Artifact.Digest == ae.RuntimePolicy.Artifact.Digest {
				t.Error("runtime policy digests must differ between producers")
			}
			if ne.Conformance.Cases[0].CorrelationID == ae.Conformance.Cases[0].CorrelationID {
				t.Error("correlation ids must differ between producers")
			}
			if ne.Conformance.Fixture.ID == ae.Conformance.Fixture.ID {
				t.Error("fixture ids must differ between producers")
			}
			// while the shared bindings agree: same agent artifact and the
			// same fixed controlled-tool fixture
			if ne.Agent.ArtifactDigest != ae.Agent.ArtifactDigest {
				t.Error("agent artifact digests must match (same signed subject)")
			}
			if ne.Conformance.ControlledTool.Artifact.Digest != ae.Conformance.ControlledTool.Artifact.Digest {
				t.Error("controlled tool digests must match (same fixture implementation)")
			}
		})
	}
}
