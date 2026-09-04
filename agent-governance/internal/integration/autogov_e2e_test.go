package integration

import (
	"context"
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

	"github.com/liatrio/autogov/agent-governance/internal/demokit"
	pred "github.com/liatrio/autogov/agent-governance/internal/evidence"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/sigstore/sigstore-go/pkg/bundle"
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
	agDemoIdentity       = "agent-governance-demo@autogov.local"
	agDemoIssuer         = "https://demo.autogov.local/oidc"
	agVSAStatementType   = "https://in-toto.io/Statement/v1"
	agVSAPredicateType   = "https://slsa.dev/verification_summary/v1"
	agAdmissionPolicyURI = "https://github.com/liatrio/autogov/agent-governance/policy"
	agAdmissionPolicySHA = "35ba8fe7713f95c77800f086f3e0af2b7034446770375a52a84debffed2963b6"
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

var autogovBinary string

type vsaDocument struct {
	Type          string               `json:"_type"`
	PredicateType string               `json:"predicateType"`
	Subject       []resourceDescriptor `json:"subject"`
	Predicate     struct {
		InputAttestations  []resourceDescriptor `json:"inputAttestations"`
		Policy             resourceDescriptor   `json:"policy"`
		VerificationResult string               `json:"verificationResult"`
	} `json:"predicate"`
	Metadata map[string]interface{} `json:"metadata"`
}

type resourceDescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

func TestMain(m *testing.M) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve repository root:", err)
		os.Exit(1)
	}
	buildDir, err := os.MkdirTemp("", "agent-governance-integration-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create integration build directory:", err)
		os.Exit(1)
	}
	autogovBinary = filepath.Join(buildDir, "autogov")
	build := exec.Command("go", "build", "-o", autogovBinary, ".")
	build.Dir = repoRoot
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build AutoGov for black-box tests: %v\n%s", buildErr, output)
		if removeErr := os.RemoveAll(buildDir); removeErr != nil {
			fmt.Fprintln(os.Stderr, "remove integration build directory after build failure:", removeErr)
		}
		os.Exit(1)
	}
	code := m.Run()
	if removeErr := os.RemoveAll(buildDir); removeErr != nil && code == 0 {
		fmt.Fprintln(os.Stderr, "remove integration build directory:", removeErr)
		code = 1
	}
	os.Exit(code)
}

func agCompanionDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func agEvidencePath(t *testing.T, producer, name string) string {
	return filepath.Join(agCompanionDir(t), "fixtures", "evidence", producer, name+".json")
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

// a trusted signer may issue a hand-built deployment predicate. the offline
// gate must still reject contract gaps even though signature verification
// succeeds and the paired test-result remains byte-for-byte linked.
func signModifiedDeployment(t *testing.T, signer *demokit.Signer, built *demokit.BuiltCase, mutate func(map[string]interface{})) (deployment, testResult []byte) {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(built.PredicateBody, &body); err != nil {
		t.Fatalf("parse predicate body: %v", err)
	}
	mutate(body)
	tamperedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal modified predicate body: %v", err)
	}
	statement, err := json.Marshal(demokit.Statement{
		Type:          demokit.InTotoStatementType,
		Subject:       []demokit.Subject{{Name: built.AgentName, Digest: map[string]string{"sha256": built.AgentDigestHex}}},
		PredicateType: pred.AgentGovernanceDeploymentPredicateTypeURI,
		Predicate:     tamperedBody,
	})
	if err != nil {
		t.Fatalf("marshal modified deployment statement: %v", err)
	}
	deployment, err = signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("sign modified deployment statement: %v", err)
	}
	testResult, err = signer.SignStatement(built.TestResultStatement)
	if err != nil {
		t.Fatalf("sign linked test-result statement: %v", err)
	}
	return deployment, testResult
}

// runAgentGovernanceOffline drives the real offline command path with the
// local opt-in policy bundle and enforcing exit behavior.
func runAgentGovernanceOffline(t *testing.T, attestationsPath, trustedRootPath, imageDigest, vsaOutput string) error {
	t.Helper()
	cmd := exec.Command(autogovBinary, "offline",
		"--attestations", attestationsPath,
		"--trusted-root", trustedRootPath,
		"--cert-identity", agDemoIdentity,
		"--cert-issuer", agDemoIssuer,
		"--image-digest", imageDigest,
		"--vsa-output", vsaOutput,
		"--policy-uri", agAdmissionPolicyURI,
		"--policy-bundle-path", filepath.Join(agCompanionDir(t), "policy"),
		"--generate-vsa",
		"--fail-on-policy-error",
		"--quiet",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("autogov offline: %w\n%s", err, output)
	}
	return nil
}

func readVSA(t *testing.T, path string) *vsaDocument {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected VSA JSON at %s: %v", path, err)
	}
	var v vsaDocument
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("VSA JSON did not parse: %v", err)
	}
	if v.Type != agVSAStatementType {
		t.Errorf("VSA _type = %q, want %q", v.Type, agVSAStatementType)
	}
	if v.PredicateType != agVSAPredicateType {
		t.Errorf("VSA predicateType = %q, want %q", v.PredicateType, agVSAPredicateType)
	}
	if v.Predicate.Policy.URI != agAdmissionPolicyURI {
		t.Errorf("VSA policy URI = %q, want relocated policy URI %q", v.Predicate.Policy.URI, agAdmissionPolicyURI)
	}
	if got := v.Predicate.Policy.Digest["sha256"]; got != agAdmissionPolicySHA {
		t.Errorf("VSA policy SHA-256 = %q, want preserved digest %q", got, agAdmissionPolicySHA)
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
					assertVSABindings(t, v, built, deployment, testResult)
				} else {
					// the enforcing command exits non-zero AFTER writing the
					// failed VSA JSON
					if runErr == nil {
						t.Error("enforcing command succeeded for a non-admissible case")
					}
					assertViolationsPresent(t, v)
					wantViolation := map[string]string{
						"adapter-bypass":   "consequential write-marker action",
						"no-policy-loaded": "no runtime policy loaded",
					}[tc.name]
					if wantViolation != "" && !violationsContain(t, v, wantViolation) {
						t.Errorf("failed %s row lacks its kind-specific violation %q", tc.name, wantViolation)
					}
				}
			})
		}
		if want := []string{"PASSED", "PASSED", "FAILED", "FAILED"}; fmt.Sprint(results) != fmt.Sprint(want) {
			t.Errorf("%s producer VSA sequence = %v, want %v", producer, results, want)
		}
	}
}

func TestAgentGovernanceSignedStatementWithoutPredicateTypeWritesNoVSA(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}
	built, err := demokit.BuildCase(agEvidencePath(t, "non-agt", "allowed-action"))
	if err != nil {
		t.Fatal(err)
	}

	statement, err := json.Marshal(map[string]interface{}{
		"_type":     demokit.InTotoStatementType,
		"subject":   []demokit.Subject{{Name: built.AgentName, Digest: map[string]string{"sha256": built.AgentDigestHex}}},
		"predicate": json.RawMessage(built.PredicateBody),
	})
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	testResult, err := signer.SignStatement(built.TestResultStatement)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	attestations := filepath.Join(dir, "attestations.jsonl")
	writeBundleLines(t, attestations, deployment, testResult)
	trustedRoot := filepath.Join(dir, "trusted-root.json")
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRoot, rootJSON, 0600); err != nil {
		t.Fatal(err)
	}

	vsaOut := filepath.Join(dir, "vsa.json")
	runErr := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut)
	if runErr == nil {
		t.Fatal("cryptographically valid statement without predicateType produced a VSA")
	}
	if !strings.Contains(runErr.Error(), "failed to build coherent VSA inputs") {
		t.Fatalf("offline error = %v, want coherent VSA input failure", runErr)
	}
	if _, statErr := os.Stat(vsaOut); !os.IsNotExist(statErr) {
		t.Fatalf("VSA output exists after input-construction failure: %v", statErr)
	}
}

// the schema permits one to four cases per deployment. exercise two positive
// cases through signed bundles and the full offline seam so the Rego every-case
// loop and per-case descriptor pairing cannot become single-case-only by
// accident.
func TestAgentGovernanceTwoPositiveCasesAdmission(t *testing.T) {
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

	allowed, err := demokit.BuildCase(agEvidencePath(t, "non-agt", "allowed-action"))
	if err != nil {
		t.Fatal(err)
	}
	denied, err := demokit.BuildCase(agEvidencePath(t, "non-agt", "denied-action"))
	if err != nil {
		t.Fatal(err)
	}
	combined := *allowed.Evidence
	combined.Conformance.Cases = append(
		[]pred.AgentGovernanceCase{},
		allowed.Evidence.Conformance.Cases[0],
		denied.Evidence.Conformance.Cases[0],
	)
	body, err := combined.Generate()
	if err != nil {
		t.Fatalf("generate two-case predicate: %v", err)
	}
	statement, err := demokit.BuildDeploymentStatement(&combined, body)
	if err != nil {
		t.Fatalf("build two-case deployment statement: %v", err)
	}
	deployment, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("sign two-case deployment: %v", err)
	}
	allowedTestResult, err := signer.SignStatement(allowed.TestResultStatement)
	if err != nil {
		t.Fatalf("sign allowed test-result: %v", err)
	}
	deniedTestResult, err := signer.SignStatement(denied.TestResultStatement)
	if err != nil {
		t.Fatalf("sign denied test-result: %v", err)
	}

	attestations := filepath.Join(dir, "two-positive-cases.jsonl")
	writeBundleLines(t, attestations, deployment, allowedTestResult, deniedTestResult)
	vsaOut := filepath.Join(dir, "two-positive-cases-vsa.json")
	if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+allowed.AgentDigestHex, vsaOut); err != nil {
		t.Fatalf("two positive signed cases were not admitted: %v", err)
	}
	if got := readVSA(t, vsaOut).Predicate.VerificationResult; got != "PASSED" {
		t.Errorf("two-case VSA = %s, want PASSED", got)
	}
}

// assertVSABindings checks that a PASSED VSA binds the signed subject and the
// exact payload digests extracted from the actual verified DSSE bundles. it
// compares the signed deployment body's cross-link with the separate signed
// test-result payload instead of comparing a builder value with the expression
// that created it.
func assertVSABindings(t *testing.T, v *vsaDocument, built *demokit.BuiltCase, deploymentBundle, testResultBundle []byte) {
	t.Helper()
	deploymentStatement := signedBundlePayload(t, deploymentBundle)
	testResultStatement := signedBundlePayload(t, testResultBundle)

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
		pred.AgentGovernanceDeploymentPredicateTypeURI: sha256Hex(deploymentStatement),
		pred.TestResultPredicateTypeURI:                sha256Hex(testResultStatement),
	}
	for predicateType, want := range wantDigests {
		found := false
		for _, ia := range v.Predicate.InputAttestations {
			if ia.URI == "urn:attestation:sha256:"+want && ia.Digest["sha256"] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("VSA inputAttestations do not bind %s statement resource digest %s (got %+v)", predicateType, want, v.Predicate.InputAttestations)
		}
	}

	var deployment struct {
		Predicate struct {
			Conformance struct {
				Cases []struct {
					TestResult struct {
						StatementDigest string `json:"statementDigest"`
					} `json:"testResult"`
				} `json:"cases"`
			} `json:"conformance"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(deploymentStatement, &deployment); err != nil {
		t.Fatalf("signed deployment statement did not parse: %v", err)
	}
	if len(deployment.Predicate.Conformance.Cases) != 1 {
		t.Fatalf("signed deployment has %d cases, want one", len(deployment.Predicate.Conformance.Cases))
	}
	wantLink := "sha256:" + sha256Hex(testResultStatement)
	if got := deployment.Predicate.Conformance.Cases[0].TestResult.StatementDigest; got != wantLink {
		t.Errorf("signed deployment case statementDigest %s does not match separate signed test-result digest %s", got, wantLink)
	}
}

func signedBundlePayload(t *testing.T, signed []byte) []byte {
	t.Helper()
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(signed); err != nil {
		t.Fatalf("signed bundle did not parse: %v", err)
	}
	envelope, err := b.Envelope()
	if err != nil {
		t.Fatalf("signed bundle has no DSSE envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("signed bundle payload did not decode: %v", err)
	}
	return payload
}

// signedLinkageValid evaluates the local gate's linkage rule over payloads
// extracted from the actual signed bundles. it keeps the portability matrix
// tied to the same signed evidence bytes later admitted through offline.
func signedLinkageValid(t *testing.T, deploymentBundle, testResultBundle []byte) bool {
	t.Helper()
	policyPath := filepath.Join(agCompanionDir(t), "policy", "agent_governance.rego")
	module, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read agent-governance policy: %v", err)
	}
	input := []interface{}{
		map[string]interface{}{
			"dsseEnvelope": map[string]interface{}{
				"payload":     base64.StdEncoding.EncodeToString(signedBundlePayload(t, deploymentBundle)),
				"payloadType": "application/vnd.in-toto+json",
			},
		},
		map[string]interface{}{
			"dsseEnvelope": map[string]interface{}{
				"payload":     base64.StdEncoding.EncodeToString(signedBundlePayload(t, testResultBundle)),
				"payloadType": "application/vnd.in-toto+json",
			},
		},
	}
	results, err := rego.New(
		rego.Query(`
			deployment := data.governance.deployment_statements[0]
			selected_case := deployment.predicate.conformance.cases[0]
			data.governance.linkage_valid(deployment, selected_case)
		`),
		rego.Module("agent_governance.rego", string(module)),
		rego.Input(input),
	).Eval(context.Background())
	if err != nil {
		t.Fatalf("evaluate signed linkage: %v", err)
	}
	return len(results) == 1
}

func assertViolationsPresent(t *testing.T, v *vsaDocument) {
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

	// a valid Sigstore signature alone is not an admission decision. exercise
	// the contract rules with hand-built, separately signed predicate bodies so
	// future changes cannot turn these load-bearing checks into dead policy.
	t.Run("signed hand-built contract gaps", func(t *testing.T) {
		cases := []struct {
			name      string
			violation string
			mutate    func(map[string]interface{})
		}{
			{
				name:      "controlled action class",
				violation: "controlled tool",
				mutate: func(body map[string]interface{}) {
					tool := body["conformance"].(map[string]interface{})["controlledTool"].(map[string]interface{})
					tool["actionClass"] = "filesystem.write.anything"
				},
			},
			{
				name:      "adapter runtime binding",
				violation: "adapter contract version or runtime digest linkage",
				mutate: func(body map[string]interface{}) {
					body["adapter"].(map[string]interface{})["runtimeDigest"] = "sha256:" + strings.Repeat("f", 64)
				},
			},
			{
				name:      "required identity root",
				violation: "missing required core fields",
				mutate: func(body map[string]interface{}) {
					delete(body, "identity")
				},
			},
			{
				name:      "sparse identity object",
				violation: "nested core shape",
				mutate: func(body map[string]interface{}) {
					body["identity"] = map[string]interface{}{}
				},
			},
			{
				name:      "invalid default behavior",
				violation: "default behavior",
				mutate: func(body map[string]interface{}) {
					body["enforcement"].(map[string]interface{})["defaultBehavior"] = "permit-all"
				},
			},
			{
				name:      "inverted timestamps",
				violation: "case timestamps",
				mutate: func(body map[string]interface{}) {
					cases := body["conformance"].(map[string]interface{})["cases"].([]interface{})
					cases[0].(map[string]interface{})["completedAt"] = "2026-08-26T19:59:59Z"
				},
			},
			{
				name:      "unexpected aggregate root",
				violation: "unexpected predicate field",
				mutate: func(body map[string]interface{}) {
					body["compliant"] = true
				},
			},
			{
				name:      "duplicate case id and kind",
				violation: "duplicate conformance case ids",
				mutate: func(body map[string]interface{}) {
					conformance := body["conformance"].(map[string]interface{})
					cases := conformance["cases"].([]interface{})
					conformance["cases"] = append(cases, cases[0])
				},
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				deployment, testResult := signModifiedDeployment(t, signer, built, tc.mutate)
				attestations := filepath.Join(dir, "hand-built-"+strings.ReplaceAll(tc.name, " ", "-")+".jsonl")
				writeBundleLines(t, attestations, deployment, testResult)
				vsaOut := filepath.Join(dir, "hand-built-"+strings.ReplaceAll(tc.name, " ", "-")+"-vsa.json")

				if err := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut); err == nil {
					t.Error("hand-built contract gap was admitted")
				}
				v := readVSA(t, vsaOut)
				if v.Predicate.VerificationResult != "FAILED" {
					t.Errorf("VSA = %s, want FAILED", v.Predicate.VerificationResult)
				}
				if !violationsContain(t, v, tc.violation) {
					t.Errorf("expected signed hand-built violation containing %q", tc.violation)
				}
			})
		}
	})
}

func violationsContain(t *testing.T, v *vsaDocument, substring string) bool {
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
		TestResultLinkageValid            bool
		AdmissionResult                   string
	}

	project := func(e *pred.AgentGovernanceDeployment, linkageValid bool, admissionResult string) projection {
		c := e.Conformance.Cases[0]
		return projection{
			ToolName:               e.Conformance.ControlledTool.Name,
			ActionClass:            e.Conformance.ControlledTool.ActionClass,
			ToolDigest:             e.Conformance.ControlledTool.Artifact.Digest,
			Kind:                   c.Kind,
			Mode:                   e.Enforcement.Mode,
			DefaultBehavior:        e.Enforcement.DefaultBehavior,
			Required:               e.Enforcement.RequiredInterventionPoints,
			Observed:               e.Enforcement.ObservedInterventionPoints,
			Loaded:                 e.RuntimePolicy.Loaded,
			CountZero:              e.RuntimePolicy.Count == 0,
			DecisionState:          c.Decision.State,
			DecisionVerdict:        c.Decision.Verdict,
			OutcomeState:           c.Outcome.State,
			OutcomeResult:          c.Outcome.Result,
			TestResultLinkageValid: linkageValid,
			AdmissionResult:        admissionResult,
		}
	}

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

	admissionProjection := func(t *testing.T, producer, caseName string, built *demokit.BuiltCase) (bool, string) {
		t.Helper()
		deployment, testResult := signBuiltCase(t, signer, built)
		linkageValid := signedLinkageValid(t, deployment, testResult)
		if !linkageValid {
			t.Fatal("the local gate could not link the signed deployment and test-result payloads")
		}

		attestations := filepath.Join(dir, producer+"-"+caseName+"-portability.jsonl")
		writeBundleLines(t, attestations, deployment, testResult)
		vsaOut := filepath.Join(dir, producer+"-"+caseName+"-portability-vsa.json")
		runErr := runAgentGovernanceOffline(t, attestations, trustedRoot, "sha256:"+built.AgentDigestHex, vsaOut)
		v := readVSA(t, vsaOut)
		if (v.Predicate.VerificationResult == "PASSED") != (runErr == nil) {
			t.Errorf("offline exit and VSA result disagree: result=%s error=%v", v.Predicate.VerificationResult, runErr)
		}
		return linkageValid, v.Predicate.VerificationResult
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

			leftLinkage, leftAdmission := admissionProjection(t, "non-agt", tc.name, nonAGT)
			rightLinkage, rightAdmission := admissionProjection(t, "agt", tc.name, agt)
			left := project(nonAGT.Evidence, leftLinkage, leftAdmission)
			right := project(agt.Evidence, rightLinkage, rightAdmission)
			if fmt.Sprintf("%+v", left) != fmt.Sprintf("%+v", right) {
				t.Errorf("portability projection mismatch:\nnon-agt: %+v\nagt:     %+v", left, right)
			}
			if left.AdmissionResult != tc.wantResult {
				t.Errorf("portability admission result = %s, want %s", left.AdmissionResult, tc.wantResult)
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
