// Command demo runs the agent-governance evidence spike end to end against a
// built autogov binary: it completes and signs each producer's committed
// four-case evidence (plus the unknown-outcome negative) with the local
// demonstration CA, then enforces every signed pair through the real
// `autogov offline` verification -> local opt-in OPA policy -> unsigned VSA
// JSON path and checks the expected PASSED, PASSED, FAILED, FAILED sequence
// and enforcing exit codes per producer.
//
// the generated VSA JSON statements are UNSIGNED; signing or re-verifying the
// VSA itself is outside this spike.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/liatrio/autogov/examples/agent-governance/demokit"
)

const (
	demoIdentity = "agent-governance-demo@autogov.local"
	demoIssuer   = "https://demo.autogov.local/oidc"
	policyURI    = "https://github.com/liatrio/autogov/examples/agent-governance/policy"
)

type caseSpec struct {
	name       string
	wantResult string
	wantExit0  bool
	mandatory  bool
}

var cases = []caseSpec{
	{"allowed-action", "PASSED", true, true},
	{"denied-action", "PASSED", true, true},
	{"adapter-bypass", "FAILED", false, true},
	{"no-policy-loaded", "FAILED", false, true},
	{"unknown-outcome", "FAILED", false, false}, // negative fixture, not one of the four
}

func main() {
	autogovPath := flag.String("autogov", filepath.Join("bin", "autogov"), "path to the built autogov binary")
	examplesDir := flag.String("examples", filepath.Join("examples", "agent-governance"), "path to examples/agent-governance")
	workdir := flag.String("workdir", "", "working directory for signed bundles and VSA output (default: a temp dir; supplied directory is retained)")
	keep := flag.Bool("keep", false, "keep an automatically created temporary working directory")
	flag.Parse()

	if err := run(*autogovPath, *examplesDir, *workdir, *keep); err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}
}

func run(autogovPath, examplesDir, workdir string, keep bool) error {
	if _, err := os.Stat(autogovPath); err != nil {
		return fmt.Errorf("autogov binary not found at %s (run `task build` first): %w", autogovPath, err)
	}
	absExamples, err := filepath.Abs(examplesDir)
	if err != nil {
		return err
	}

	workdir, cleanup, err := prepareWorkdir(workdir, keep)
	if err != nil {
		return err
	}
	defer cleanup()
	fmt.Printf("working directory: %s\n", workdir)

	signer, err := demokit.NewSigner(demoIdentity, demoIssuer)
	if err != nil {
		return fmt.Errorf("failed to create demo signer: %w", err)
	}
	trustedRootPath := filepath.Join(workdir, "trusted-root.json")
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		return err
	}
	if err := os.WriteFile(trustedRootPath, rootJSON, 0600); err != nil {
		return err
	}

	fmt.Println("\nproducer   case               expected  vsa       exit  ok")
	fmt.Println("---------  -----------------  --------  --------  ----  --")

	failures := 0
	for _, producer := range []string{"non-agt", "agt"} {
		for _, tc := range cases {
			ok, err := runCase(autogovPath, absExamples, workdir, trustedRootPath, signer, producer, tc)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", producer, tc.name, err)
			}
			if !ok {
				failures++
			}
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d case(s) did not match the expected admission result", failures)
	}
	fmt.Println("\nall cases matched: PASSED, PASSED, FAILED, FAILED per producer (plus the failing unknown-outcome negative)")
	fmt.Println("note: the VSA JSON statements written above are unsigned; VSA signing is outside this spike")
	return nil
}

// prepareWorkdir owns cleanup only for the temporary directory it creates.
// a caller-supplied path is created when necessary and always remains the
// caller's responsibility, regardless of -keep.
func prepareWorkdir(workdir string, keep bool) (string, func(), error) {
	if workdir != "" {
		if err := os.MkdirAll(workdir, 0o750); err != nil {
			return "", nil, fmt.Errorf("create working directory %s: %w", workdir, err)
		}
		return workdir, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "autogov-agentgov-demo-")
	if err != nil {
		return "", nil, err
	}
	if keep {
		return dir, func() {}, nil
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

func runCase(autogovPath, examplesDir, workdir, trustedRootPath string, signer *demokit.Signer, producer string, tc caseSpec) (bool, error) {
	evidencePath := filepath.Join(examplesDir, "fixtures", "evidence", producer, tc.name+".json")
	built, err := demokit.BuildCase(evidencePath)
	if err != nil {
		return false, err
	}

	// exercise the real CLI predicate command on the completed evidence and
	// require byte-identical deterministic output
	completedEvidence, err := json.Marshal(built.Evidence)
	if err != nil {
		return false, err
	}
	completedPath := filepath.Join(workdir, producer+"-"+tc.name+"-evidence.json")
	if err := os.WriteFile(completedPath, completedEvidence, 0600); err != nil {
		return false, err
	}
	cliBody := filepath.Join(workdir, producer+"-"+tc.name+"-predicate.json")
	cmd := exec.Command(autogovPath, "predicate", "agent-governance-deployment",
		"--evidence-path", completedPath, "--output", cliBody)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("predicate command failed: %v\n%s", err, out)
	}
	cliBytes, err := os.ReadFile(cliBody)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(cliBytes, built.PredicateBody) {
		return false, fmt.Errorf("CLI predicate output differs from the deterministic expected body")
	}

	// sign the deployment and test-result statements separately
	deployment, err := signer.SignStatement(built.DeploymentStatement)
	if err != nil {
		return false, err
	}
	testResult, err := signer.SignStatement(built.TestResultStatement)
	if err != nil {
		return false, err
	}
	attestationsPath := filepath.Join(workdir, producer+"-"+tc.name+".jsonl")
	lines := append(append([]byte{}, deployment...), '\n')
	lines = append(lines, testResult...)
	lines = append(lines, '\n')
	if err := os.WriteFile(attestationsPath, lines, 0600); err != nil {
		return false, err
	}

	// enforce through the real offline verification -> OPA -> VSA path
	vsaPath := filepath.Join(workdir, producer+"-"+tc.name+"-vsa.json")
	offline := exec.Command(autogovPath, "offline",
		"--attestations", attestationsPath,
		"--trusted-root", trustedRootPath,
		"--cert-identity", demoIdentity,
		"--cert-issuer", demoIssuer,
		"--image-digest", "sha256:"+built.AgentDigestHex,
		"--generate-vsa",
		"--vsa-output", vsaPath,
		"--policy-uri", policyURI,
		"--policy-bundle-path", filepath.Join(examplesDir, "policy"),
		"--fail-on-policy-error",
		"--quiet",
	)
	output, runErr := offline.CombinedOutput()
	exitCode := offline.ProcessState.ExitCode()
	if runErr != nil && exitCode < 0 {
		return false, fmt.Errorf("offline command did not run: %v\n%s", runErr, output)
	}

	result, err := readVSAResult(vsaPath)
	if err != nil {
		return false, fmt.Errorf("no VSA result (exit %d): %w\n%s", exitCode, err, output)
	}

	ok := result == tc.wantResult && (exitCode == 0) == tc.wantExit0
	marker := "ok"
	if !ok {
		marker = "MISMATCH"
	}
	label := tc.name
	if !tc.mandatory {
		label += "*"
	}
	fmt.Printf("%-9s  %-17s  %-8s  %-8s  %4d  %s\n", producer, label, tc.wantResult, result, exitCode, marker)
	return ok, nil
}

func readVSAResult(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var v struct {
		Predicate struct {
			VerificationResult string `json:"verificationResult"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return "", err
	}
	return v.Predicate.VerificationResult, nil
}
