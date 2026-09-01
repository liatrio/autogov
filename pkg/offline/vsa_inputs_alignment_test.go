package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/liatrio/autogov/examples/agent-governance/demokit"
)

// buildVSAInputs pairs result.Attestations[i] with bundles[i] by index. This
// probes whether the real verification paths can hand it two slices whose
// indices do not correspond.

func alignmentSignedStatement(t *testing.T, signer *demokit.Signer, name, digestHex, predicateType string) (statement, signed []byte) {
	t.Helper()
	statement, err := json.Marshal(demokit.Statement{
		Type:          demokit.InTotoStatementType,
		Subject:       []demokit.Subject{{Name: name, Digest: map[string]string{"sha256": digestHex}}},
		PredicateType: predicateType,
		Predicate:     json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err = signer.SignStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	return statement, signed
}

func writeFileDigest(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// TestBuildVSAInputsAlignmentMultiFileDirectory drives the real multi-file
// directory verification path (no hand-built VerificationResult) and checks
// that every emitted inputAttestations descriptor is self-consistent: the
// bundle whose payload digest it carries must be the bundle whose predicate
// type it names.
func TestBuildVSAInputsAlignmentMultiFileDirectory(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	if err := os.Mkdir(artifacts, 0o750); err != nil {
		t.Fatal(err)
	}
	// os.ReadDir sorts entries, so the files are iterated a.txt then b.txt
	digestA := writeFileDigest(t, filepath.Join(artifacts, "a.txt"), "alpha")
	digestB := writeFileDigest(t, filepath.Join(artifacts, "b.txt"), "beta")

	const typeA = "https://example.test/attestation/type-a/v1"
	const typeB = "https://example.test/attestation/type-b/v1"
	stmtA, signedA := alignmentSignedStatement(t, signer, "a.txt", digestA, typeA)
	stmtB, signedB := alignmentSignedStatement(t, signer, "b.txt", digestB, typeB)

	// load the bundles in the OPPOSITE order to the directory's file order, so
	// the per-file attestation results and the loaded bundle slice diverge
	attestations := filepath.Join(dir, "attestations.jsonl")
	writeBundleLines(t, attestations, signedB, signedA)

	trustedRoot := filepath.Join(dir, "trusted-root.json")
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRoot, rootJSON, 0600); err != nil {
		t.Fatal(err)
	}

	ov, err := NewOfflineVerifier(trustedRoot, VerifyOptions{
		CertIdentity:       agDemoIdentity,
		CertOIDCIssuer:     agDemoIssuer,
		Quiet:              true,
		AcceptedIdentities: []string{agDemoIdentity},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ov.LoadBundlesFromFile(attestations); err != nil {
		t.Fatal(err)
	}

	result, err := ov.VerifyArtifact(artifacts)
	if err != nil {
		t.Fatalf("directory verification errored: %v", err)
	}
	if !result.Verified {
		t.Fatalf("directory verification did not succeed: %v", result.Errors)
	}
	if len(result.Attestations) != 2 {
		t.Fatalf("expected 2 attestation results, got %d", len(result.Attestations))
	}

	typeByPayloadDigest := map[string]string{
		sha256Hex(stmtA): typeA,
		sha256Hex(stmtB): typeB,
	}

	_, _, _, inputAttestations := buildVSAInputs(result, ov.Bundles())
	if len(inputAttestations) == 0 {
		t.Fatal("no inputAttestations were produced")
	}
	for _, ia := range inputAttestations {
		got := ia.Digest["sha256"]
		wantType, known := typeByPayloadDigest[got]
		if !known {
			t.Errorf("inputAttestation digest %s matches no signed statement payload", got)
			continue
		}
		if ia.URI != wantType {
			t.Errorf("inputAttestation binds predicate type %s to the payload digest of %s — the descriptor pairs one statement's type with another statement's bytes", ia.URI, wantType)
		}
	}
}

// TestResolveFilesToProcessExpandsDirectory records the control that keeps the
// multi-file directory path off the command's VSA seam: the offline command
// expands a directory into individual files and verifies each one separately,
// so VerifyArtifact never receives the directory itself.
func TestResolveFilesToProcessExpandsDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFileDigest(t, filepath.Join(dir, "a.txt"), "alpha")
	writeFileDigest(t, filepath.Join(dir, "b.txt"), "beta")

	_, filesToProcess, err := resolveFilesToProcess(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(filesToProcess) != 2 {
		t.Fatalf("expected the directory to expand into 2 individual files, got %v", filesToProcess)
	}
	for _, f := range filesToProcess {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if info.IsDir() {
			t.Errorf("%s is a directory; the command would reach verifyDirectoryMultiFile", f)
		}
	}
}
