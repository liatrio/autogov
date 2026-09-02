package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liatrio/autogov/examples/agent-governance/demokit"
	"github.com/sigstore/sigstore-go/pkg/bundle"
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
// that every emitted inputAttestations descriptor is self-consistent: its
// resource URI and digest must identify the same verified statement bytes.
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

	knownPayloadDigests := map[string]struct{}{
		sha256Hex(stmtA): {},
		sha256Hex(stmtB): {},
	}

	_, _, _, inputAttestations, err := buildVSAInputs(result, ov.Bundles())
	if err != nil {
		t.Fatalf("build VSA inputs: %v", err)
	}
	if len(inputAttestations) == 0 {
		t.Fatal("no inputAttestations were produced")
	}
	for _, ia := range inputAttestations {
		got := ia.Digest["sha256"]
		_, known := knownPayloadDigests[got]
		if !known {
			t.Errorf("inputAttestation digest %s matches no signed statement payload", got)
			continue
		}
		wantURI := "urn:attestation:sha256:" + got
		if ia.URI != wantURI {
			t.Errorf("inputAttestation URI %s does not identify its payload digest %s", ia.URI, got)
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

func TestBundleInputDescriptorUsesStatementResourceURN(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}

	const predicateType = "https://example.test/attestation/type-a/v1"
	statement, signed := alignmentSignedStatement(t, signer, "artifact", strings.Repeat("a", 64), predicateType)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, signed, 0600); err != nil {
		t.Fatal(err)
	}
	bundles, err := LoadBundles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 {
		t.Fatalf("loaded bundles = %d, want 1", len(bundles))
	}

	descriptor, ok := bundleInputDescriptor(bundles[0])
	if !ok {
		t.Fatal("input descriptor was not built")
	}
	wantDigest := sha256Hex(statement)
	if descriptor.Digest["sha256"] != wantDigest {
		t.Errorf("descriptor digest = %q, want %q", descriptor.Digest["sha256"], wantDigest)
	}
	wantURI := "urn:attestation:sha256:" + wantDigest
	if descriptor.URI != wantURI {
		t.Errorf("descriptor URI = %q, want resource URI %q (not predicate type %q)", descriptor.URI, wantURI, predicateType)
	}
}

func TestBundleInputDescriptorRejectsIncompletePayloads(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}

	loadBundle := func(t *testing.T, signed []byte) *bundle.Bundle {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(path, signed, 0600); err != nil {
			t.Fatal(err)
		}
		bundles, err := LoadBundles(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(bundles) != 1 {
			t.Fatalf("loaded bundles = %d, want 1", len(bundles))
		}
		return bundles[0]
	}

	validBundle := func(t *testing.T) *bundle.Bundle {
		t.Helper()
		_, signed := alignmentSignedStatement(t, signer, "artifact", strings.Repeat("c", 64), "https://example.test/attestation/type-a/v1")
		return loadBundle(t, signed)
	}

	missingPredicateType, err := json.Marshal(map[string]interface{}{
		"_type":     demokit.InTotoStatementType,
		"subject":   []demokit.Subject{{Name: "artifact", Digest: map[string]string{"sha256": strings.Repeat("c", 64)}}},
		"predicate": map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	missingPredicateTypeSigned, err := signer.SignStatement(missingPredicateType)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		bundle func(*testing.T) *bundle.Bundle
	}{
		{
			name: "nil bundle",
			bundle: func(*testing.T) *bundle.Bundle {
				return nil
			},
		},
		{
			name: "empty bundle",
			bundle: func(*testing.T) *bundle.Bundle {
				return &bundle.Bundle{}
			},
		},
		{
			name: "empty payload",
			bundle: func(t *testing.T) *bundle.Bundle {
				b := validBundle(t)
				b.GetDsseEnvelope().Payload = nil
				return b
			},
		},
		{
			name: "corrupt payload",
			bundle: func(t *testing.T) *bundle.Bundle {
				b := validBundle(t)
				b.GetDsseEnvelope().Payload = []byte("{")
				return b
			},
		},
		{
			name: "missing predicate type",
			bundle: func(t *testing.T) *bundle.Bundle {
				return loadBundle(t, missingPredicateTypeSigned)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, ok := bundleInputDescriptor(tc.bundle(t))
			if ok {
				t.Fatalf("incomplete bundle produced descriptor %+v", descriptor)
			}
		})
	}
}

func TestBuildVSAInputsRejectsVerifiedRowsWithoutDescriptors(t *testing.T) {
	signer, err := demokit.NewSigner(agDemoIdentity, agDemoIssuer)
	if err != nil {
		t.Fatal(err)
	}
	_, signed := alignmentSignedStatement(t, signer, "artifact", strings.Repeat("b", 64), "https://example.test/attestation/type-a/v1")
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, signed, 0600); err != nil {
		t.Fatal(err)
	}
	bundles, err := LoadBundles(path)
	if err != nil {
		t.Fatal(err)
	}
	// buildVSAInputs consumes verified results. this deliberately malformed
	// payload models an incoherent result/bundle handoff; it must not produce a
	// type or OPA input that lacks the matching VSA resource descriptor.
	bundles[0].GetDsseEnvelope().Payload = []byte("not JSON")
	result := &VerificationResult{Attestations: []AttestationResult{{
		Type:     "https://example.test/attestation/type-a/v1",
		Subject:  &Subject{Name: "artifact", Digest: map[string]string{"sha256": strings.Repeat("b", 64)}},
		Verified: true,
	}}}

	types, subjects, opaBundles, descriptors, err := buildVSAInputs(result, bundles)
	if err == nil {
		t.Fatal("verified attestation without a descriptor was silently dropped")
	}
	if len(types) != 0 || len(subjects) != 0 || len(opaBundles) != 0 || len(descriptors) != 0 {
		t.Errorf("failed VSA input construction returned partial facts: types=%d subjects=%d OPA bundles=%d descriptors=%d", len(types), len(subjects), len(opaBundles), len(descriptors))
	}
}

func TestBuildVSAInputsRejectsNilBundleWithoutPanic(t *testing.T) {
	result := &VerificationResult{Attestations: []AttestationResult{{
		Type:     "https://example.test/attestation/type-a/v1",
		Subject:  &Subject{Name: "artifact", Digest: map[string]string{"sha256": strings.Repeat("b", 64)}},
		Verified: true,
	}}}

	for _, tc := range []struct {
		name   string
		bundle *bundle.Bundle
	}{
		{name: "nil", bundle: nil},
		{name: "empty", bundle: &bundle.Bundle{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			types, subjects, opaBundles, descriptors, err := buildVSAInputs(result, []*bundle.Bundle{tc.bundle})
			if err == nil {
				t.Fatal("verified attestation with an unusable bundle was accepted")
			}
			if len(types) != 0 || len(subjects) != 0 || len(opaBundles) != 0 || len(descriptors) != 0 {
				t.Errorf("failed VSA input construction returned partial facts: types=%d subjects=%d OPA bundles=%d descriptors=%d", len(types), len(subjects), len(opaBundles), len(descriptors))
			}
		})
	}
}
