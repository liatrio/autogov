package offline

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liatrio/autogov/pkg/vsa"
)

func TestOfflineCLIEmitsVSAWithNamedAndUnnamedSubjects(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "autogov")
	const cliVersion = "v9.8.7-offline-test"
	const opaVersion = "v1.19.0-offline-test"
	build := exec.Command("go", "build", "-ldflags", "-X main.version="+cliVersion+" -X main.OpaVersion="+opaVersion, "-o", binary, "../..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build AutoGov: %v\n%s", err, output)
	}

	signer, err := newOfflineTestSigner(offlineTestIdentity, offlineTestIssuer)
	if err != nil {
		t.Fatal(err)
	}
	rootJSON, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	trustedRoot := filepath.Join(dir, "trusted-root.json")
	if err := os.WriteFile(trustedRoot, rootJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name           string
		namedSubject   bool
		wantSubjectURI string
	}{
		{name: "mixed", namedSubject: true, wantSubjectURI: "artifact"},
		{name: "unnamed-only", wantSubjectURI: "sha256:" + digest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caseDir := t.TempDir()
			var signedStatements [][]byte
			wantInputDigests := make(map[string]bool)
			for i, predicateType := range []string{"https://slsa.dev/provenance/v1", "https://example.test/scan/v1"} {
				subject := map[string]any{"digest": map[string]string{"sha256": digest}}
				if i == 0 && tc.namedSubject {
					subject["name"] = "artifact"
				}
				statement, err := json.Marshal(map[string]any{
					"_type":         inTotoStatementType,
					"subject":       []any{subject},
					"predicateType": predicateType,
					"predicate":     map[string]any{},
				})
				if err != nil {
					t.Fatal(err)
				}
				signed, err := signer.SignStatement(statement)
				if err != nil {
					t.Fatal(err)
				}
				signedStatements = append(signedStatements, signed)
				wantInputDigests[sha256Hex(statement)] = true
			}
			attestationsPath := filepath.Join(caseDir, "attestations.jsonl")
			writeBundleLines(t, attestationsPath, signedStatements...)

			policyDir := filepath.Join(caseDir, "policy")
			if err := os.Mkdir(policyDir, 0o750); err != nil {
				t.Fatal(err)
			}
			// Both statements must reach policy evaluation. Silently dropping the
			// unnamed scan cannot restore successful VSA generation in this test.
			const policy = `package governance
import rego.v1
default allow := false
allow if {
    count(input) == 2
    types := {statement.predicateType |
        some b in input
        statement := json.unmarshal(base64.decode(b.dsseEnvelope.payload))
    }
    types == {"https://slsa.dev/provenance/v1", "https://example.test/scan/v1"}
}
`
			if err := os.WriteFile(filepath.Join(policyDir, "admission.rego"), []byte(policy), 0o600); err != nil {
				t.Fatal(err)
			}

			vsaPath := filepath.Join(caseDir, "vsa.json")
			command := exec.Command(binary, "offline",
				"--attestations", attestationsPath,
				"--trusted-root", trustedRoot,
				"--cert-identity", offlineTestIdentity,
				"--cert-issuer", offlineTestIssuer,
				"--image-digest", "sha256:"+digest,
				"--generate-vsa", "--vsa-output", vsaPath,
				"--policy-uri", "https://example.test/policy",
				"--policy-bundle-path", policyDir,
				"--fail-on-policy-error", "--quiet",
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("offline command rejected valid named/unnamed subjects: %v\n%s", err, output)
			}
			vsaJSON, err := os.ReadFile(vsaPath)
			if err != nil {
				t.Fatalf("offline command did not write the VSA: %v", err)
			}
			var summary vsa.VSA
			if err := json.Unmarshal(vsaJSON, &summary); err != nil {
				t.Fatal(err)
			}
			versions := summary.Predicate.Verifier.Version
			if versions["autogov"] != cliVersion || versions["opa"] != opaVersion {
				t.Errorf("VSA verifier versions = %v, want autogov=%q opa=%q", versions, cliVersion, opaVersion)
			}
			if summary.Predicate.VerificationResult != "PASSED" {
				t.Errorf("verification result = %q, want PASSED", summary.Predicate.VerificationResult)
			}
			if len(summary.Subject) != 1 || summary.Subject[0].URI != tc.wantSubjectURI || summary.Subject[0].Digest["sha256"] != digest {
				t.Errorf("VSA subject = %+v, want URI %q with bare SHA-256 digest %q", summary.Subject, tc.wantSubjectURI, digest)
			}
			if len(summary.Predicate.InputAttestations) != len(wantInputDigests) {
				t.Fatalf("input attestations = %d, want %d", len(summary.Predicate.InputAttestations), len(wantInputDigests))
			}
			for _, input := range summary.Predicate.InputAttestations {
				got := input.Digest["sha256"]
				if !wantInputDigests[got] || input.URI != "urn:attestation:sha256:"+got {
					t.Errorf("unexpected or duplicate input attestation: %+v", input)
				}
				delete(wantInputDigests, got)
			}
			if len(wantInputDigests) != 0 {
				t.Errorf("VSA omitted signed statement payloads: %v", wantInputDigests)
			}
		})
	}
}
