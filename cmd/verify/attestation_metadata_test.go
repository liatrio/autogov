package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/liatrio/autogov/pkg/vsa"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/stretchr/testify/require"
)

func TestGeneratedAttestationVSAUsesConfiguredBuildInfo(t *testing.T) {
	originalVersion, originalOPA := version, opaVersion
	t.Cleanup(func() { SetBuildInfo(originalVersion, originalOPA) })
	SetBuildInfo("v9.9.9-test", "v9.9.8-test")

	policyDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte("package governance\nallow := true\nviolations := {}\n"), 0o600))
	output := filepath.Join(policyDir, "vsa.json")
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	err := generateVSAWithOptions(context.Background(), "sha256:"+digest, []vsa.VSASubject{{
		URI: "artifact",
		Digest: map[string]string{
			"sha256": digest,
		},
	}}, nil, nil, []oci.Signature{}, true, output, "https://example.test/policy", policyDir, "", "", false)
	require.NoError(t, err)

	var statement struct {
		Predicate struct {
			Verifier struct {
				Version map[string]string `json:"version"`
			} `json:"verifier"`
		} `json:"predicate"`
	}
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &statement))
	require.Equal(t, "v9.9.9-test", statement.Predicate.Verifier.Version["autogov"])
	require.Equal(t, "v9.9.8-test", statement.Predicate.Verifier.Version["opa"])
}
