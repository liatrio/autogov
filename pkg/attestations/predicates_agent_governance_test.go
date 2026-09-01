package attestations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// the agent-governance deployment predicate URI is locked; registry metadata
// and the docs page must stay in lockstep with the constant.
func TestAgentGovernanceDeploymentRegistryLockstep(t *testing.T) {
	const wantURI = "https://autogov.dev/attestation/agent-governance-deployment/v0.1"

	if PredicateTypeAutogovAgentGovernanceDeployment != wantURI {
		t.Fatalf("PredicateTypeAutogovAgentGovernanceDeployment = %q, want %q",
			PredicateTypeAutogovAgentGovernanceDeployment, wantURI)
	}

	info, exists := LookupPredicateType(PredicateTypeAutogovAgentGovernanceDeployment)
	if !exists {
		t.Fatal("agent-governance deployment predicate type missing from registry")
	}
	if info.URI != wantURI {
		t.Errorf("registry URI = %q, want %q", info.URI, wantURI)
	}
	if info.ShortName == "" || info.Description == "" || info.Spec == "" {
		t.Errorf("registry metadata incomplete: %+v", info)
	}

	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "predicate-types.md"))
	if err != nil {
		t.Fatalf("failed to read docs/predicate-types.md: %v", err)
	}
	if !strings.Contains(string(docs), wantURI) {
		t.Error("docs/predicate-types.md does not document the agent-governance deployment URI")
	}
}
