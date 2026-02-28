package gitpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTUFTargets(t *testing.T) {
	data := []byte(`{
		"type": "targets",
		"version": 1,
		"expires": "2026-01-01T00:00:00Z",
		"targets": {},
		"delegations": {
			"keys": {
				"key-id-1": {"keytype": "ecdsa", "keyval": {"public": "..."}}
			},
			"roles": [
				{
					"name": "protect-main",
					"keyids": ["key-id-1"],
					"threshold": 2,
					"paths": ["git:refs/heads/main"],
					"terminating": true
				}
			]
		},
		"custom": {
			"gittuf-rules": [
				{
					"name": "require-signed-commits",
					"pattern": "refs/heads/main",
					"authorized_keys": ["key-id-1"],
					"threshold": 1
				}
			]
		}
	}`)

	policy, err := parseTUFTargets(data)
	require.NoError(t, err)
	assert.NotNil(t, policy)

	// Should have rules from both delegations and custom gittuf-rules.
	assert.GreaterOrEqual(t, len(policy.Rules), 2)

	// Should have branch protection for refs/heads/main.
	bp, ok := policy.ProtectedBranches["refs/heads/main"]
	assert.True(t, ok, "expected branch protection for refs/heads/main")
	assert.True(t, bp.RequireSignedCommits)
	assert.True(t, bp.RequirePR)

	// Should have required signers for refs/heads/main.
	signers, ok := policy.RequiredSigners["refs/heads/main"]
	assert.True(t, ok, "expected required signers for refs/heads/main")
	assert.NotEmpty(t, signers)
}

func TestParseTUFTargets_InvalidJSON(t *testing.T) {
	_, err := parseTUFTargets([]byte("not json"))
	assert.Error(t, err)
}

func TestParseTUFTargets_WrongType(t *testing.T) {
	data := []byte(`{"type": "not-targets", "delegations": {"keys": {}, "roles": [{"name":"r","keyids":["k"],"threshold":1,"paths":["refs/heads/main"]}]}, "custom": {"gittuf-rules": []}}`)
	_, err := parseTUFTargets(data)
	assert.Error(t, err, "should reject non-targets type")
}

func TestParseTUFTargets_EmptyRules(t *testing.T) {
	data := []byte(`{"type": "targets", "delegations": {"keys": {}, "roles": []}, "custom": {"gittuf-rules": []}}`)
	_, err := parseTUFTargets(data)
	assert.Error(t, err, "should reject targets with no rules")
}

func TestParseSimplePolicy(t *testing.T) {
	data := []byte(`{
		"rules": [
			{"name": "rule1", "pattern": "refs/heads/main", "threshold": 1}
		],
		"protected_branches": {
			"refs/heads/main": {
				"require_pr": true,
				"require_signed_commits": true
			}
		},
		"required_signers": {
			"refs/heads/main": ["user@example.com"]
		}
	}`)

	policy, err := parseSimplePolicy(data)
	require.NoError(t, err)
	assert.Len(t, policy.Rules, 1)
	assert.Contains(t, policy.ProtectedBranches, "refs/heads/main")
	assert.Contains(t, policy.RequiredSigners, "refs/heads/main")
}

func TestParseSimplePolicy_Empty(t *testing.T) {
	_, err := parseSimplePolicy([]byte(`{}`))
	assert.Error(t, err)
}

func TestLoadPolicyFromPath_File(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")

	data := []byte(`{
		"rules": [{"name": "test", "pattern": "refs/heads/main"}],
		"protected_branches": {"refs/heads/main": {"require_pr": true}}
	}`)
	require.NoError(t, os.WriteFile(policyFile, data, 0o644))

	policy, err := LoadPolicyFromPath(policyFile)
	require.NoError(t, err)
	assert.Len(t, policy.Rules, 1)
}

func TestLoadPolicyFromPath_Directory(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")

	data := []byte(`{
		"rules": [{"name": "test", "pattern": "refs/heads/main"}],
		"protected_branches": {"refs/heads/main": {"require_pr": true}}
	}`)
	require.NoError(t, os.WriteFile(policyFile, data, 0o644))

	policy, err := LoadPolicyFromPath(dir)
	require.NoError(t, err)
	assert.NotNil(t, policy)
}

func TestLoadPolicyFromPath_Nonexistent(t *testing.T) {
	_, err := LoadPolicyFromPath("/nonexistent/path")
	assert.Error(t, err)
}

func TestIsBranchPattern(t *testing.T) {
	assert.True(t, isBranchPattern("git:refs/heads/main"))
	assert.True(t, isBranchPattern("refs/heads/main"))
	assert.False(t, isBranchPattern("src/*"))
	assert.False(t, isBranchPattern(""))
}

func TestBranchPatternToRef(t *testing.T) {
	assert.Equal(t, "refs/heads/main", branchPatternToRef("git:refs/heads/main"))
	assert.Equal(t, "refs/heads/main", branchPatternToRef("refs/heads/main"))
}
