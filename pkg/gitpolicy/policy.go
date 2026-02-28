package gitpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// LoadPolicy discovers and loads a gittuf policy from a git repository.
// It first checks for a gittuf policy ref (refs/gittuf/policy), then
// falls back to the .gittuf/ directory in the working tree.
func LoadPolicy(repo *git.Repository, repoPath string) (*Policy, error) {
	// Try loading from gittuf policy ref.
	pol, err := loadPolicyFromRef(repo)
	if err == nil && pol != nil {
		return pol, nil
	}

	// Try loading from .gittuf/ directory.
	gittufDir := filepath.Join(repoPath, ".gittuf")
	if info, err := os.Stat(gittufDir); err == nil && info.IsDir() {
		return loadPolicyFromDirectory(gittufDir)
	}

	return nil, fmt.Errorf("no gittuf policy found in repository (checked refs/gittuf/policy and .gittuf/)")
}

// LoadPolicyFromPath loads a policy from an explicit file or directory path.
func LoadPolicyFromPath(path string) (*Policy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("policy path %q: %w", path, err)
	}

	if info.IsDir() {
		return loadPolicyFromDirectory(path)
	}

	return loadPolicyFromFile(path)
}

// loadPolicyFromRef attempts to load a policy from the refs/gittuf/policy ref.
func loadPolicyFromRef(repo *git.Repository) (*Policy, error) {
	ref, err := repo.Reference(plumbing.ReferenceName("refs/gittuf/policy"), true)
	if err != nil {
		return nil, err
	}

	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("read gittuf policy commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read gittuf policy tree: %w", err)
	}

	// Look for targets.json in the policy tree (gittuf uses TUF-style metadata).
	file, err := tree.File("targets.json")
	if err != nil {
		return nil, fmt.Errorf("targets.json not found in gittuf policy: %w", err)
	}

	content, err := file.Contents()
	if err != nil {
		return nil, fmt.Errorf("read targets.json: %w", err)
	}

	return parseTUFTargets([]byte(content))
}

// loadPolicyFromDirectory loads policy files from a directory.
func loadPolicyFromDirectory(dir string) (*Policy, error) {
	// Look for targets.json first (gittuf format).
	targetsPath := filepath.Join(dir, "targets.json")
	if _, err := os.Stat(targetsPath); err == nil {
		return loadPolicyFromFile(targetsPath)
	}

	// Look for policy.json.
	policyPath := filepath.Join(dir, "policy.json")
	if _, err := os.Stat(policyPath); err == nil {
		return loadPolicyFromFile(policyPath)
	}

	// Try to load any .json file in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			pol, err := loadPolicyFromFile(filepath.Join(dir, entry.Name()))
			if err == nil {
				return pol, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid policy files found in %s", dir)
}

// loadPolicyFromFile loads a policy from a JSON file.
func loadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	// Try parsing as TUF targets format first.
	pol, err := parseTUFTargets(data)
	if err == nil {
		return pol, nil
	}

	// Try parsing as a simple policy format.
	return parseSimplePolicy(data)
}

// tufTargets represents the relevant fields of a TUF targets.json (gittuf format).
type tufTargets struct {
	Type        string `json:"type"`
	Version     int    `json:"version"`
	Delegations struct {
		Keys  map[string]tufKey `json:"keys"`
		Roles []tufRole         `json:"roles"`
	} `json:"delegations"`
	Custom struct {
		GittufRules []gittufRule `json:"gittuf-rules"`
	} `json:"custom"`
}

type tufKey struct {
	KeyType string `json:"keytype"`
	KeyVal  struct {
		Public string `json:"public"`
	} `json:"keyval"`
}

type tufRole struct {
	Name        string   `json:"name"`
	KeyIDs      []string `json:"keyids"`
	Threshold   int      `json:"threshold"`
	Paths       []string `json:"paths"`
	Terminating bool     `json:"terminating"`
}

type gittufRule struct {
	Name           string   `json:"name"`
	Pattern        string   `json:"pattern"`
	AuthorizedKeys []string `json:"authorized_keys"`
	Threshold      int      `json:"threshold"`
}

// parseTUFTargets parses a TUF-style targets.json into our Policy structure.
func parseTUFTargets(data []byte) (*Policy, error) {
	var targets tufTargets
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("parse TUF targets: %w", err)
	}

	// Validate it looks like a TUF targets document.
	if targets.Type != "targets" || (len(targets.Delegations.Roles) == 0 && len(targets.Custom.GittufRules) == 0) {
		return nil, fmt.Errorf("not a valid TUF targets document")
	}

	policy := &Policy{
		ProtectedBranches: make(map[string]BranchProtectionConfig),
		RequiredSigners:   make(map[string][]string),
	}

	// Extract rules from delegations.
	for _, role := range targets.Delegations.Roles {
		for _, path := range role.Paths {
			rule := PolicyRuleConfig{
				Name:           role.Name,
				Pattern:        path,
				AuthorizedKeys: role.KeyIDs,
				Threshold:      role.Threshold,
			}
			policy.Rules = append(policy.Rules, rule)

			// If it looks like a branch protection pattern, extract config.
			if isBranchPattern(path) {
				ref := branchPatternToRef(path)
				policy.ProtectedBranches[ref] = BranchProtectionConfig{
					RequireSignedCommits: true,
					RequirePR:            true,
					RequireReviews:       role.Threshold > 1,
					MinReviewers:         role.Threshold,
				}
				policy.RequiredSigners[ref] = role.KeyIDs
			}
		}
	}

	// Extract rules from custom gittuf-rules.
	for _, rule := range targets.Custom.GittufRules {
		policyRule := PolicyRuleConfig(rule)
		policy.Rules = append(policy.Rules, policyRule)

		if isBranchPattern(rule.Pattern) {
			ref := branchPatternToRef(rule.Pattern)
			existing := policy.ProtectedBranches[ref]
			existing.RequireSignedCommits = true
			if rule.Threshold > 1 {
				existing.RequireReviews = true
				existing.MinReviewers = rule.Threshold
			}
			policy.ProtectedBranches[ref] = existing
			policy.RequiredSigners[ref] = append(policy.RequiredSigners[ref], rule.AuthorizedKeys...)
		}
	}

	return policy, nil
}

// parseSimplePolicy parses a simple JSON policy format.
func parseSimplePolicy(data []byte) (*Policy, error) {
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse simple policy: %w", err)
	}

	if len(policy.Rules) == 0 && len(policy.ProtectedBranches) == 0 && len(policy.RequiredSigners) == 0 {
		return nil, fmt.Errorf("empty or invalid policy file")
	}

	return &policy, nil
}

// isBranchPattern checks if a path pattern refers to a git branch.
func isBranchPattern(pattern string) bool {
	return len(pattern) >= 5 && (pattern[:4] == "git:" || pattern[:5] == "refs/")
}

// branchPatternToRef normalizes a branch pattern to a ref format.
func branchPatternToRef(pattern string) string {
	if len(pattern) > 4 && pattern[:4] == "git:" {
		return pattern[4:]
	}
	return pattern
}
