// Package gitpolicy provides verification of gittuf-style repository policies.
// It verifies branch protection rules and signer requirements against a local
// git repository, reporting which policies are enforced.
package gitpolicy

// VerifyOptions configures policy verification.
type VerifyOptions struct {
	// RepoPath is the path to the local git repository.
	RepoPath string
	// TargetRef is the ref to verify policy against (e.g., "refs/heads/main").
	TargetRef string
	// PolicyPath is an explicit path to a policy file or directory. Optional.
	PolicyPath string
	// CertIdentity is the expected signer identity for commit signatures.
	CertIdentity string
	// CertIssuer is the expected OIDC issuer.
	CertIssuer string
	// MaxCommits limits how many commits to walk for verification.
	MaxCommits int
}

// VerificationResult holds the outcome of policy verification.
type VerificationResult struct {
	Verified         bool                    `json:"verified"`
	Ref              string                  `json:"ref"`
	PolicyRules      []PolicyRule            `json:"policy_rules,omitempty"`
	BranchProtection *BranchProtectionStatus `json:"branch_protection,omitempty"`
	SignerPolicy     *SignerPolicyStatus     `json:"signer_policy,omitempty"`
	ErrorMsg         string                  `json:"error,omitempty"`
	Warnings         []string                `json:"warnings,omitempty"`
}

// PolicyRule represents a single policy rule and its enforcement status.
type PolicyRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enforced    bool   `json:"enforced"`
	Details     string `json:"details,omitempty"`
}

// BranchProtectionStatus reports branch protection verification results.
type BranchProtectionStatus struct {
	RequirePR            bool `json:"require_pr"`
	RequireReviews       bool `json:"require_reviews"`
	MinReviewers         int  `json:"min_reviewers,omitempty"`
	RequireSignedCommits bool `json:"require_signed_commits"`
	EnforceAdmins        bool `json:"enforce_admins"`
	Verified             bool `json:"verified"`

	// Evidence tracks what was observed in commit history.
	MergeCommitCount  int `json:"merge_commit_count"`
	SignedCommitCount int `json:"signed_commit_count"`
	TotalCommitCount  int `json:"total_commit_count"`
}

// SignerPolicyStatus reports signer policy verification results.
type SignerPolicyStatus struct {
	RequiredSigners []string `json:"required_signers,omitempty"`
	VerifiedSigners []string `json:"verified_signers,omitempty"`
	MissingSigners  []string `json:"missing_signers,omitempty"`
	AllSigned       bool     `json:"all_signed"`
}

// Policy represents a parsed gittuf-style policy.
type Policy struct {
	Rules             []PolicyRuleConfig                `json:"rules,omitempty"`
	ProtectedBranches map[string]BranchProtectionConfig `json:"protected_branches,omitempty"`
	RequiredSigners   map[string][]string               `json:"required_signers,omitempty"`
	// LoadedFrom records which file the policy was loaded from (set during discovery).
	LoadedFrom string `json:"-"`
}

// PolicyRuleConfig defines a single policy rule from a gittuf policy file.
type PolicyRuleConfig struct {
	Name           string   `json:"name"`
	Pattern        string   `json:"pattern"`
	AuthorizedKeys []string `json:"authorized_keys,omitempty"`
	Threshold      int      `json:"threshold,omitempty"`
}

// BranchProtectionConfig defines branch protection requirements.
type BranchProtectionConfig struct {
	RequirePR            bool `json:"require_pr"`
	RequireReviews       bool `json:"require_reviews"`
	MinReviewers         int  `json:"min_reviewers,omitempty"`
	RequireSignedCommits bool `json:"require_signed_commits"`
	EnforceAdmins        bool `json:"enforce_admins"`
}
