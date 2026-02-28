package gitpolicy

import (
	"fmt"

	"github.com/go-git/go-git/v5"
)

// VerifyPolicy orchestrates the full policy verification flow.
// It opens the repository, discovers or loads the policy, and evaluates
// branch protection and signer requirements.
func VerifyPolicy(opts VerifyOptions) (*VerificationResult, error) {
	result := &VerificationResult{
		Ref: opts.TargetRef,
	}

	// Open the repository.
	repo, err := git.PlainOpen(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("verify policy: open repository %q: %w", opts.RepoPath, err)
	}

	// Load policy.
	var policy *Policy
	if opts.PolicyPath != "" {
		policy, err = LoadPolicyFromPath(opts.PolicyPath)
		if err != nil {
			result.ErrorMsg = fmt.Sprintf("failed to load policy from %q: %v", opts.PolicyPath, err)
			return result, nil
		}
	} else {
		policy, err = LoadPolicy(repo, opts.RepoPath)
		if err != nil {
			result.ErrorMsg = fmt.Sprintf("no policy found: %v", err)
			result.Warnings = append(result.Warnings, "no gittuf policy found; provide --policy-path for an explicit policy file")
			return result, nil
		}
	}

	// Build policy rules from the loaded policy for the report.
	result.PolicyRules = buildPolicyRules(policy, opts.TargetRef)

	// Verify branch protection.
	branchStatus, err := VerifyBranchProtection(repo, opts.TargetRef, policy, opts.MaxCommits)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("branch protection check failed: %v", err))
	} else {
		result.BranchProtection = branchStatus
	}

	// Verify signer policy.
	signerStatus, err := VerifySignerPolicy(repo, opts.TargetRef, policy, opts)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("signer policy check failed: %v", err))
	} else {
		result.SignerPolicy = signerStatus
	}

	// Determine overall verification status.
	result.Verified = computeOverallStatus(result)

	return result, nil
}

// buildPolicyRules builds a summary of policy rules for the target ref.
func buildPolicyRules(policy *Policy, targetRef string) []PolicyRule {
	var rules []PolicyRule

	// Branch protection rules.
	if config, ok := policy.ProtectedBranches[targetRef]; ok {
		if config.RequirePR {
			rules = append(rules, PolicyRule{
				Name:        "require-pr",
				Description: "Require pull request for changes",
			})
		}
		if config.RequireReviews {
			rules = append(rules, PolicyRule{
				Name:        "require-reviews",
				Description: fmt.Sprintf("Require minimum %d reviewers", config.MinReviewers),
			})
		}
		if config.RequireSignedCommits {
			rules = append(rules, PolicyRule{
				Name:        "require-signed-commits",
				Description: "Require signed commits",
			})
		}
		if config.EnforceAdmins {
			rules = append(rules, PolicyRule{
				Name:        "enforce-admins",
				Description: "Enforce restrictions on administrators",
			})
		}
	}

	// Signer rules.
	if signers, ok := policy.RequiredSigners[targetRef]; ok && len(signers) > 0 {
		rules = append(rules, PolicyRule{
			Name:        "required-signers",
			Description: fmt.Sprintf("Require commits signed by: %v", signers),
		})
	}

	return rules
}

// computeOverallStatus determines the overall verification status.
func computeOverallStatus(result *VerificationResult) bool {
	if result.ErrorMsg != "" {
		return false
	}

	allPassed := (result.BranchProtection == nil || result.BranchProtection.Verified) &&
		(result.SignerPolicy == nil || result.SignerPolicy.AllSigned)

	// Update rule enforcement status based on results.
	for i := range result.PolicyRules {
		rule := &result.PolicyRules[i]
		switch rule.Name {
		case "require-pr":
			if result.BranchProtection != nil {
				rule.Enforced = result.BranchProtection.MergeCommitCount > 0
				if rule.Enforced {
					rule.Details = fmt.Sprintf("%d merge commits found", result.BranchProtection.MergeCommitCount)
				} else {
					rule.Details = "no merge commits found"
				}
			}
		case "require-reviews":
			if result.BranchProtection != nil {
				rule.Enforced = result.BranchProtection.MergeCommitCount > 0
				if rule.Enforced {
					rule.Details = "merge commits indicate review workflow"
				} else {
					rule.Details = "cannot verify review count from commit history alone"
				}
			}
		case "require-signed-commits":
			if result.BranchProtection != nil {
				rule.Enforced = result.BranchProtection.SignedCommitCount == result.BranchProtection.TotalCommitCount &&
					result.BranchProtection.TotalCommitCount > 0
				rule.Details = fmt.Sprintf("%d/%d commits signed",
					result.BranchProtection.SignedCommitCount, result.BranchProtection.TotalCommitCount)
			}
		case "enforce-admins":
			// Cannot verify admin enforcement from commit history alone.
			rule.Details = "cannot verify admin enforcement from commit history"
		case "required-signers":
			if result.SignerPolicy != nil {
				rule.Enforced = result.SignerPolicy.AllSigned
				if rule.Enforced {
					rule.Details = "all required signers verified"
				} else if len(result.SignerPolicy.MissingSigners) > 0 {
					rule.Details = fmt.Sprintf("missing signers: %v", result.SignerPolicy.MissingSigners)
				}
			}
		}
	}

	return allPassed
}
