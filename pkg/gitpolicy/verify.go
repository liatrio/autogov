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

	// Warn if policy was loaded from an unexpected file.
	if policy.LoadedFrom != "" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("policy loaded from fallback file: %s (neither targets.json nor policy.json found)", policy.LoadedFrom))
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
		updatePolicyRuleStatus(&result.PolicyRules[i], result)
	}

	return allPassed
}

// updatePolicyRuleStatus updates a single policy rule's enforcement status and
// details based on the verification result.
func updatePolicyRuleStatus(rule *PolicyRule, result *VerificationResult) {
	switch rule.Name {
	case "require-pr":
		updateRequirePRRule(rule, result.BranchProtection)
	case "require-reviews":
		updateRequireReviewsRule(rule, result.BranchProtection)
	case "require-signed-commits":
		updateRequireSignedCommitsRule(rule, result.BranchProtection)
	case "enforce-admins":
		// Cannot verify admin enforcement from commit history alone.
		rule.Details = "cannot verify admin enforcement from commit history"
	case "required-signers":
		updateRequiredSignersRule(rule, result.SignerPolicy)
	}
}

// updateRequirePRRule updates the require-pr rule from branch protection status.
func updateRequirePRRule(rule *PolicyRule, bp *BranchProtectionStatus) {
	if bp == nil {
		return
	}
	rule.Enforced = bp.MergeCommitCount > 0
	if rule.Enforced {
		rule.Details = fmt.Sprintf("%d merge commits found", bp.MergeCommitCount)
	} else {
		rule.Details = "no merge commits found"
	}
}

// updateRequireReviewsRule updates the require-reviews rule from branch protection status.
func updateRequireReviewsRule(rule *PolicyRule, bp *BranchProtectionStatus) {
	if bp == nil {
		return
	}
	rule.Enforced = bp.MergeCommitCount > 0
	if rule.Enforced {
		rule.Details = "merge commits indicate review workflow"
	} else {
		rule.Details = "cannot verify review count from commit history alone"
	}
}

// updateRequireSignedCommitsRule updates the require-signed-commits rule from branch protection status.
func updateRequireSignedCommitsRule(rule *PolicyRule, bp *BranchProtectionStatus) {
	if bp == nil {
		return
	}
	rule.Enforced = bp.SignedCommitCount == bp.TotalCommitCount &&
		bp.TotalCommitCount > 0
	rule.Details = fmt.Sprintf("%d/%d commits signed",
		bp.SignedCommitCount, bp.TotalCommitCount)
}

// updateRequiredSignersRule updates the required-signers rule from signer policy status.
func updateRequiredSignersRule(rule *PolicyRule, sp *SignerPolicyStatus) {
	if sp == nil {
		return
	}
	rule.Enforced = sp.AllSigned
	if rule.Enforced {
		rule.Details = "all required signers verified"
	} else if len(sp.MissingSigners) > 0 {
		rule.Details = fmt.Sprintf("missing signers: %v", sp.MissingSigners)
	}
}
