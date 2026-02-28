package gitpolicy

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov/pkg/gitsign"
)

// VerifyBranchProtection checks the commit history on a ref for evidence
// of branch protection enforcement. It examines merge commit patterns
// (indicating PR workflow) and cryptographically verifies commit signatures
// (indicating signing policy).
func VerifyBranchProtection(repo *git.Repository, ref string, policy *Policy, maxCommits int) (*BranchProtectionStatus, error) {
	if maxCommits <= 0 {
		maxCommits = 50
	}

	status := &BranchProtectionStatus{}

	// Get the branch protection config for this ref.
	config, hasConfig := policy.ProtectedBranches[ref]
	if hasConfig {
		status.RequirePR = config.RequirePR
		status.RequireReviews = config.RequireReviews
		status.MinReviewers = config.MinReviewers
		status.RequireSignedCommits = config.RequireSignedCommits
		status.EnforceAdmins = config.EnforceAdmins
	}

	// Resolve the ref.
	hash, err := resolveRef(repo, ref)
	if err != nil {
		return nil, err
	}

	// Walk commits on the ref.
	commits, err := walkCommits(repo, hash, maxCommits)
	if err != nil {
		return nil, err
	}

	status.TotalCommitCount = len(commits)

	verifyOpts := gitsign.VerifyOptions{
		SkipRekor: true,
	}

	for _, c := range commits {
		// Merge commits indicate PR workflow.
		if c.NumParents() > 1 {
			status.MergeCommitCount++
		}

		// Cryptographically verify commit signatures rather than just
		// checking presence, so invalid/expired signatures don't count.
		if c.PGPSignature != "" {
			result, err := gitsign.VerifyCommit(repo, c.Hash.String(), verifyOpts)
			if err == nil && result.Verified {
				status.SignedCommitCount++
			}
		}
	}

	// Determine verification status based on policy requirements and evidence.
	status.Verified = evaluateBranchProtection(status, hasConfig)

	return status, nil
}

// evaluateBranchProtection determines if branch protection is verified
// based on policy config and observed evidence.
func evaluateBranchProtection(status *BranchProtectionStatus, hasConfig bool) bool {
	if !hasConfig {
		// No policy config — check if there's evidence of good practices.
		return status.MergeCommitCount > 0 || status.SignedCommitCount > 0
	}

	// If PR is required, expect merge commits.
	if status.RequirePR && status.MergeCommitCount == 0 && status.TotalCommitCount > 0 {
		return false
	}

	// If signed commits required, expect all commits to be signed.
	if status.RequireSignedCommits && status.TotalCommitCount > 0 &&
		status.SignedCommitCount < status.TotalCommitCount {
		return false
	}

	return true
}

// resolveRef resolves a ref string to a hash.
func resolveRef(repo *git.Repository, ref string) (plumbing.Hash, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if hash == nil {
		return plumbing.ZeroHash, fmt.Errorf("ref %q resolved to nil", ref)
	}
	return *hash, nil
}

// walkCommits walks commit history from a starting hash, following first parent.
func walkCommits(repo *git.Repository, from plumbing.Hash, maxCommits int) ([]*object.Commit, error) {
	var commits []*object.Commit

	current, err := repo.CommitObject(from)
	if err != nil {
		return nil, err
	}

	seen := make(map[plumbing.Hash]bool)
	for current != nil && len(commits) < maxCommits {
		if seen[current.Hash] {
			break
		}
		seen[current.Hash] = true
		commits = append(commits, current)

		if current.NumParents() == 0 {
			break
		}

		parent, err := current.Parent(0)
		if err != nil {
			break
		}
		current = parent
	}

	return commits, nil
}
