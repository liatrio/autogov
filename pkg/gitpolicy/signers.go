package gitpolicy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/liatrio/autogov/pkg/gitsign"
)

// VerifySignerPolicy walks commits on a ref and verifies that commit signers
// match the required signers defined in the policy.
func VerifySignerPolicy(repo *git.Repository, ref string, policy *Policy, opts VerifyOptions) (*SignerPolicyStatus, error) {
	status := &SignerPolicyStatus{}

	// Get required signers for this ref.
	requiredSigners := policy.RequiredSigners[ref]
	if len(requiredSigners) == 0 {
		// No signer requirements for this ref.
		status.AllSigned = true
		return status, nil
	}
	status.RequiredSigners = requiredSigners

	// Resolve the ref.
	hash, err := resolveRef(repo, ref)
	if err != nil {
		return nil, fmt.Errorf("verify signers: resolve ref %q: %w", ref, err)
	}

	maxCommits := opts.MaxCommits
	if maxCommits <= 0 {
		maxCommits = 50
	}

	// Walk commits.
	commits, err := walkCommits(repo, hash, maxCommits)
	if err != nil {
		return nil, fmt.Errorf("verify signers: walk commits: %w", err)
	}

	// Verify signatures and collect signer identities.
	verifyOpts := gitsign.VerifyOptions{
		CertIdentity: opts.CertIdentity,
		CertIssuer:   opts.CertIssuer,
	}

	signersSeen := make(map[string]bool)
	for _, c := range commits {
		result, err := gitsign.VerifyCommit(repo, c.Hash.String(), verifyOpts)
		if err != nil {
			continue
		}

		if result.Verified && result.Signer != "" {
			signersSeen[result.Signer] = true
			if !slices.Contains(status.VerifiedSigners, result.Signer) {
				status.VerifiedSigners = append(status.VerifiedSigners, result.Signer)
			}
		}
	}

	// Check which required signers are present.
	for _, required := range requiredSigners {
		if !signerMatchesAny(required, signersSeen) {
			status.MissingSigners = append(status.MissingSigners, required)
		}
	}

	status.AllSigned = len(status.MissingSigners) == 0

	return status, nil
}

// signerMatchesAny checks if a required signer matches any of the observed signers.
// Supports exact match and prefix matching for URI-based identities.
func signerMatchesAny(required string, seen map[string]bool) bool {
	if seen[required] {
		return true
	}

	// Try prefix matching for URI identities (e.g., key IDs that map to cert subjects).
	for signer := range seen {
		if strings.EqualFold(signer, required) {
			return true
		}
		// Path-bounded prefix match (same as gitsign.matchIdentity).
		if strings.HasPrefix(signer, required) {
			rest := signer[len(required):]
			if len(rest) > 0 && (rest[0] == '/' || rest[0] == '@') {
				return true
			}
		}
	}

	return false
}
