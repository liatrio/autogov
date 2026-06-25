package vsa

import (
	"fmt"
	"strings"
	"time"

	"github.com/liatrio/autogov/pkg/attestations"
)

// SourceVSAOptions configures a standards-shaped SLSA Source VSA.
//
// A Source VSA is a verification_summary/v1 statement whose subject is the
// source revision (the repo at a git commit) rather than a build artifact.
// See https://slsa.dev/spec/v1.2-rc1/verifying-source and the source-track
// level definitions at https://slsa.dev/spec/v1.2/source-requirements.
type SourceVSAOptions struct {
	// RepoURI is the source repository (becomes resourceUri and subject name).
	RepoURI string
	// Commit is the verified git revision SHA (becomes the subject gitCommit digest).
	Commit string
	// SourceLevel is the highest SLSA_SOURCE_LEVEL_n the evidence supports.
	SourceLevel string
	// AdditionalLevels are non-numbered source-track assertions the verifier can
	// vouch for (e.g. a review-control annotation). These sit alongside the
	// numbered level in verifiedLevels per the source-track VSA spec, which
	// allows additional properties.
	AdditionalLevels []string
	// Passed is the overall verification result.
	Passed bool
	// PolicyURI identifies the policy the verification was performed against.
	PolicyURI string
	// PolicyDigest is the optional digest of that policy.
	PolicyDigest map[string]string
	// InputAttestations are the bundles this VSA summarizes.
	InputAttestations []ResourceDescriptor
	// AdditionalVerifiers records the verifying tool versions.
	AdditionalVerifiers map[string]string
}

// GenerateSourceVSA builds a standards-shaped SLSA Source VSA.
//
// Per the source track, the subject is the revision (repo + gitCommit digest),
// resourceUri is the repository, and verifiedLevels MUST contain only the
// highest SLSA source level met. The source control system is the expected
// issuer of a Source VSA; autogov issues it here as a downstream verifier and
// records that in verifier.id (see the issuer note in the docs).
func GenerateSourceVSA(opts SourceVSAOptions) (*VSA, error) {
	if opts.RepoURI == "" {
		return nil, fmt.Errorf("source VSA: repo URI is required")
	}
	if opts.Commit == "" {
		return nil, fmt.Errorf("source VSA: commit is required")
	}
	if !IsSLSATrackLevel(opts.SourceLevel) || !strings.HasPrefix(opts.SourceLevel, "SLSA_SOURCE_LEVEL_") {
		return nil, fmt.Errorf("source VSA: invalid source level %q", opts.SourceLevel)
	}

	result := "PASSED"
	if !opts.Passed {
		result = "FAILED"
	}

	// only the highest numbered source level, plus any non-numbered annotations.
	verifiedLevels := append([]string{opts.SourceLevel}, opts.AdditionalLevels...)

	verifierVersions := make(map[string]string, len(opts.AdditionalVerifiers))
	for tool, ver := range opts.AdditionalVerifiers {
		verifierVersions[tool] = ver
	}

	subject := VSASubject{
		URI:    opts.RepoURI,
		Digest: map[string]string{"gitCommit": strings.ToLower(strings.TrimSpace(opts.Commit))},
	}

	v := &VSA{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: attestations.PredicateTypeVSA,
		Subject:       []VSASubject{subject},
		Predicate: VSAPredicate{
			Verifier: VSAVerifier{
				ID:      "https://github.com/liatrio/autogov",
				Version: verifierVersions,
			},
			TimeVerified:       time.Now().UTC().Format(time.RFC3339),
			ResourceURI:        opts.RepoURI,
			Policy:             VSAPolicy{URI: opts.PolicyURI, Digest: opts.PolicyDigest},
			InputAttestations:  opts.InputAttestations,
			VerificationResult: result,
			VerifiedLevels:     verifiedLevels,
			// slsaVersion stays "1.1" for consistency with the rest of the codebase's
			// VSAs; the v1.2-rc1 source-track docs cited above describe the source
			// level semantics, not the verification_summary predicate version.
			SlsaVersion: "1.1",
		},
		Metadata: map[string]interface{}{
			"autogov.source.level": opts.SourceLevel,
		},
	}

	if err := v.ValidateComprehensive(); err != nil {
		return nil, fmt.Errorf("generated source VSA failed validation: %w", err)
	}

	return v, nil
}
