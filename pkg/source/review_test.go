package source

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullL3Controls is a controls record that satisfies every L3 leg.
func fullL3Controls() *SourceReviewControls {
	return &SourceReviewControls{
		ForcePushBlocked:        true,
		RequiredLinearHistory:   true,
		DeletionBlocked:         true,
		RequiredSignatures:      true,
		RequiredStatusChecks:    []string{"build", "test"},
		BypassActors:            nil, // no bypass = cleanest
		BypassActorsComplete:    true,
		ContinuityStartRevision: "abc123",
		ContinuityComplete:      true, // v0.2 fail-closed continuity signal
	}
}

func TestComputeSourceLevelFromControls(t *testing.T) {
	const base = SLSASourceLevel1

	t.Run("full controls, no bypass -> L3", func(t *testing.T) {
		lvl, ann := ComputeSourceLevelFromControls(fullL3Controls(), nil, base)
		assert.Equal(t, SLSASourceLevel3, lvl)
		assert.Contains(t, ann, "ORG_SOURCE_FORCE_PUSH_BLOCKED")
		assert.Contains(t, ann, "ORG_SOURCE_STATUS_CHECKS_REQUIRED")
	})

	t.Run("full controls + allowlisted bypass -> L3", func(t *testing.T) {
		tc := fullL3Controls()
		tc.BypassActors = []string{"Integration:801323:always"}
		lvl, _ := ComputeSourceLevelFromControls(tc, []string{"Integration:801323"}, base)
		assert.Equal(t, SLSASourceLevel3, lvl)
	})

	t.Run("non-allowlisted bypass actor -> not L3 (stays base)", func(t *testing.T) {
		tc := fullL3Controls()
		tc.BypassActors = []string{"Team:42:always"}
		lvl, _ := ComputeSourceLevelFromControls(tc, []string{"Integration:801323"}, base)
		assert.Equal(t, base, lvl)
	})

	t.Run("bypassActorsComplete=false -> not L3 (fail-closed: empty != none)", func(t *testing.T) {
		tc := fullL3Controls()
		tc.BypassActorsComplete = false
		lvl, _ := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl, "unknown bypass authority must not earn L3")
	})

	t.Run("empty continuity -> not L3 (fail-closed: undetermined)", func(t *testing.T) {
		tc := fullL3Controls()
		tc.ContinuityStartRevision = ""
		lvl, _ := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl)
	})

	t.Run("continuityComplete=false + non-empty start -> not L3 (fail-closed)", func(t *testing.T) {
		// fail-closed: a populated start revision is NOT enough — the producer must
		// also assert ContinuityComplete. A bundle missing continuityComplete (it
		// decodes to false) with a start but no complete flag must keep the level
		// dormant.
		tc := fullL3Controls()
		tc.ContinuityComplete = false
		lvl, ann := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl, "an incomplete continuity proof must not earn L3")
		assert.NotContains(t, ann, "ORG_SOURCE_CONTINUOUS_ENFORCEMENT")
	})

	t.Run("continuityComplete=true + non-empty start -> L3 + continuity annotation", func(t *testing.T) {
		lvl, ann := ComputeSourceLevelFromControls(fullL3Controls(), nil, base)
		assert.Equal(t, SLSASourceLevel3, lvl)
		assert.Contains(t, ann, "ORG_SOURCE_CONTINUOUS_ENFORCEMENT")
	})

	t.Run("force-push not blocked -> not L3", func(t *testing.T) {
		tc := fullL3Controls()
		tc.ForcePushBlocked = false
		lvl, _ := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl)
	})

	t.Run("no required status checks -> not L3", func(t *testing.T) {
		tc := fullL3Controls()
		tc.RequiredStatusChecks = nil
		lvl, _ := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl)
	})

	t.Run("no retained/immutable history (neither linear nor deletion-blocked) -> not L3", func(t *testing.T) {
		tc := fullL3Controls()
		tc.RequiredLinearHistory = false
		tc.DeletionBlocked = false
		lvl, _ := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl)
	})

	t.Run("nil controls -> base, no annotations", func(t *testing.T) {
		lvl, ann := ComputeSourceLevelFromControls(nil, nil, base)
		assert.Equal(t, base, lvl)
		assert.Nil(t, ann)
	})

	t.Run("annotations always emitted even when not L3", func(t *testing.T) {
		// only force-push set + incomplete bypass -> not L3, but the annotation is still recorded.
		tc := &SourceReviewControls{ForcePushBlocked: true, BypassActorsComplete: false}
		lvl, ann := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, base, lvl)
		assert.Equal(t, []string{"ORG_SOURCE_FORCE_PUSH_BLOCKED"}, ann)
	})

	t.Run("two-party review -> annotation, never a numeric L4", func(t *testing.T) {
		tc := fullL3Controls()
		tc.TwoPartyReviewed = true
		lvl, ann := ComputeSourceLevelFromControls(tc, nil, base)
		assert.Equal(t, SLSASourceLevel3, lvl) // review is NOT required for L3
		assert.Contains(t, ann, "ORG_SOURCE_TWO_PARTY_REVIEWED")
		for _, a := range ann {
			assert.NotEqual(t, "SLSA_SOURCE_LEVEL_4", a, "there is no numeric L4 token")
		}
	})
}

func TestBypassActorsAllNarrow(t *testing.T) {
	assert.True(t, bypassActorsAllNarrow(nil, nil), "no bypass is narrow")
	assert.True(t, bypassActorsAllNarrow([]string{}, []string{"Integration:1"}), "empty is narrow")
	assert.True(t, bypassActorsAllNarrow([]string{"Integration:801323:always"}, []string{"Integration:801323"}))
	assert.True(t, bypassActorsAllNarrow(
		[]string{"Integration:801323:always", "Integration:801323:pull_request"},
		[]string{"Integration:801323"}), "same actor, different modes both match Type:ID")
	assert.False(t, bypassActorsAllNarrow([]string{"Team:42:always"}, []string{"Integration:801323"}))
	assert.False(t, bypassActorsAllNarrow([]string{"RepositoryRole:5:always"}, nil), "no allowlist + a bypass -> not narrow")
	assert.False(t, bypassActorsAllNarrow(
		[]string{"Integration:801323:always", "Team:42:always"},
		[]string{"Integration:801323"}), "one disallowed actor fails the whole set")
}

func TestVerifySourceReviewControls_RequiresCertIdentity(t *testing.T) {
	// fail-closed: an unverified source-review bundle must never be able to promote
	// the source level, so the verifier refuses without an enforced signer identity.
	_, err := VerifySourceReviewControls("ignored.json", VerifyOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert-identity")
}

func TestVerifySourceReviewControls_LoadFailure(t *testing.T) {
	// a missing/unreadable bundle is an error (caller degrades to no promotion).
	_, err := VerifySourceReviewControls(filepath.Join("testdata", "does-not-exist.jsonl"),
		VerifyOptions{CertIdentity: "https://github.com/org/repo/.github/workflows/x.yml@refs/heads/main"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load source-review bundle")
}

func TestVerifySourceReviewControls_IdentityMismatchFailsClosed(t *testing.T) {
	// pointing at a real, validly-signed bundle whose signer does NOT match the
	// expected identity must fail closed (no controls) — the public-good source
	// fixture is signed by chainguard, not the org/repo identity below.
	_, err := VerifySourceReviewControls(
		filepath.Join("testdata", "bundle-public-good.jsonl"),
		VerifyOptions{CertIdentity: "https://github.com/org/repo/.github/workflows/never-matches.yml@refs/heads/main"},
	)
	require.Error(t, err, "a non-matching signer must not yield controls")
	assert.NotContains(t, err.Error(), "cert-identity", "should fail at verification, not the pre-check")
}

func TestCheckSourceReviewBinding(t *testing.T) {
	const commit = "abc1234567890def1234567890abcdef12345678"
	const repo = "https://github.com/liatrio/autogov"

	t.Run("matching commit, no repo opt -> ok", func(t *testing.T) {
		require.NoError(t, checkSourceReviewBinding("", commit, VerifyOptions{Commit: commit}))
	})
	t.Run("matching commit + repo -> ok", func(t *testing.T) {
		require.NoError(t, checkSourceReviewBinding(repo, commit, VerifyOptions{RepoURI: repo, Commit: commit}))
	})
	t.Run("mismatched commit -> error (replay blocked)", func(t *testing.T) {
		err := checkSourceReviewBinding(repo, "0000000000000000000000000000000000000000", VerifyOptions{RepoURI: repo, Commit: commit})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not the verified commit")
	})
	t.Run("no expected commit -> error (cannot bind)", func(t *testing.T) {
		err := checkSourceReviewBinding(repo, commit, VerifyOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no expected commit")
	})
	t.Run("matching commit, mismatched repo -> error", func(t *testing.T) {
		err := checkSourceReviewBinding("https://github.com/evil/repo", commit, VerifyOptions{RepoURI: repo, Commit: commit})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repository")
	})
}
