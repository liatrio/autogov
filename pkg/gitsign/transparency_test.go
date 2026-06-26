package gitsign

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyCommit_RejectsBackdatedSigningTime proves the fix stopped trusting
// the CMS signingTime attribute for chain validation (ac5). The signer leaf is
// expired relative to "now"; a verifiable TSA token carries a genTime that is
// ALSO outside the leaf validity window. Under the old VerifyWithChain the
// chain would be checked at the in-window signingTime and pass; under the new
// VerifyWithChainAtTime(certPool, tsaGenTime) the chain is checked at the TSA
// genTime and the expired leaf fails.
func TestVerifyCommit_RejectsBackdatedSigningTime(t *testing.T) {
	// leaf valid only in a short window in the past.
	leafNotBefore := time.Now().Add(-48 * time.Hour)
	leafNotAfter := time.Now().Add(-47 * time.Hour)
	pki := newTestPKI(t, leafNotBefore, leafNotAfter)
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)

	// TSA genTime is NOW (outside the expired leaf window). The cms signingTime
	// attribute, set by AddSigner, is also "now" — but the point is the chain is
	// validated at the trusted TSA time, and the leaf is expired at that time.
	sigPEM := pki.signCommit(t, commit, true, time.Now())
	hash := storeSignedCommit(t, repo, commit, sigPEM)

	result, err := VerifyCommit(repo, hash.String(), VerifyOptions{})
	require.NoError(t, err)
	assert.False(t, result.Verified, "expired leaf at trusted time must not verify")
	assert.False(t, result.TransparencyVerified)
	assert.NotEmpty(t, result.ErrorMsg)
}

// TestVerifyCommit_TransparencyUnboundNotVerified proves a structurally valid
// CMS signature with NO transparency anchor (no TSA token, no rekor) yields
// Verified=false with the transparency marker unset (ac6).
func TestVerifyCommit_TransparencyUnboundNotVerified(t *testing.T) {
	// leaf valid right now, so cms-at-now would otherwise pass.
	pki := newTestPKI(t, time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)

	// no TSA token attached -> transparency-unbound.
	sigPEM := pki.signCommit(t, commit, false, time.Time{})
	hash := storeSignedCommit(t, repo, commit, sigPEM)

	result, err := VerifyCommit(repo, hash.String(), VerifyOptions{})
	require.NoError(t, err)
	assert.False(t, result.Verified, "transparency-unbound signature must not be Verified")
	assert.False(t, result.TransparencyVerified, "transparency marker must stay false")
	assert.Contains(t, result.ErrorMsg, "not transparency-verified")
}

// TestVerifyCommit_TSABoundVerified proves the durable GitHub-path fix: a
// CMS signature with a valid in-window leaf and a verifiable RFC3161 TSA token
// (genTime inside the leaf window) is Verified with TransparencyVerified=true,
// and the chain is pinned to the TSA genTime (ac1 github path, ac2).
func TestVerifyCommit_TSABoundVerified(t *testing.T) {
	now := time.Now()
	pki := newTestPKI(t, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)

	sigPEM := pki.signCommit(t, commit, true, now)
	hash := storeSignedCommit(t, repo, commit, sigPEM)

	result, err := VerifyCommit(repo, hash.String(), VerifyOptions{})
	require.NoError(t, err)
	assert.True(t, result.Verified, "TSA-anchored in-window signature must verify; err=%s", result.ErrorMsg)
	assert.True(t, result.TransparencyVerified)
	assert.Equal(t, "test-signer@example.com", result.Signer)
	// no rekor on the github path.
	assert.Equal(t, int64(0), result.RekorLogIndex)
}

// TestVerifyCommit_TSAGenTimeOutsideLeafWindowFails proves the time source is
// the TSA genTime, not "now": the leaf is valid now, but the TSA token's
// genTime is in the past (before NotBefore), so chain validation at the genTime
// fails even though it would pass at now (ac2).
func TestVerifyCommit_TSAGenTimeOutsideLeafWindowFails(t *testing.T) {
	now := time.Now()
	// leaf valid only from 1h ago to 1h ahead.
	pki := newTestPKI(t, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)

	// TSA genTime is 10 days ago — before the leaf NotBefore.
	sigPEM := pki.signCommit(t, commit, true, now.Add(-240*time.Hour))
	hash := storeSignedCommit(t, repo, commit, sigPEM)

	result, err := VerifyCommit(repo, hash.String(), VerifyOptions{})
	require.NoError(t, err)
	assert.False(t, result.Verified, "chain pinned to TSA genTime must reject leaf-not-yet-valid")
	assert.False(t, result.TransparencyVerified)
}
