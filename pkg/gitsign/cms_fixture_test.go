package gitsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cmsFixtureOptions controls the synthetic CMS-signed commit fixture.
type cmsFixtureOptions struct {
	// notBefore / notAfter bound the self-signed leaf's validity. defaults to a
	// window centered on now if zero.
	notBefore time.Time
	notAfter  time.Time
	// signingTime is the value written into the CMS signingTime authenticated
	// attribute. defaults to now if zero.
	signingTime time.Time
	// identityURI, if set, becomes the leaf's URI SAN (the gitsign signer identity).
	identityURI string
}

// newCMSSignedCommit builds a git repo with a single commit whose PGPSignature is
// a structurally valid CMS "SIGNED MESSAGE" detached signature over the commit's
// canonical (signature-stripped) bytes, signed by a self-signed leaf. it installs
// that leaf as the trusted Fulcio root via the fulcioPoolFn seam for the duration
// of the test, so verifyCommitObject's VerifyWithChainAtTime path runs against a
// trust anchor we control.
//
// the harness limitation noted in the story (go-git only produces unsigned
// commits) is why this fixture is built by hand: there is no real CMS-signed
// commit fixture in the repo, and an unsigned commit short-circuits on
// result.Unsigned before reaching the CMS/transparency logic.
func newCMSSignedCommit(t *testing.T, opts cmsFixtureOptions) (*git.Repository, string) {
	t.Helper()

	now := time.Now().UTC()
	if opts.notBefore.IsZero() {
		opts.notBefore = now.Add(-1 * time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = now.Add(1 * time.Hour)
	}
	if opts.signingTime.IsZero() {
		opts.signingTime = now
	}

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data\n"), 0o644))
	_, err = wt.Add("file.txt")
	require.NoError(t, err)

	hash, err := wt.Commit("feat: cms-signed commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	})
	require.NoError(t, err)

	commit, err := repo.CommitObject(hash)
	require.NoError(t, err)

	// the bytes that gitsign signs are the commit object without its signature.
	signedContent, err := encodeCommitWithoutSignature(commit)
	require.NoError(t, err)

	// self-signed leaf standing in for a Fulcio cert.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-fulcio-leaf"},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if opts.identityURI != "" {
		u, perr := url.Parse(opts.identityURI)
		require.NoError(t, perr)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// build a detached CMS signature with a caller-controlled signingTime. the
	// signingTime is passed via ExtraSignedAttributes so the test can place it
	// inside (or outside) the leaf's validity window independently of "now".
	sd, err := pkcs7.NewSignedData(signedContent)
	require.NoError(t, err)
	require.NoError(t, sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: pkcs7.OIDAttributeSigningTime, Value: opts.signingTime},
		},
	}))
	sd.Detach()
	blob, err := sd.Finish()
	require.NoError(t, err)

	sig := string(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: blob}))

	// re-encode the commit with the signature header and store it, so VerifyCommit
	// resolves a CMS-signed commit object.
	commit.PGPSignature = sig
	obj := repo.Storer.NewEncodedObject()
	require.NoError(t, commit.Encode(obj))
	signedHash, err := repo.Storer.SetEncodedObject(obj)
	require.NoError(t, err)

	// point the branch ref at the signed commit object.
	headRef, err := repo.Head()
	require.NoError(t, err)
	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(headRef.Name(), signedHash)))

	// install our self-signed leaf as the trusted root for the duration of the test.
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	t.Cleanup(SetFulcioPoolForTesting(pool))

	return repo, signedHash.String()
}

// TestVerifyCommit_RejectsBackdatedSigningTime proves we stopped trusting the cms
// signingTime attribute (ac5). the leaf's validity window is entirely in the past
// and the signingTime attribute sits inside that expired window. under the old
// VerifyWithChain the chain would be checked at signingTime and pass; under
// VerifyWithChainAtTime(now) the expired leaf fails ee.Verify.
func TestVerifyCommit_RejectsBackdatedSigningTime(t *testing.T) {
	now := time.Now().UTC()
	repo, hash := newCMSSignedCommit(t, cmsFixtureOptions{
		notBefore:   now.Add(-2 * time.Hour),
		notAfter:    now.Add(-1 * time.Hour), // expired relative to now
		signingTime: now.Add(-90 * time.Minute),
	})

	result, err := VerifyCommit(repo, hash, VerifyOptions{})
	require.NoError(t, err)
	assert.False(t, result.Verified, "expired leaf with backdated signingTime must not verify")
	assert.False(t, result.CMSVerified, "chain pinned to now must reject the expired leaf")
	assert.Contains(t, result.ErrorMsg, "CMS signature verification failed")
	assert.Contains(t, result.ErrorMsg, "expired")
}

// TestVerifyCommit_TransparencyUnboundNotVerified proves a structurally valid CMS
// signature with no rekor entry is reported not verified, with the transparency
// markers distinguishing it from a CMS failure (ac6).
func TestVerifyCommit_TransparencyUnboundNotVerified(t *testing.T) {
	repo, hash := newCMSSignedCommit(t, cmsFixtureOptions{
		identityURI: "https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main",
	})

	result, err := VerifyCommit(repo, hash, VerifyOptions{})
	require.NoError(t, err)

	// the CMS signature is valid at now against the trusted leaf...
	assert.True(t, result.CMSVerified, "cms-at-now should validate the current leaf")
	assert.Equal(t, "https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main", result.Signer)

	// ...but it is NOT transparency-verified, so the gate-bearing booleans stay false.
	assert.False(t, result.Verified, "no rekor inclusion proof: must not be Verified")
	assert.False(t, result.TransparencyVerified)
	assert.Zero(t, result.RekorLogIndex, "no transparency verification: rekor index absent")
	assert.Contains(t, result.ErrorMsg, "not transparency-verified")
}

// TestVerifyCommit_CertIdentityMismatchUnbound confirms identity enforcement still
// runs on the CMS-at-now path and short-circuits before the transparency marker.
func TestVerifyCommit_CertIdentityMismatchUnbound(t *testing.T) {
	repo, hash := newCMSSignedCommit(t, cmsFixtureOptions{
		identityURI: "https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main",
	})

	result, err := VerifyCommit(repo, hash, VerifyOptions{CertIdentity: "https://github.com/evil/repo"})
	require.NoError(t, err)
	assert.False(t, result.Verified)
	assert.Contains(t, result.ErrorMsg, "cert-identity mismatch")
}
