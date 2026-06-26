package gitpolicy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
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
	"github.com/liatrio/autogov/pkg/gitsign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCMSUnboundCommitRepo builds a repo with a single commit whose signature is a
// structurally valid CMS "SIGNED MESSAGE" (valid at now against a self-signed leaf
// installed as the trust anchor) but with no rekor inclusion proof. such a commit
// is CMS-valid yet transparency-unbound: gitsign.VerifyCommit returns
// Verified == false, CMSVerified == true. this is the fixture ac7 requires — an
// unsigned commit would short-circuit on result.Unsigned and never exercise the
// exclusion logic.
func newCMSUnboundCommitRepo(t *testing.T, identityURI string) (*git.Repository, string) {
	t.Helper()

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

	// gitsign signs the commit object without its signature header.
	mo := new(plumbing.MemoryObject)
	require.NoError(t, commit.EncodeWithoutSignature(mo))
	reader, err := mo.Reader()
	require.NoError(t, err)
	signedContent, err := io.ReadAll(reader)
	require.NoError(t, err)

	now := time.Now().UTC()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	u, err := url.Parse(identityURI)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-fulcio-leaf"},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:                  true,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	sd, err := pkcs7.NewSignedData(signedContent)
	require.NoError(t, err)
	require.NoError(t, sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}))
	sd.Detach()
	blob, err := sd.Finish()
	require.NoError(t, err)

	commit.PGPSignature = string(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: blob}))
	obj := repo.Storer.NewEncodedObject()
	require.NoError(t, commit.Encode(obj))
	signedHash, err := repo.Storer.SetEncodedObject(obj)
	require.NoError(t, err)

	headRef, err := repo.Head()
	require.NoError(t, err)
	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(headRef.Name(), signedHash)))

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	t.Cleanup(gitsign.SetFulcioPoolForTesting(pool))

	return repo, headRef.Name().String()
}

// TestVerifyBranchProtection_ExcludesTransparencyUnbound proves a CMS-valid but
// transparency-unbound commit is NOT counted toward SignedCommitCount, so a
// require-signed-commits policy cannot pass on presence-only signatures (ac7).
func TestVerifyBranchProtection_ExcludesTransparencyUnbound(t *testing.T) {
	repo, ref := newCMSUnboundCommitRepo(t, "https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main")

	// sanity: the underlying gitsign result is cms-valid but not Verified.
	res, err := gitsign.VerifyCommit(repo, ref, gitsign.VerifyOptions{})
	require.NoError(t, err)
	require.True(t, res.CMSVerified, "fixture must be cms-valid to be a meaningful test")
	require.False(t, res.Verified, "fixture must be transparency-unbound")

	policy := &Policy{
		ProtectedBranches: map[string]BranchProtectionConfig{
			ref: {RequireSignedCommits: true},
		},
	}

	status, err := VerifyBranchProtection(repo, ref, policy, 50)
	require.NoError(t, err)

	assert.Equal(t, 1, status.TotalCommitCount)
	assert.Equal(t, 0, status.SignedCommitCount, "transparency-unbound commit must not count as signed")
	assert.False(t, status.Verified, "require-signed-commits cannot pass on a presence-only signature")
}

// TestVerifySignerPolicy_ExcludesTransparencyUnbound proves a CMS-valid but
// transparency-unbound signer is NOT collected into AllSigned / VerifiedSigners,
// so a required-signers policy cannot pass on presence-only signatures (ac7).
func TestVerifySignerPolicy_ExcludesTransparencyUnbound(t *testing.T) {
	identity := "https://github.com/liatrio/autogov/.github/workflows/release.yml@refs/heads/main"
	repo, ref := newCMSUnboundCommitRepo(t, identity)

	policy := &Policy{
		RequiredSigners: map[string][]string{
			ref: {identity},
		},
	}

	status, err := VerifySignerPolicy(repo, ref, policy, VerifyOptions{TargetRef: ref})
	require.NoError(t, err)

	assert.False(t, status.AllSigned, "transparency-unbound signer must not satisfy required signers")
	assert.Empty(t, status.VerifiedSigners, "transparency-unbound signer must not be collected")
	assert.Contains(t, status.MissingSigners, identity)
}
