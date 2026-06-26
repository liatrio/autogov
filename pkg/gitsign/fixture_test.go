package gitsign

// In-package test helpers that build structurally valid CMS-signed commits.
//
// The repo ships no CMS-signed fixtures (only unsigned go-git commits), and an
// unsigned commit short-circuits to Verified=false before the cms/transparency
// path runs — so it cannot exercise the new transparency-exclusion logic. These
// helpers mint a self-signed "Fulcio" leaf + an in-process test TSA so the new
// timestamp-pinning and transparency-gating paths can be tested without hitting
// any live Sigstore/Rekor/TSA service. They also override the buildFulcioPool /
// loadTSARoots seams to trust the test PKI.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// testPKI holds a self-signed CA + leaf (the "Fulcio" signer) and a separate
// TSA CA + leaf used to mint RFC3161 timestamp tokens.
type testPKI struct {
	fulcioCA *x509.Certificate
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
	tsaCA    *x509.Certificate
	tsaCert  *x509.Certificate
	tsaKey   *ecdsa.PrivateKey
}

// newTestPKI builds a fresh PKI. leafNotBefore/leafNotAfter control the signer
// leaf's validity window so tests can simulate an expired-by-now leaf.
func newTestPKI(t *testing.T, leafNotBefore, leafNotAfter time.Time) *testPKI {
	t.Helper()

	// CN contains "github" so root.DetectTrustedRootFromCert attributes the leaf
	// to the GitHub-internal backend (the TSA path under test). A backend that
	// cannot be attributed now fails closed by design.
	fulcioCA, fulcioCAKey := mkCA(t, "test github fulcio ca")
	leafCert, leafKey := mkLeaf(t, "test-signer", fulcioCA, fulcioCAKey, leafNotBefore, leafNotAfter)

	tsaCA, tsaCAKey := mkCA(t, "test-tsa-ca")
	tsaCert, tsaKey := mkTSALeaf(t, "test-tsa", tsaCA, tsaCAKey)

	return &testPKI{
		fulcioCA: fulcioCA,
		leafCert: leafCert,
		leafKey:  leafKey,
		tsaCA:    tsaCA,
		tsaCert:  tsaCert,
		tsaKey:   tsaKey,
	}
}

// install points the buildFulcioPool and loadTSARoots seams at this PKI and
// restores them when the test ends.
func (p *testPKI) install(t *testing.T) {
	t.Helper()
	origFulcio := buildFulcioPool
	origTSA := loadTSARoots
	t.Cleanup(func() {
		buildFulcioPool = origFulcio
		loadTSARoots = origTSA
	})

	buildFulcioPool = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(p.fulcioCA)
		return pool, nil
	}
	loadTSARoots = func() (*x509.CertPool, *x509.CertPool, error) {
		roots := x509.NewCertPool()
		roots.AddCert(p.tsaCA)
		return roots, x509.NewCertPool(), nil
	}
}

func mkCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

func mkLeaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// gitsign identity lives in an email SAN for human signers.
		EmailAddresses: []string{"test-signer@example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}

func mkTSALeaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen TSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 2),
		Subject:      pkix.Name{CommonName: cn},
		// give the TSA a wide validity so a backdated/forward genTime still
		// chains; the point under test is the signer leaf window, not the TSA's.
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create TSA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse TSA cert: %v", err)
	}
	return cert, key
}

// mkTSAToken mints an RFC3161 timestamp token over signatureValue with the
// given genTime, signed by the test TSA.
func (p *testPKI) mkTSAToken(t *testing.T, signatureValue []byte, genTime time.Time) []byte {
	t.Helper()
	tsr := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		Time:              genTime,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		AddTSACertificate: true,
	}
	digest := sha256.Sum256(signatureValue)
	tsr.HashedMessage = digest[:]

	respDER, err := tsr.CreateResponseWithOpts(p.tsaCert, p.tsaKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("create TSA response: %v", err)
	}
	// extract the bare token from the response (our verify path calls
	// timestamp.Parse on the token, not ParseResponse on the response).
	token := extractTokenFromResponse(t, respDER)
	return token
}

// signCommit builds a detached CMS over the commit's signature-stripped
// encoding and returns the PEM "SIGNED MESSAGE" string. If withTSA is true a
// verifiable RFC3161 token (genTime = tsaGenTime) is added as an unauthenticated
// attribute over the signature value.
func (p *testPKI) signCommit(t *testing.T, commit *object.Commit, withTSA bool, tsaGenTime time.Time) string {
	t.Helper()

	content, err := encodeCommitWithoutSignature(commit)
	if err != nil {
		t.Fatalf("encode commit: %v", err)
	}

	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatalf("new signed data: %v", err)
	}
	sd.SetDigestAlgorithm(oidDigestSHA256())
	if err := sd.AddSignerChain(p.leafCert, p.leafKey, []*x509.Certificate{p.fulcioCA}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("add signer: %v", err)
	}
	sd.Detach()
	cmsDER, err := sd.Finish()
	if err != nil {
		t.Fatalf("finish signed data: %v", err)
	}

	if withTSA {
		sigValue := cmsSignatureValueForTest(t, cmsDER)
		token := p.mkTSAToken(t, sigValue, tsaGenTime)
		cmsDER = addTSAToken(t, cmsDER, token)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: cmsDER})
	return string(pemBytes)
}

// storeSignedCommit takes an unsigned commit, attaches sigPEM, re-encodes, and
// stores the object so it can be resolved by hash. Returns the new hash.
func storeSignedCommit(t *testing.T, repo *git.Repository, commit *object.Commit, sigPEM string) plumbing.Hash {
	t.Helper()
	commit.PGPSignature = sigPEM
	obj := repo.Storer.NewEncodedObject()
	if err := commit.Encode(obj); err != nil {
		t.Fatalf("encode signed commit: %v", err)
	}
	h, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		t.Fatalf("store signed commit: %v", err)
	}
	return h
}

// makeUnsignedCommit creates a repo with a single unsigned commit and returns
// the repo plus the loaded *object.Commit (so a signature can be attached).
func makeUnsignedCommit(t *testing.T) (*git.Repository, *object.Commit) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := wt.Add("README.md"); err != nil {
		t.Fatalf("add: %v", err)
	}
	h, err := wt.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	commit, err := repo.CommitObject(h)
	if err != nil {
		t.Fatalf("commit object: %v", err)
	}
	return repo, commit
}

// --- small wrappers to keep imports tidy in the fixture file ---

func oidDigestSHA256() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
}

// cmsSignatureValueForTest extracts the first signer's EncryptedDigest from a
// CMS DER, so the test TSA token can be minted over the same bytes the
// production verifier binds against.
func cmsSignatureValueForTest(t *testing.T, cmsDER []byte) []byte {
	t.Helper()
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		t.Fatalf("unmarshal CMS contentInfo: %v", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal CMS signedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 || len(sd.SignerInfos[0].EncryptedDigest) == 0 {
		t.Fatalf("CMS has no signer signature value")
	}
	return sd.SignerInfos[0].EncryptedDigest
}

// extractTokenFromResponse pulls the bare TimeStampToken (a ContentInfo) out of
// a DER-encoded RFC3161 response.
func extractTokenFromResponse(t *testing.T, respDER []byte) []byte {
	t.Helper()
	var resp struct {
		Status struct {
			Status       int
			StatusString []string       `asn1:"optional"`
			FailInfo     asn1.BitString `asn1:"optional"`
		}
		TimeStampToken asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatalf("unmarshal TSA response: %v", err)
	}
	return resp.TimeStampToken.FullBytes
}

// addTSAToken re-serializes the CMS with the RFC3161 token added as an
// unauthenticated attribute on the first signer. It re-parses the CMS into the
// mirror structs, appends the attribute, and re-marshals.
func addTSAToken(t *testing.T, cmsDER, token []byte) []byte {
	t.Helper()

	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		t.Fatalf("unmarshal CMS contentInfo: %v", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal CMS signedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		t.Fatalf("CMS has no signers")
	}

	// SET OF AttributeValue { token }
	setBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      token,
	})
	if err != nil {
		t.Fatalf("marshal attr value set: %v", err)
	}
	sd.SignerInfos[0].UnauthenticatedAttributes = []cmsAttribute{
		{
			Type:  oidAttributeTimeStampToken,
			Value: asn1.RawValue{FullBytes: setBytes},
		},
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal signedData: %v", err)
	}
	ci.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdBytes,
	}
	out, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("marshal contentInfo: %v", err)
	}
	return out
}
