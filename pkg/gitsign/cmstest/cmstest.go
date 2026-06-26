// Package cmstest provides test-only helpers for building structurally valid
// CMS-signed git commits. It exists so packages outside pkg/gitsign (notably
// pkg/gitpolicy) can build CMS-signed-but-transparency-unbound commits to test
// the transparency-exclusion behavior, without duplicating the PKI/CMS plumbing
// and without hitting any live Sigstore/Rekor/TSA service.
//
// Commits produced here carry a real CMS "SIGNED MESSAGE" signature with a
// self-signed leaf and NO RFC3161 timestamp token, so gitsign.VerifyCommit
// reaches the new transparency check and returns Verified=false (transparency-
// unbound) — exactly the case that must be excluded from signed-commit counts
// and signer policy.
package cmstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

var oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// SignerEmail is the email SAN baked into the test signer leaf.
const SignerEmail = "test-signer@example.com"

// AddUnboundSignedCommit appends a CMS-signed (but transparency-unbound) commit
// to the repo at repoDir on top of HEAD and returns the new commit hash. The
// signature is a real detached CMS "SIGNED MESSAGE" with a self-signed leaf and
// no RFC3161 timestamp token.
func AddUnboundSignedCommit(t *testing.T, repoDir, message, fileContent string) plumbing.Hash {
	t.Helper()

	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "signed.txt"), []byte(fileContent), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := wt.Add("signed.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	h, err := wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test Signer",
			Email: "test@example.com",
			When:  time.Now().UTC(),
		},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	commit, err := repo.CommitObject(h)
	if err != nil {
		t.Fatalf("commit object: %v", err)
	}

	sigPEM := signCommit(t, commit)
	commit.PGPSignature = sigPEM
	obj := repo.Storer.NewEncodedObject()
	if err := commit.Encode(obj); err != nil {
		t.Fatalf("encode signed commit: %v", err)
	}
	newHash, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		t.Fatalf("store signed commit: %v", err)
	}

	// repoint the branch ref at the signed commit so range/walk see it.
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	ref := plumbing.NewHashReference(head.Name(), newHash)
	if err := repo.Storer.SetReference(ref); err != nil {
		t.Fatalf("set ref: %v", err)
	}
	return newHash
}

func signCommit(t *testing.T, commit *object.Commit) string {
	t.Helper()

	caCert, caKey := mkCA(t)
	leafCert, leafKey := mkLeaf(t, caCert, caKey)

	obj := &plumbing.MemoryObject{}
	if err := commit.EncodeWithoutSignature(obj); err != nil {
		t.Fatalf("encode without sig: %v", err)
	}
	r, err := obj.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	content, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}

	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatalf("new signed data: %v", err)
	}
	sd.SetDigestAlgorithm(oidDigestSHA256)
	if err := sd.AddSignerChain(leafCert, leafKey, []*x509.Certificate{caCert}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("add signer: %v", err)
	}
	sd.Detach()
	cmsDER, err := sd.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: cmsDER}))
}

func mkCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cmstest-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

func mkLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano() + 1),
		Subject:        pkix.Name{CommonName: "cmstest-signer"},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(1 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: []string{SignerEmail},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert, key
}
