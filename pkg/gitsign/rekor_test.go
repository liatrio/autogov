package gitsign

// Tests + in-package fixtures for the public-good Rekor inclusion path.
//
// gitsign embeds a serialized Rekor TransparencyLogEntry in the CMS unsigned
// attributes (OID 1.3.6.1.4.1.57264.3.1) for offline verification. The repo
// ships no real public-good signed fixtures, so these helpers mint a self-signed
// "sigstore" Fulcio leaf and a self-signed transparency-log key, then build a
// structurally valid entry whose Signed Entry Timestamp (inclusion promise)
// verifies offline against the injected test log key. No live Sigstore/Rekor
// service is contacted.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/digitorus/pkcs7"
	"github.com/go-git/go-git/v5/plumbing/object"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgtlog "github.com/sigstore/sigstore-go/pkg/tlog"
	"google.golang.org/protobuf/proto"

	"github.com/liatrio/autogov/pkg/root"
)

// rekorTestPKI holds a public-good "sigstore" Fulcio leaf and a self-signed
// transparency-log signing key used to mint a verifiable inclusion promise.
type rekorTestPKI struct {
	fulcioCA *x509.Certificate
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey

	logKey         *ecdsa.PrivateKey
	logID          []byte
	integratedTime time.Time
	logIndex       int64
}

// newRekorTestPKI builds a public-good PKI. The CA Subject CN contains "sigstore"
// so root.DetectTrustedRootFromCert attributes the leaf to the public-good
// backend (the Rekor path under test). leafNotBefore/leafNotAfter set the signer
// leaf validity window so tests can pin verification to the integrated time.
func newRekorTestPKI(t *testing.T, leafNotBefore, leafNotAfter, integratedTime time.Time) *rekorTestPKI {
	t.Helper()
	ca, caKey := mkCA(t, "sigstore test fulcio ca")
	leaf, leafKey := mkLeaf(t, "test-signer", ca, caKey, leafNotBefore, leafNotAfter)

	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen log key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal log pub: %v", err)
	}
	sum := sha256.Sum256(pubDER)

	return &rekorTestPKI{
		fulcioCA:       ca,
		leafCert:       leaf,
		leafKey:        leafKey,
		logKey:         logKey,
		logID:          sum[:],
		integratedTime: integratedTime,
		logIndex:       7,
	}
}

// install points buildFulcioPool at the sigstore test CA and loadRekorVerifiers
// at the test transparency-log key, restoring both when the test ends.
func (p *rekorTestPKI) install(t *testing.T) {
	t.Helper()
	origFulcio := buildFulcioPool
	origRekor := loadRekorVerifiers
	t.Cleanup(func() {
		buildFulcioPool = origFulcio
		loadRekorVerifiers = origRekor
	})

	buildFulcioPool = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(p.fulcioCA)
		return pool, nil
	}
	loadRekorVerifiers = func() (map[string]*sgroot.TransparencyLog, error) {
		return map[string]*sgroot.TransparencyLog{
			hex.EncodeToString(p.logID): {
				ID:                  p.logID,
				PublicKey:           &p.logKey.PublicKey,
				SignatureHashFunc:   crypto.SHA256,
				ValidityPeriodStart: time.Unix(0, 0),
			},
		}, nil
	}
}

// signCommitWithRekor mints a detached CMS over the commit and embeds a Rekor
// TransparencyLogEntry whose Signed Entry Timestamp verifies against the test log
// key. The canonical body is cleared before embedding, exactly as gitsign does,
// so the verifier exercises the recompute path.
func (p *rekorTestPKI) signCommitWithRekor(t *testing.T, commit *object.Commit) string {
	t.Helper()
	return p.buildRekorSig(t, commit, rekorSigOpts{})
}

// rekorSigOpts controls how buildRekorSig deviates from a valid signature, so the
// negative cases share one builder.
type rekorSigOpts struct {
	tamperSET           bool // corrupt the SET so VerifySET fails
	zeroIntegratedTime  bool // omit the integrated time (AC5d)
	bogusInclusionProof bool // attach a present-but-invalid inclusion proof
}

// buildRekorSig mints a detached CMS over the commit and embeds a Rekor
// TransparencyLogEntry whose SET is signed by the test log key, applying any
// deviations in opts. The canonical body is cleared before embedding, exactly as
// gitsign does, so the verifier exercises the recompute path.
func (p *rekorTestPKI) buildRekorSig(t *testing.T, commit *object.Commit, opts rekorSigOpts) string {
	t.Helper()

	cmsDER := mintBareCMS(t, p, commit)
	sigValue := cmsSignatureValueForTest(t, cmsDER)
	signedAttrs := signedAttrsForTest(t, cmsDER)

	// recompute the canonical body the SET commits to (also self-checks that
	// signedAttrs are the exact bytes the CMS signature covered).
	body, err := canonicalHashedRekordBody(context.Background(), signedAttrs, sigValue, p.leafCert)
	if err != nil {
		t.Fatalf("canonical body: %v", err)
	}

	integ := p.integratedTime.Unix()
	if opts.zeroIntegratedTime {
		integ = 0
	}

	set := p.signSETAt(t, body, integ)
	if opts.tamperSET && len(set) > 0 {
		set[len(set)-1] ^= 0xFF
	}

	tle := &rekorpb.TransparencyLogEntry{
		LogIndex:         p.logIndex,
		LogId:            &protocommon.LogId{KeyId: p.logID},
		KindVersion:      &rekorpb.KindVersion{Kind: "hashedrekord", Version: "0.0.1"},
		IntegratedTime:   integ,
		InclusionPromise: &rekorpb.InclusionPromise{SignedEntryTimestamp: set},
		// CanonicalizedBody intentionally left nil, matching gitsign's ToAttributes.
	}
	if opts.bogusInclusionProof {
		// syntactically valid (passes ParseTransparencyLogEntry) but the root hash
		// does not match the leaf, so tlog.VerifyInclusion fails — exercising the
		// HasInclusionProof()/rekorLogVerifier/VerifyInclusion branch + fail-closed.
		tle.InclusionProof = &rekorpb.InclusionProof{
			LogIndex:   p.logIndex,
			RootHash:   make([]byte, 32),
			TreeSize:   1,
			Checkpoint: &rekorpb.Checkpoint{Envelope: "bogus-origin\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"},
		}
	}
	protoBytes, err := proto.Marshal(tle)
	if err != nil {
		t.Fatalf("marshal tle: %v", err)
	}

	cmsDER = addRekorEntry(t, cmsDER, protoBytes)
	return string(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: cmsDER}))
}

// signSETAt produces a Signed Entry Timestamp over the canonical Rekor payload
// with the given integrated time, matching exactly what sgtlog.VerifySET
// reconstructs and verifies.
func (p *rekorTestPKI) signSETAt(t *testing.T, canonicalBody []byte, integratedTime int64) []byte {
	t.Helper()
	payload := sgtlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(canonicalBody),
		IntegratedTime: integratedTime,
		LogIndex:       p.logIndex,
		LogID:          hex.EncodeToString(p.logID),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal rekor payload: %v", err)
	}
	canon, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatalf("canonicalize rekor payload: %v", err)
	}
	h := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, p.logKey, h[:])
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return sig
}

// signedAttrsForTest extracts the marshaled SignedAttrs the CMS signature covers,
// reusing the production raw-CMS parse + tag transform.
func signedAttrsForTest(t *testing.T, cmsDER []byte) []byte {
	t.Helper()
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		t.Fatalf("unmarshal contentInfo: %v", err)
	}
	var sd cmsSignedDataRaw
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal signedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		t.Fatalf("no signers")
	}
	attrs, ok := marshaledSignedAttrs(sd.SignerInfos[0].AuthenticatedAttributes)
	if !ok {
		t.Fatalf("no signed attrs")
	}
	return attrs
}

// addRekorEntry re-serializes the CMS with the serialized TransparencyLogEntry
// added as an unauthenticated attribute (OID 1.3.6.1.4.1.57264.3.1) on the first
// signer, encoded as a SET OF { OCTET STRING } exactly as gitsign's ToAttributes
// produces it. Mirrors addTSAToken.
func addRekorEntry(t *testing.T, cmsDER, protoBytes []byte) []byte {
	t.Helper()

	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		t.Fatalf("unmarshal contentInfo: %v", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal signedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		t.Fatalf("no signers")
	}

	octet, err := asn1.Marshal(protoBytes) // []byte → OCTET STRING
	if err != nil {
		t.Fatalf("marshal octet: %v", err)
	}
	setBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      octet,
	})
	if err != nil {
		t.Fatalf("marshal attr set: %v", err)
	}
	sd.SignerInfos[0].UnauthenticatedAttributes = []cmsAttribute{
		{
			Type:  oidAttributeRekorEntry,
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

// --- tests ---

func TestVerifyCommit_PublicGood_ValidRekorEntry(t *testing.T) {
	now := time.Now()
	integ := now.Add(-30 * time.Minute)
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), integ)
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)
	sig := pki.signCommitWithRekor(t, commit)
	h := storeSignedCommit(t, repo, commit, sig)

	result, err := VerifyCommit(repo, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified, got false (err=%q)", result.ErrorMsg)
	}
	if !result.TransparencyVerified {
		t.Fatalf("expected TransparencyVerified")
	}
	if result.RekorLogIndex != pki.logIndex {
		t.Fatalf("RekorLogIndex = %d, want %d", result.RekorLogIndex, pki.logIndex)
	}
	if !result.Timestamp.Equal(integ.Truncate(time.Second)) {
		t.Fatalf("Timestamp = %v, want integrated time %v", result.Timestamp, integ.Truncate(time.Second))
	}
	if result.Signer != "test-signer@example.com" {
		t.Fatalf("Signer = %q", result.Signer)
	}
}

// proves the cert chain is validated at the Rekor integrated time, not wall-clock
// now: the leaf window contains now (so the CMS signingTime attribute is in-range)
// but the integrated time is far in the past, before the leaf NotBefore — so
// verification fails only because the chain is pinned to the integrated time.
// (The mirror-image positive case — an expired-vs-now leaf valid at the
// integrated time — holds in production, where a real gitsign signingTime falls
// inside the past leaf window; it is not unit-testable here because the digitorus
// signer stamps signingTime = now, matching the existing TSA tests' constraint.)
func TestVerifyCommit_PublicGood_ChainValidatedAtIntegratedTime(t *testing.T) {
	now := time.Now()
	integ := now.Add(-240 * time.Hour) // 10 days ago, before the leaf NotBefore
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), integ)
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)
	sig := pki.signCommitWithRekor(t, commit)
	h := storeSignedCommit(t, repo, commit, sig)

	result, err := VerifyCommit(repo, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected not Verified (chain pinned to integrated time, which precedes leaf NotBefore)")
	}
}

// a validly-included but unrelated entry grafted onto a different commit's
// signature must be rejected by the binding check.
func TestVerifyCommit_PublicGood_GraftedEntryRejected(t *testing.T) {
	now := time.Now()
	integ := now.Add(-30 * time.Minute)
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), integ)
	pki.install(t)

	// build a valid signature+entry for commit A.
	repoA, commitA := makeUnsignedCommit(t)
	sigA := pki.signCommitWithRekor(t, commitA)
	_ = storeSignedCommit(t, repoA, commitA, sigA)
	entryProto, _, _, ok := extractRekorEntry(decodeSignedMessage(t, sigA))
	if !ok {
		t.Fatalf("extract entry from sigA failed")
	}

	// build a fresh signature for commit B and graft A's entry onto it.
	repoB, commitB := makeUnsignedCommit(t)
	cmsB := mintBareCMS(t, pki, commitB)
	cmsB = addRekorEntry(t, cmsB, entryProto)
	sigB := string(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: cmsB}))
	h := storeSignedCommit(t, repoB, commitB, sigB)

	result, err := VerifyCommit(repoB, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected not Verified (grafted unrelated entry)")
	}
}

// a tampered Signed Entry Timestamp must fail SET verification — and the error
// must name the SET, isolating it as the rejection cause (not, say, a binding or
// chain failure).
func TestVerifyCommit_PublicGood_TamperedSETRejected(t *testing.T) {
	now := time.Now()
	integ := now.Add(-30 * time.Minute)
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), integ)
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)
	sig := pki.buildRekorSig(t, commit, rekorSigOpts{tamperSET: true})
	h := storeSignedCommit(t, repo, commit, sig)

	result, err := VerifyCommit(repo, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected not Verified (tampered SET)")
	}
	if !strings.Contains(result.ErrorMsg, "signed entry timestamp") {
		t.Fatalf("expected SET verification failure, got ErrorMsg=%q", result.ErrorMsg)
	}
}

// a present-but-invalid inclusion proof must fail closed. The SET verifies, so
// this isolates the inclusion-proof branch (HasInclusionProof → rekorLogVerifier
// → tlog.VerifyInclusion) and proves a bad proof is rejected rather than ignored.
func TestVerifyCommit_PublicGood_InvalidInclusionProofRejected(t *testing.T) {
	now := time.Now()
	integ := now.Add(-30 * time.Minute)
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), integ)
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)
	sig := pki.buildRekorSig(t, commit, rekorSigOpts{bogusInclusionProof: true})
	h := storeSignedCommit(t, repo, commit, sig)

	result, err := VerifyCommit(repo, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected not Verified (invalid inclusion proof)")
	}
	if !strings.Contains(result.ErrorMsg, "inclusion proof") {
		t.Fatalf("expected inclusion-proof failure, got ErrorMsg=%q", result.ErrorMsg)
	}
}

// an entry with no integrated time fails closed (AC5d).
func TestVerifyCommit_PublicGood_NoIntegratedTimeFailsClosed(t *testing.T) {
	now := time.Now()
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), now.Add(-30*time.Minute))
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)
	sig := pki.buildRekorSig(t, commit, rekorSigOpts{zeroIntegratedTime: true})
	h := storeSignedCommit(t, repo, commit, sig)

	result, err := VerifyCommit(repo, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected not Verified (no integrated time)")
	}
}

// a public-good signature with no embedded entry fails closed.
func TestVerifyCommit_PublicGood_MissingEntryFailsClosed(t *testing.T) {
	now := time.Now()
	pki := newRekorTestPKI(t, now.Add(-time.Hour), now.Add(time.Hour), now.Add(-30*time.Minute))
	pki.install(t)

	repo, commit := makeUnsignedCommit(t)
	cms := mintBareCMS(t, pki, commit) // no rekor attribute embedded
	sig := string(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: cms}))
	h := storeSignedCommit(t, repo, commit, sig)

	result, err := VerifyCommit(repo, h.String(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected not Verified (no embedded entry)")
	}
	if result.TransparencyVerified {
		t.Fatalf("expected TransparencyVerified false")
	}
}

// TestVerifyRekorInclusion_RealPublicGoodFixture validates extraction +
// canonical-body recompute + SET and inclusion-proof verification against a REAL
// public-good gitsign commit, checked against the REAL embedded trusted root (no
// test seam). This is the byte-format de-risk: it proves real gitsign emits what
// we parse and that our recomputed HashedRekord body verifies against the live
// rekor.sigstore.dev key — and, since this entry carries a full inclusion proof,
// it exercises the valid-proof path the synthetic tests cannot mint.
//
// Fixture provenance: chainguard-dev/sdk@7d6ba51f1c73f2f799b74ccceb5174506c796fd4
// (public-good sigstore.dev Fulcio; embedded OID 1.3.6.1.4.1.57264.3.1 with an
// inclusion promise AND a full inclusion proof; rekor logIndex 1969107809,
// integratedTime 2026-06-26T15:42:37Z). Refresh from a newer commit if the
// embedded public trusted root ever drops the rekor key that signed it.
func TestVerifyRekorInclusion_RealPublicGoodFixture(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/real-public-good-gitsign.pem")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "SIGNED MESSAGE" {
		t.Fatalf("fixture is not a SIGNED MESSAGE PEM")
	}

	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}
	signerCert := p7.GetOnlySigner()
	if signerCert == nil {
		t.Fatalf("no signer cert in fixture")
	}

	// the fixture must route to the public-good backend (Fulcio issuer is
	// sigstore.dev, even though the OIDC issuer extension is GitHub Actions).
	src, err := root.DetectTrustedRootFromCert(encodeCertPEM(signerCert))
	if err != nil {
		t.Fatalf("detect trusted root: %v", err)
	}
	if src != root.TrustedRootSourcePublic {
		t.Fatalf("fixture backend = %q, want public", src)
	}

	entryProto, sigValue, signedAttrs, ok := extractRekorEntry(block.Bytes)
	if !ok {
		t.Fatalf("extractRekorEntry: no embedded entry found in real fixture")
	}

	// independently read the entry's log key + integrated time for the
	// environmental pre-check and the result assertions.
	tle := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(entryProto, tle); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if tle.GetInclusionProof() == nil {
		t.Fatalf("fixture entry unexpectedly has no inclusion proof")
	}

	// environmental skip (NOT a code failure): if autogov's embedded public
	// trusted-root snapshot no longer carries the rekor key that signed this
	// entry, or it isn't valid at the entry's integrated time, the fixture is
	// stale relative to the snapshot — skip with guidance rather than fail.
	rekorLogs, err := loadRekorVerifiers()
	if err != nil {
		t.Fatalf("load rekor verifiers: %v", err)
	}
	keyID := hex.EncodeToString(tle.GetLogId().GetKeyId())
	tl, present := rekorLogs[keyID]
	if !present {
		t.Skipf("embedded public trusted root has no rekor key %s; refresh the fixture from a newer commit", keyID)
	}
	integ := time.Unix(tle.IntegratedTime, 0)
	if tl.ValidityPeriodStart.After(integ) || (!tl.ValidityPeriodEnd.IsZero() && tl.ValidityPeriodEnd.Before(integ)) {
		t.Skipf("embedded rekor key not valid at fixture integrated time %v; refresh the fixture", integ)
	}

	// the embedded root CAN verify this entry — so any failure now is a code bug,
	// not an environmental one.
	gotTime, gotIndex, err := verifyRekorInclusion(entryProto, sigValue, signedAttrs, signerCert)
	if err != nil {
		t.Fatalf("verifyRekorInclusion on real fixture: %v", err)
	}
	if gotIndex != tle.LogIndex {
		t.Fatalf("logIndex = %d, want %d", gotIndex, tle.LogIndex)
	}
	if gotTime.Unix() != tle.IntegratedTime {
		t.Fatalf("integratedTime = %d, want %d", gotTime.Unix(), tle.IntegratedTime)
	}
}

// --- small helpers for the negative cases ---

// mintBareCMS produces a detached CMS over the commit with no Rekor attribute.
func mintBareCMS(t *testing.T, p *rekorTestPKI, commit *object.Commit) []byte {
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
		t.Fatalf("finish: %v", err)
	}
	return cmsDER
}

func decodeSignedMessage(t *testing.T, sigPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(sigPEM))
	if block == nil {
		t.Fatalf("decode PEM")
	}
	return block.Bytes
}
