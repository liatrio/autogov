package gitsign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgtlog "github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/proto"

	"github.com/liatrio/autogov/pkg/root"
)

// oidAttributeRekorEntry is the OID under which gitsign stores a proto-serialized
// Rekor TransparencyLogEntry as a CMS unauthenticated attribute on the SignerInfo,
// enabling offline transparency-log verification. See sigstore/rekor oid-info.md
// (1.3.6.1.4.1.57264.3.1 = "Proto serialized TransparencyLogEntry").
var oidAttributeRekorEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}

// --- raw CMS mirror that captures the SignedAttrs bytes verbatim ---
//
// The Rekor HashedRekord for a gitsign signature is computed over the marshaled
// CMS SignedAttrs (NOT the git object body): hashedrekord.data.hash =
// sha256(SignedAttrs), signature = the SignerInfo EncryptedDigest, publicKey =
// the signer cert. So to recompute the canonical entry body (gitsign clears it
// before embedding) we need the exact bytes the CMS signature covered. We
// capture the [0] IMPLICIT AuthenticatedAttributes element raw and convert it to
// its "marshaled for verification" form (the universal SET OF encoding) by
// flipping the leading tag byte — the same transform CMS verifiers apply per
// RFC 5652 §5.4. cmsContentInfo / cmsAttribute / cmsIssuerAndSerial are shared
// with transparency.go.

type cmsSignerInfoRaw struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     cmsIssuerAndSerial
	DigestAlgorithm           asn1.RawValue
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm asn1.RawValue
	EncryptedDigest           []byte
	UnauthenticatedAttributes []cmsAttribute `asn1:"optional,omitempty,tag:1"`
}

type cmsSignedDataRaw struct {
	Version                    int
	DigestAlgorithmIdentifiers []asn1.RawValue `asn1:"set"`
	ContentInfo                asn1.RawValue
	Certificates               asn1.RawValue      `asn1:"optional,tag:0"`
	CRLs                       []asn1.RawValue    `asn1:"optional,tag:1"`
	SignerInfos                []cmsSignerInfoRaw `asn1:"set"`
}

// extractRekorEntry re-parses the raw CMS bytes and returns, for the first
// SignerInfo carrying an embedded Rekor TransparencyLogEntry: the serialized
// entry proto, that signer's EncryptedDigest (signature value), and the marshaled
// SignedAttrs the signature was computed over (the HashedRekord artifact). All
// three come from the SAME SignerInfo so the entry, signature, and artifact
// cannot be mixed across signers. Returns ok=false when no embedded entry is
// present (e.g. a legacy "online" gitsign signature or a non-gitsign signature).
func extractRekorEntry(cmsDER []byte) (entryProto, sigValue, signedAttrs []byte, ok bool) {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		return nil, nil, nil, false
	}
	if !ci.ContentType.Equal(oidSignedData) || len(ci.Content.Bytes) == 0 {
		return nil, nil, nil, false
	}

	var sd cmsSignedDataRaw
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, nil, nil, false
	}

	for _, si := range sd.SignerInfos {
		for _, attr := range si.UnauthenticatedAttributes {
			if !attr.Type.Equal(oidAttributeRekorEntry) {
				continue
			}
			// attr.Value is a SET OF AttributeValue; the entry is the single
			// OCTET STRING element holding the serialized proto.
			var pb []byte
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &pb); err != nil {
				return nil, nil, nil, false
			}
			if len(si.EncryptedDigest) == 0 {
				return nil, nil, nil, false
			}
			attrs, attrsOK := marshaledSignedAttrs(si.AuthenticatedAttributes)
			if !attrsOK {
				return nil, nil, nil, false
			}
			return pb, si.EncryptedDigest, attrs, true
		}
	}
	return nil, nil, nil, false
}

// marshaledSignedAttrs converts the [0] IMPLICIT AuthenticatedAttributes element
// to the form the CMS signature was actually computed over: the universal SET OF
// encoding. The only difference is the outer tag (context [0] constructed = 0xA0
// → universal SET constructed = 0x31); the length and contents are identical, so
// the leading byte is replaced and the rest copied verbatim. Returns ok=false
// when no authenticated attributes are present (an unsigned-attrs-only signature
// cannot anchor a HashedRekord).
func marshaledSignedAttrs(rawAttrs asn1.RawValue) ([]byte, bool) {
	if len(rawAttrs.FullBytes) == 0 || rawAttrs.FullBytes[0] != 0xA0 {
		return nil, false
	}
	out := make([]byte, len(rawAttrs.FullBytes))
	copy(out, rawAttrs.FullBytes)
	out[0] = 0x31 // universal SET OF (constructed)
	return out, true
}

// canonicalHashedRekordBody recomputes the canonicalized Rekor HashedRekord entry
// body from the signed message (the marshaled CMS SignedAttrs), the signature
// value, and the signer certificate. gitsign clears the canonical body before
// embedding the entry, so the verifier must recompute it; the recomputation also
// cryptographically re-verifies that the signature covers sha256(message) under
// the certificate's key (rekor's V001Entry.validate). Mirrors gitsign's
// internal/rekor/oid.canonicalHashedRekordBody.
func canonicalHashedRekordBody(ctx context.Context, message, sig []byte, cert *x509.Certificate) ([]byte, error) {
	hash := sha256.Sum256(message)
	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, fmt.Errorf("marshal cert: %w", err)
	}
	re := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: new("sha256"),
					Value:     new(hex.EncodeToString(hash[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(sig),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}
	body, err := rekortypes.CanonicalizeEntry(ctx, re)
	if err != nil {
		return nil, fmt.Errorf("canonicalize hashedrekord: %w", err)
	}
	return body, nil
}

// loadRekorVerifiers returns the public-good trusted root's Rekor transparency
// log verifiers, keyed by hex(logID) as sgtlog.VerifySET expects. It is a package
// var so tests can inject a self-signed test log key.
var loadRekorVerifiers = func() (map[string]*sgroot.TransparencyLog, error) {
	tr, err := sgroot.NewTrustedRootFromJSON(root.GetPublicTrustedRoot())
	if err != nil {
		return nil, fmt.Errorf("parse public trusted root: %w", err)
	}
	logs := tr.RekorLogs()
	if len(logs) == 0 {
		return nil, fmt.Errorf("no rekor logs in public trusted root")
	}
	return logs, nil
}

// verifyRekorInclusion verifies the embedded public-good Rekor entry for a gitsign
// signature and returns the trusted integrated time and log index.
//
// It (1) deserializes the entry, (2) recomputes the canonical HashedRekord body
// from the SignedAttrs + signature + cert (which also re-verifies the signature),
// (3) verifies the Signed Entry Timestamp (inclusion promise) against the trusted
// log key — the signed metadata that anchors the integrated time — and the
// inclusion proof when one is present, and (4) binds the entry to THIS signature
// and signer certificate so a validly-logged but unrelated entry cannot be
// grafted on. Any failure returns an error, leaving the caller fail-closed.
func verifyRekorInclusion(entryProto, sigValue, signedAttrs []byte, signerCert *x509.Certificate) (time.Time, int64, error) {
	tle := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(entryProto, tle); err != nil {
		return time.Time{}, 0, fmt.Errorf("unmarshal transparency log entry: %w", err)
	}

	// gitsign clears CanonicalizedBody on embedding; recompute it so the Merkle
	// leaf / SET payload body match the log.
	body, err := canonicalHashedRekordBody(context.Background(), signedAttrs, sigValue, signerCert)
	if err != nil {
		return time.Time{}, 0, err
	}
	tle.CanonicalizedBody = body

	entry, err := sgtlog.ParseTransparencyLogEntry(tle)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parse transparency log entry: %w", err)
	}

	// the SET (inclusion promise) is the signed metadata that makes the integrated
	// time trustworthy; require and verify it. an inclusion proof alone is not
	// signed metadata and must not be used to anchor time.
	if !entry.HasInclusionPromise() {
		return time.Time{}, 0, fmt.Errorf("entry carries no inclusion promise (SET)")
	}
	rekorLogs, err := loadRekorVerifiers()
	if err != nil {
		return time.Time{}, 0, err
	}
	if err := sgtlog.VerifySET(entry, rekorLogs); err != nil {
		return time.Time{}, 0, fmt.Errorf("verify signed entry timestamp: %w", err)
	}

	// when an inclusion proof is also present, verify it (offline) for defense in
	// depth — a present-but-invalid proof fails closed.
	if entry.HasInclusionProof() {
		verifier, err := rekorLogVerifier(rekorLogs, entry.LogKeyID())
		if err != nil {
			return time.Time{}, 0, err
		}
		if err := sgtlog.VerifyInclusion(entry, verifier); err != nil {
			return time.Time{}, 0, fmt.Errorf("verify inclusion proof: %w", err)
		}
	}

	// Anti-graft binding: a validly-logged entry from an UNRELATED signature must
	// not verify when grafted onto this commit. That binding is enforced by
	// VerifySET above, NOT by the equality checks below: VerifySET reconstructs
	// the log-signed payload over `entry.Body()` == base64(CanonicalizedBody), and
	// we overwrote CanonicalizedBody with `body` recomputed from THIS commit's
	// signedAttrs + sigValue + signerCert. So the log-key signature only verifies
	// when the grafted entry's SET was signed over a body identical to the one we
	// recomputed here — i.e. when the entry actually belongs to this signature.
	// A grafted entry's SET was signed over a different body and fails VerifySET.
	//
	// The two equality checks below are therefore tautological TODAY (entry was
	// parsed from a body built from sigValue/signerCert, so they cannot fail) and
	// are kept only as defense-in-depth: if a future refactor stops recomputing
	// the body (e.g. trusts the embedded CanonicalizedBody), these become live and
	// catch a mismatch. (Do NOT instead compare the recomputed body to the
	// embedded one — gitsign nils CanonicalizedBody on embed, so the embedded copy
	// is always empty.)
	if !bytes.Equal(entry.Signature(), sigValue) {
		return time.Time{}, 0, fmt.Errorf("transparency log entry signature does not match the commit signature")
	}
	if !entryCertMatches(entry.PublicKey(), signerCert) {
		return time.Time{}, 0, fmt.Errorf("transparency log entry certificate does not match the signer certificate")
	}

	it := entry.IntegratedTime()
	if it.IsZero() {
		return time.Time{}, 0, fmt.Errorf("transparency log entry carries no integrated time")
	}
	return it, entry.LogIndex(), nil
}

// rekorLogVerifier builds a signature.Verifier for the trusted Rekor log that
// produced the entry, selected by the entry's log key ID.
func rekorLogVerifier(logs map[string]*sgroot.TransparencyLog, logKeyID string) (signature.Verifier, error) {
	tl, ok := logs[hex.EncodeToString([]byte(logKeyID))]
	if !ok {
		return nil, fmt.Errorf("rekor log key not found in trusted root")
	}
	v, err := signature.LoadVerifier(tl.PublicKey, tl.SignatureHashFunc)
	if err != nil {
		return nil, fmt.Errorf("load rekor log verifier: %w", err)
	}
	return v, nil
}

// entryCertMatches reports whether the public key recovered from a transparency
// log entry is the signer certificate. gitsign embeds the signer cert in the
// entry, so PublicKey returns an *x509.Certificate equal to the signer.
func entryCertMatches(pk any, signerCert *x509.Certificate) bool {
	cert, ok := pk.(*x509.Certificate)
	if !ok || cert == nil {
		return false
	}
	return cert.Equal(signerCert)
}
