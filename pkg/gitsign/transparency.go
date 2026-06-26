package gitsign

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/liatrio/autogov/pkg/root"
)

// id-aa-timeStampToken (RFC 3161) — the OID under which gitsign stores the
// RFC3161 timestamp token as a CMS unauthenticated attribute on the SignerInfo.
var oidAttributeTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// oidSignedData is the CMS SignedData content type.
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// trustedTimestamp is the result of establishing a trusted time for a gitsign
// signature. Source is "tsa" (GitHub-internal RFC3161 path) or "rekor"
// (public-good transparency-log path). RekorLogIndex is populated only for the
// rekor path; it is 0 for the TSA path.
type trustedTimestamp struct {
	Time          time.Time
	Source        string
	RekorLogIndex int64
}

// --- minimal ASN.1 mirror of the CMS structures we must re-parse ---
//
// github.com/digitorus/pkcs7 exposes the parsed PKCS7 (Certificates, Content,
// Signers) but hides the per-signer UnauthenticatedAttributes behind an
// unexported signerInfo type. The RFC3161 timestamp token lives there, so we
// re-parse the raw CMS bytes ourselves to reach it. The structs below mirror
// the digitorus layout exactly so encoding/asn1 unmarshals byte-for-byte.

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type cmsAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type cmsIssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber asn1.RawValue
}

type cmsSignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     cmsIssuerAndSerial
	DigestAlgorithm           asn1.RawValue
	AuthenticatedAttributes   []cmsAttribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm asn1.RawValue
	EncryptedDigest           []byte
	UnauthenticatedAttributes []cmsAttribute `asn1:"optional,omitempty,tag:1"`
}

type cmsSignedData struct {
	Version                    int
	DigestAlgorithmIdentifiers []asn1.RawValue `asn1:"set"`
	ContentInfo                asn1.RawValue
	Certificates               asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs                       []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos                []cmsSignerInfo `asn1:"set"`
}

// extractTimestampTokenAndSig re-parses the raw CMS bytes and returns the
// DER-encoded RFC3161 timestamp token together with the EncryptedDigest
// (signature value) of the SAME SignerInfo that carried the token. Pairing the
// two from one SignerInfo prevents binding a token found on one signer to a
// different signer's signature value. Returns (nil, nil, false) when no
// timestamp token is present (e.g. public-good signatures, which anchor on
// Rekor instead of a TSA) or the CMS cannot be parsed.
func extractTimestampTokenAndSig(cmsDER []byte) (token, sigValue []byte, ok bool) {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		return nil, nil, false
	}
	if !ci.ContentType.Equal(oidSignedData) || len(ci.Content.Bytes) == 0 {
		return nil, nil, false
	}

	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, nil, false
	}

	for _, si := range sd.SignerInfos {
		for _, attr := range si.UnauthenticatedAttributes {
			if !attr.Type.Equal(oidAttributeTimeStampToken) {
				continue
			}
			// attr.Value is a SET OF AttributeValue; the timestamp token is the
			// single ContentInfo element inside it.
			var tok asn1.RawValue
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &tok); err != nil {
				return nil, nil, false
			}
			if len(si.EncryptedDigest) == 0 {
				return nil, nil, false
			}
			return tok.FullBytes, si.EncryptedDigest, true
		}
	}
	return nil, nil, false
}

// verifyTSATimestamp verifies an RFC3161 timestamp token against the GitHub
// trusted root's timestamp-authority cert chains and confirms the token's
// message imprint covers the signature value. On success it returns the TSA
// genTime, which is the trusted time the cert chain must be pinned to.
//
// The token is over the CMS signature value (EncryptedDigest), matching the
// gitsign/sigstore convention of timestamping the signature.
func verifyTSATimestamp(tokenDER []byte, signatureValue []byte) (time.Time, error) {
	// timestamp.Parse verifies the token's own signature when it embeds certs;
	// gitsign tokens from timestamp.githubapp.com do embed the TSA chain.
	ts, err := timestamp.Parse(tokenDER)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp token: %w", err)
	}

	// identify the actual TSA signer cert (not blindly Certificates[0], which is
	// the raw embedded list and may not be signer-first) and chain it to a
	// trusted TSA root from the GitHub root.
	signerCert, err := tsaSignerCert(tokenDER, ts)
	if err != nil {
		return time.Time{}, err
	}
	tsaRoots, tsaIntermediates, err := loadTSARoots()
	if err != nil {
		return time.Time{}, err
	}
	if err := verifyTSAChain(signerCert, ts, tsaRoots, tsaIntermediates); err != nil {
		return time.Time{}, err
	}

	// the token must actually cover this signature, otherwise an attacker could
	// graft an unrelated valid token onto a forged signature.
	if !hashedMessageMatches(ts, signatureValue) {
		return time.Time{}, fmt.Errorf("timestamp token does not cover the signature value")
	}

	if ts.Time.IsZero() {
		return time.Time{}, fmt.Errorf("timestamp token carries no genTime")
	}
	return ts.Time, nil
}

// hashedMessageMatches confirms the token's message imprint is the hash of the
// provided signature value under the token's declared hash algorithm.
func hashedMessageMatches(ts *timestamp.Timestamp, signatureValue []byte) bool {
	if !ts.HashAlgorithm.Available() {
		return false
	}
	h := ts.HashAlgorithm.New()
	h.Write(signatureValue)
	computed := h.Sum(nil)
	return subtle.ConstantTimeCompare(computed, ts.HashedMessage) == 1
}

// tsaSignerCert returns the certificate that actually signed the timestamp
// token. It re-parses the token's PKCS7 and uses GetOnlySigner so the chained
// leaf is the signer — not an arbitrary embedded cert. Falls back to the first
// embedded cert only when there is exactly one (the common single-cert token).
func tsaSignerCert(tokenDER []byte, ts *timestamp.Timestamp) (*x509.Certificate, error) {
	if p7, err := pkcs7.Parse(tokenDER); err == nil {
		if signer := p7.GetOnlySigner(); signer != nil {
			return signer, nil
		}
	}
	if len(ts.Certificates) == 1 {
		return ts.Certificates[0], nil
	}
	return nil, fmt.Errorf("could not identify the TSA signer certificate")
}

// verifyTSAChain verifies the timestamp's signer certificate chains to a
// trusted TSA root and carries the timestamping EKU. Intermediates from both
// the token itself and the trusted root are made available to the verifier.
func verifyTSAChain(signerCert *x509.Certificate, ts *timestamp.Timestamp, roots, intermediates *x509.CertPool) error {
	if signerCert == nil {
		return fmt.Errorf("timestamp token embeds no TSA signer certificate")
	}
	// any embedded cert that is not the signer is a candidate intermediate.
	pool := intermediates.Clone()
	for _, c := range ts.Certificates {
		if !c.Equal(signerCert) {
			pool.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		// pin chain validity to the token's own genTime so an expired TSA cert
		// is rejected, while not depending on wall-clock now.
		CurrentTime: ts.Time,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err := signerCert.Verify(opts); err != nil {
		return fmt.Errorf("verify TSA cert chain: %w", err)
	}
	return nil
}

// timestampAuthoritiesJSON mirrors the timestampAuthorities section of a
// sigstore trusted root.
type timestampAuthoritiesJSON struct {
	TimestampAuthorities []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
	} `json:"timestampAuthorities"`
}

// loadTSARoots loads the GitHub trusted root's timestamp-authority cert chains
// into root and intermediate pools. The last cert in each chain is treated as a
// root; earlier certs are intermediates. It is a package var so tests can inject
// a self-signed test TSA root.
var loadTSARoots = func() (*x509.CertPool, *x509.CertPool, error) {
	var tr timestampAuthoritiesJSON
	if err := json.Unmarshal(root.GetGitHubTrustedRoot(), &tr); err != nil {
		return nil, nil, fmt.Errorf("parse github trusted root TSA section: %w", err)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	added := 0
	for _, ta := range tr.TimestampAuthorities {
		certs := ta.CertChain.Certificates
		for i, c := range certs {
			der, err := base64.StdEncoding.DecodeString(c.RawBytes)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			if i == len(certs)-1 {
				roots.AddCert(cert)
			} else {
				intermediates.AddCert(cert)
			}
			added++
		}
	}
	if added == 0 {
		return nil, nil, fmt.Errorf("no TSA certificates found in github trusted root")
	}
	return roots, intermediates, nil
}
