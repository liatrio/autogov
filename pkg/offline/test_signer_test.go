package offline

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/digitorus/timestamp"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"
)

// offlineTestSigner is a self-contained test Sigstore CA: a local root with a
// Fulcio-style signing intermediate and an RFC3161 timestamping authority. It
// signs in-toto statements into offline-verifiable Sigstore bundles and
// exports the matching trusted root JSON. Test infrastructure
// only — the certificates live for hours and chain to nothing public.
type offlineTestSigner struct {
	identity string
	issuer   string

	rootCert *x509.Certificate

	fulcioIntermediate    *x509.Certificate
	fulcioIntermediateKey *ecdsa.PrivateKey

	tsaIntermediate *x509.Certificate
	tsaLeaf         *x509.Certificate
	tsaLeafKey      *ecdsa.PrivateKey

	validityStart time.Time
	validityEnd   time.Time
}

// oidcIssuerV2OID is the current Fulcio OIDC issuer certificate extension.
var oidcIssuerV2OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// ekuOID is the X.509 Extended Key Usage extension.
var ekuOID = asn1.ObjectIdentifier{2, 5, 29, 37}

// ekuTimestampingOID marks a timestamping certificate.
var ekuTimestampingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

// newOfflineTestSigner builds the test CA hierarchy for one signing identity
// (an email SAN) and OIDC issuer.
func newOfflineTestSigner(identity, issuer string) (*offlineTestSigner, error) {
	s := &offlineTestSigner{
		identity:      identity,
		issuer:        issuer,
		validityStart: time.Now().Add(-1 * time.Hour),
		validityEnd:   time.Now().Add(24 * time.Hour),
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "autogov-offline-test-root", Organization: []string{"autogov-offline-test"}},
		NotBefore:             s.validityStart,
		NotAfter:              s.validityEnd,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	s.rootCert, err = createCert(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create test root CA: %w", err)
	}

	if err := s.createFulcioIntermediate(rootKey); err != nil {
		return nil, err
	}
	if err := s.createTSA(rootKey); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *offlineTestSigner) createFulcioIntermediate(rootKey *ecdsa.PrivateKey) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "autogov-offline-test-fulcio", Organization: []string{"autogov-offline-test"}},
		NotBefore:             s.validityStart,
		NotAfter:              s.validityEnd,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	s.fulcioIntermediate, err = createCert(template, s.rootCert, &key.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("failed to create test Fulcio intermediate: %w", err)
	}
	s.fulcioIntermediateKey = key
	return nil
}

func (s *offlineTestSigner) createTSA(rootKey *ecdsa.PrivateKey) error {
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "autogov-offline-test-tsa", Organization: []string{"autogov-offline-test"}},
		NotBefore:             s.validityStart,
		NotAfter:              s.validityEnd,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	s.tsaIntermediate, err = createCert(intermediateTemplate, s.rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("failed to create test TSA intermediate: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	timestampingExt, err := asn1.Marshal([]asn1.ObjectIdentifier{ekuTimestampingOID})
	if err != nil {
		return err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: "autogov-offline-test-tsa-leaf"},
		NotBefore:    s.validityStart,
		NotAfter:     s.validityEnd,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
		// timestamping EKU with the critical bit, as RFC3161 verification expects
		ExtraExtensions: []pkix.Extension{{
			Id:       ekuOID,
			Critical: true,
			Value:    timestampingExt,
		}},
	}
	s.tsaLeaf, err = createCert(leafTemplate, s.tsaIntermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		return fmt.Errorf("failed to create test TSA leaf: %w", err)
	}
	s.tsaLeafKey = leafKey
	return nil
}

// SignStatement signs one in-toto statement into a Sigstore bundle (JSON):
// an ephemeral Fulcio-style leaf certificate for the signer identity, a DSSE
// envelope over the exact statement bytes, and an RFC3161 timestamp from the
// test TSA. The bundle carries no transparency log entry; offline
// verification uses the observer timestamp against the exported trusted root.
func (s *offlineTestSigner) SignStatement(statementJSON []byte) ([]byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	issuerExtension, err := asn1.MarshalWithParams(s.issuer, "utf8")
	if err != nil {
		return nil, fmt.Errorf("failed to encode Fulcio issuer extension: %w", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:   newSerial(),
		EmailAddresses: []string{s.identity},
		NotBefore:      time.Now().Add(-5 * time.Minute),
		NotAfter:       time.Now().Add(1 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:           false,
		ExtraExtensions: []pkix.Extension{{
			Id:       oidcIssuerV2OID,
			Critical: false,
			Value:    issuerExtension,
		}},
	}
	leafCert, err := createCert(leafTemplate, s.fulcioIntermediate, &leafKey.PublicKey, s.fulcioIntermediateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing certificate: %w", err)
	}

	const payloadType = "application/vnd.in-toto+json"
	pae := dssePAE(payloadType, statementJSON)
	paeDigest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, paeDigest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign DSSE payload: %w", err)
	}

	tsr, err := s.timestampResponse(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to create RFC3161 timestamp: %w", err)
	}

	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{
						{RawBytes: leafCert.Raw},
						{RawBytes: s.fulcioIntermediate.Raw},
						{RawBytes: s.rootCert.Raw},
					},
				},
			},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: tsr}},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload:     statementJSON,
			PayloadType: payloadType,
			Signatures:  []*protodsse.Signature{{Sig: sig}},
		}},
	}
	return protojson.Marshal(b)
}

// timestampResponse issues an RFC3161 timestamp over the signature bytes.
func (s *offlineTestSigner) timestampResponse(sig []byte) ([]byte, error) {
	tsq, err := timestamp.CreateRequest(bytes.NewReader(sig), &timestamp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	req, err := timestamp.ParseRequest(tsq)
	if err != nil {
		return nil, err
	}
	tsTemplate := timestamp.Timestamp{
		HashAlgorithm:   req.HashAlgorithm,
		HashedMessage:   req.HashedMessage,
		Time:            time.Now(),
		Policy:          asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:        false,
		Qualified:       false,
		ExtraExtensions: req.Extensions,
	}
	return tsTemplate.CreateResponseWithOpts(s.tsaLeaf, s.tsaLeafKey, crypto.SHA256)
}

// TrustedRootJSON exports the trusted root that verifies this signer's
// bundles: the test Fulcio CA chain and the test timestamping authority.
func (s *offlineTestSigner) TrustedRootJSON() ([]byte, error) {
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:                s.rootCert,
		Intermediates:       []*x509.Certificate{s.fulcioIntermediate},
		ValidityPeriodStart: s.validityStart,
		ValidityPeriodEnd:   s.validityEnd,
		URI:                 "https://test.autogov.local/fulcio",
	}
	tsa := &root.SigstoreTimestampingAuthority{
		Root:                s.rootCert,
		Intermediates:       []*x509.Certificate{s.tsaIntermediate},
		Leaf:                s.tsaLeaf,
		ValidityPeriodStart: s.validityStart,
		ValidityPeriodEnd:   s.validityEnd,
		URI:                 "https://test.autogov.local/tsa",
	}
	tr, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		[]root.CertificateAuthority{fulcioCA},
		nil,
		[]root.TimestampingAuthority{tsa},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build trusted root: %w", err)
	}
	return tr.MarshalJSON()
}

// dssePAE is the DSSE v1 pre-authentication encoding.
func dssePAE(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

func createCert(template, parent *x509.Certificate, pub any, priv crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func newSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		// crypto/rand failure is unrecoverable for a test signer
		panic(err)
	}
	return serial
}
