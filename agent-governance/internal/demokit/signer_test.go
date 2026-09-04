package demokit

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestSignerUsesFulcioIssuerV2DERString(t *testing.T) {
	const issuer = "https://demo.autogov.local/oidc"
	deprecatedIssuerOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	signer, err := NewSigner("agent-governance-demo@autogov.local", issuer)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignStatement([]byte(`{"fixture":"statement"}`))
	if err != nil {
		t.Fatal(err)
	}

	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(signed, &bundle); err != nil {
		t.Fatal(err)
	}
	chain := bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(chain) == 0 {
		t.Fatal("signed bundle has no leaf certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0].GetRawBytes())
	if err != nil {
		t.Fatal(err)
	}

	var extensionValue []byte
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(deprecatedIssuerOID) {
			t.Fatal("demo signer emitted deprecated Fulcio issuer OID")
		}
		if extension.Id.Equal(certificate.OIDIssuerV2) {
			extensionValue = extension.Value
		}
	}
	if extensionValue == nil {
		t.Fatal("demo signer omitted Fulcio issuer v2 OID")
	}
	var got string
	rest, err := asn1.Unmarshal(extensionValue, &got)
	if err != nil || len(rest) != 0 {
		t.Fatalf("issuer v2 extension is not a complete DER string: value=%x err=%v", extensionValue, err)
	}
	if got != issuer {
		t.Errorf("issuer v2 extension = %q, want %q", got, issuer)
	}
}

func TestSignerExportsTrustedRootJSON(t *testing.T) {
	signer, err := NewSigner("agent-governance-demo@autogov.local", "https://demo.autogov.local/oidc")
	if err != nil {
		t.Fatal(err)
	}
	data, err := signer.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("trusted root output is not valid JSON")
	}
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"certificateAuthorities", "timestampAuthorities"} {
		values, ok := document[field].([]interface{})
		if !ok || len(values) == 0 {
			t.Errorf("trusted root %s = %#v, want a non-empty array", field, document[field])
		}
	}
}
