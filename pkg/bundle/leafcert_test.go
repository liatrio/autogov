package bundle

import (
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

func TestLeafCertDER(t *testing.T) {
	// nil / empty material returns nil
	if got := LeafCertDER(nil); got != nil {
		t.Errorf("LeafCertDER(nil) = %v, want nil", got)
	}
	if got := LeafCertDER(&bundle.Bundle{Bundle: &protobundle.Bundle{}}); got != nil {
		t.Errorf("LeafCertDER(empty) = %v, want nil", got)
	}

	// single-certificate form (real public-good bundle)
	b, err := bundle.LoadJSONFromPath(filepath.Join("testdata", "bundle-public-good.jsonl"))
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	if got := LeafCertDER(b); len(got) == 0 {
		t.Error("LeafCertDER(single-cert bundle) returned no certificate")
	}

	// certificate-chain form (synthetic): the leaf is the first cert in the chain
	leaf := []byte{0x30, 0x82, 0x01, 0x02} // arbitrary non-empty DER prefix
	chainBundle := &bundle.Bundle{Bundle: &protobundle.Bundle{
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &commonv1.X509CertificateChain{
					Certificates: []*commonv1.X509Certificate{
						{RawBytes: leaf},
						{RawBytes: []byte{0xAA}},
					},
				},
			},
		},
	}}
	got := LeafCertDER(chainBundle)
	if string(got) != string(leaf) {
		t.Errorf("LeafCertDER(chain) = %v, want leaf %v", got, leaf)
	}
}
