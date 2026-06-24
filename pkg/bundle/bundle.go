// common utilities for working with Sigstore bundles
package bundle

import (
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// LeafCertDER returns the signing certificate (DER) from a bundle's verification
// material, supporting both the single-certificate and certificate-chain forms.
// Returns nil when the bundle carries no certificate (e.g. public-key bundles).
func LeafCertDER(b *bundle.Bundle) []byte {
	if b == nil || b.Bundle == nil {
		return nil
	}
	vm := b.GetVerificationMaterial()
	if c := vm.GetCertificate(); c != nil && len(c.GetRawBytes()) > 0 {
		return c.GetRawBytes()
	}
	if chain := vm.GetX509CertificateChain(); chain != nil {
		if certs := chain.GetCertificates(); len(certs) > 0 {
			return certs[0].GetRawBytes()
		}
	}
	return nil
}

// detects the attestation type from a bundle
func DetectType(b *bundle.Bundle) string {
	if b == nil {
		return "unknown"
	}

	if b.Bundle == nil {
		return "unknown"
	}

	if env, err := b.Envelope(); err == nil {
		if stmt, err := env.Statement(); err == nil {
			return stmt.PredicateType
		}
	}
	return "unknown"
}

// extracts the first subject from a bundle
func ExtractSubject(b *bundle.Bundle) (name string, digest map[string]string) {
	if b == nil || b.Bundle == nil {
		return "", nil
	}

	if env, err := b.Envelope(); err == nil {
		if stmt, err := env.Statement(); err == nil && len(stmt.Subject) > 0 {
			return stmt.Subject[0].Name, stmt.Subject[0].Digest
		}
	}
	return "", nil
}
