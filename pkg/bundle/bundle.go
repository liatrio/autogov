// Package bundle provides common utilities for working with Sigstore bundles
package bundle

import (
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// DetectType detects the attestation type from a bundle
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

// ExtractSubject extracts the first subject from a bundle
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
