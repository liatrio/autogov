package root

import (
	"os"
	"path/filepath"
	"testing"
)

// DetectTrustedRootFromCert must key off the Fulcio cert issuer, not the OIDC
// issuer. The public-good leaf is the load-bearing case: its OIDC issuer is
// token.actions.githubusercontent.com (which maps to GitHub) while its Fulcio
// issuer is sigstore.dev — the cert issuer must win and select the public root.
func TestDetectTrustedRootFromCertByFulcioIssuer(t *testing.T) {
	tests := []struct {
		file string
		want TrustedRootSource
	}{
		{"leaf-public-good.der", TrustedRootSourcePublic},
		{"leaf-github-internal.der", TrustedRootSourceGitHub},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatalf("read cert: %v", err)
			}
			got, err := DetectTrustedRootFromCert(der)
			if err != nil {
				t.Fatalf("DetectTrustedRootFromCert: %v", err)
			}
			if got != tt.want {
				t.Errorf("DetectTrustedRootFromCert(%s) = %q, want %q", tt.file, got, tt.want)
			}
		})
	}
}
