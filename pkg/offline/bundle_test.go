package offline

import (
	"os"
	"testing"
)

func TestLoadBundles(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantErr   bool
		wantCount int
	}{
		{
			name: "valid single JSON",
			content: `[{
				"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
				"verificationMaterial": {
					"certificate": {
						"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
					}
				},
				"dsseEnvelope": {
					"payload": "dGVzdA==",
					"payloadType": "application/vnd.in-toto+json",
					"signatures": [{"sig": "dGVzdA=="}]
				}
			}]`,
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "valid JSONL",
			content: `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}
{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdDI=", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdDI="}]}}`,
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:      "empty file",
			content:   "",
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:      "invalid JSON",
			content:   "not json",
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create temp file
			tmpFile, err := os.CreateTemp("", "bundle_test_*.jsonl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()

			// write test content
			if _, err := tmpFile.Write([]byte(tt.content)); err != nil {
				t.Fatalf("failed to write test content: %v", err)
			}
			_ = tmpFile.Close()

			// test loading
			bundles, err := LoadBundles(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadBundles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if len(bundles) != tt.wantCount {
				t.Errorf("LoadBundles() got %d bundles, want %d", len(bundles), tt.wantCount)
			}
		})
	}
}
