package offline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
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

func TestLoadBundlesFromDirectory(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "bundle_dir_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	validBundle := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`

	tests := []struct {
		name      string
		setup     func() string
		wantErr   bool
		wantCount int
	}{
		{
			name: "directory with valid json files",
			setup: func() string {
				dir := filepath.Join(tmpDir, "valid_json")
				_ = os.MkdirAll(dir, 0755)
				_ = os.WriteFile(filepath.Join(dir, "bundle1.json"), []byte(validBundle), 0644)
				_ = os.WriteFile(filepath.Join(dir, "bundle2.json"), []byte(validBundle), 0644)
				return dir
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name: "directory with valid jsonl files",
			setup: func() string {
				dir := filepath.Join(tmpDir, "valid_jsonl")
				_ = os.MkdirAll(dir, 0755)
				_ = os.WriteFile(filepath.Join(dir, "bundles.jsonl"), []byte(validBundle+"\n"+validBundle), 0644)
				return dir
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name: "directory with mixed files (ignores non-json)",
			setup: func() string {
				dir := filepath.Join(tmpDir, "mixed")
				_ = os.MkdirAll(dir, 0755)
				_ = os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(validBundle), 0644)
				_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a bundle"), 0644)
				_ = os.WriteFile(filepath.Join(dir, "data.yaml"), []byte("key: value"), 0644)
				return dir
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "empty directory",
			setup: func() string {
				dir := filepath.Join(tmpDir, "empty")
				_ = os.MkdirAll(dir, 0755)
				return dir
			},
			wantErr:   true,
			wantCount: 0,
		},
		{
			name: "directory with only invalid json files",
			setup: func() string {
				dir := filepath.Join(tmpDir, "invalid_only")
				_ = os.MkdirAll(dir, 0755)
				_ = os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not valid json"), 0644)
				return dir
			},
			wantErr:   true,
			wantCount: 0,
		},
		{
			name: "directory with subdirectories (should skip them)",
			setup: func() string {
				dir := filepath.Join(tmpDir, "with_subdir")
				_ = os.MkdirAll(dir, 0755)
				_ = os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(validBundle), 0644)
				_ = os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
				return dir
			},
			wantErr:   false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirPath := tt.setup()
			bundles, err := LoadBundles(dirPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadBundles() from directory expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadBundles() from directory unexpected error: %v", err)
				return
			}

			if len(bundles) != tt.wantCount {
				t.Errorf("LoadBundles() from directory got %d bundles, want %d", len(bundles), tt.wantCount)
			}
		})
	}
}

func TestWriteBundles(t *testing.T) {
	// Create a test bundle
	validBundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`

	testBundle := &bundle.Bundle{}
	if err := testBundle.UnmarshalJSON([]byte(validBundleJSON)); err != nil {
		t.Fatalf("failed to create test bundle: %v", err)
	}

	tests := []struct {
		name    string
		bundles []*bundle.Bundle
		format  string
		wantErr bool
	}{
		{
			name:    "write single bundle as json",
			bundles: []*bundle.Bundle{testBundle},
			format:  "json",
			wantErr: false,
		},
		{
			name:    "write multiple bundles as json",
			bundles: []*bundle.Bundle{testBundle, testBundle},
			format:  "json",
			wantErr: false,
		},
		{
			name:    "write single bundle as jsonl",
			bundles: []*bundle.Bundle{testBundle},
			format:  "jsonl",
			wantErr: false,
		},
		{
			name:    "write multiple bundles as jsonl",
			bundles: []*bundle.Bundle{testBundle, testBundle},
			format:  "jsonl",
			wantErr: false,
		},
		{
			name:    "unsupported format",
			bundles: []*bundle.Bundle{testBundle},
			format:  "xml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpFile, err := os.CreateTemp("", "write_bundle_test_*")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			tmpPath := tmpFile.Name()
			_ = tmpFile.Close()
			defer func() { _ = os.Remove(tmpPath) }()

			err = WriteBundles(tt.bundles, tmpPath, tt.format)

			if tt.wantErr {
				if err == nil {
					t.Errorf("WriteBundles() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("WriteBundles() unexpected error: %v", err)
				return
			}

			// Verify the file was written and can be read back
			readBundles, err := LoadBundles(tmpPath)
			if err != nil {
				t.Errorf("Failed to read back written bundles: %v", err)
				return
			}

			if len(readBundles) != len(tt.bundles) {
				t.Errorf("WriteBundles() wrote %d bundles, read back %d", len(tt.bundles), len(readBundles))
			}
		})
	}
}

func TestWriteBundlesInvalidPath(t *testing.T) {
	validBundleJSON := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`

	testBundle := &bundle.Bundle{}
	if err := testBundle.UnmarshalJSON([]byte(validBundleJSON)); err != nil {
		t.Fatalf("failed to create test bundle: %v", err)
	}

	err := WriteBundles([]*bundle.Bundle{testBundle}, "/nonexistent/path/file.json", "json")
	if err == nil {
		t.Error("WriteBundles() with invalid path expected error, got nil")
	}
}

func TestLoadBundlesStatError(t *testing.T) {
	_, err := LoadBundles("/nonexistent/path/file.json")
	if err == nil {
		t.Error("LoadBundles() with nonexistent path expected error, got nil")
	}
}

func TestLoadBundlesSingleBundleFile(t *testing.T) {
	// Test loading a single bundle (not in array)
	tmpFile, err := os.CreateTemp("", "single_bundle_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Single bundle JSON (not array, not JSONL)
	singleBundle := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`
	if _, err := tmpFile.WriteString(singleBundle); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	bundles, err := LoadBundles(tmpFile.Name())
	if err != nil {
		t.Errorf("LoadBundles() unexpected error: %v", err)
	}
	if len(bundles) != 1 {
		t.Errorf("LoadBundles() got %d bundles, want 1", len(bundles))
	}
}

func TestLoadBundlesJSONArrayWithMultiple(t *testing.T) {
	// Test loading a JSON array with multiple bundles
	tmpFile, err := os.CreateTemp("", "array_bundle_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// JSON array of bundles
	arrayBundle := `[
		{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}},
		{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdDI=", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdDI="}]}}
	]`
	if _, err := tmpFile.WriteString(arrayBundle); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	bundles, err := LoadBundles(tmpFile.Name())
	if err != nil {
		t.Errorf("LoadBundles() unexpected error: %v", err)
	}
	if len(bundles) != 2 {
		t.Errorf("LoadBundles() got %d bundles, want 2", len(bundles))
	}
}

func TestLoadBundlesJSONArrayInvalidBundle(t *testing.T) {
	// Test loading a JSON array with an invalid bundle
	tmpFile, err := os.CreateTemp("", "invalid_array_bundle_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// JSON array with one invalid bundle
	arrayBundle := `[
		{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}},
		{"invalid": "bundle"}
	]`
	if _, err := tmpFile.WriteString(arrayBundle); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	_, err = LoadBundles(tmpFile.Name())
	if err == nil {
		t.Error("LoadBundles() with invalid bundle in array expected error, got nil")
	}
}

func TestLoadBundlesJSONLWithEmptyLines(t *testing.T) {
	// Test loading JSONL with empty lines (should be skipped)
	tmpFile, err := os.CreateTemp("", "jsonl_empty_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// JSONL with empty lines
	jsonl := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}

{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdDI=", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdDI="}]}}`
	if _, err := tmpFile.WriteString(jsonl); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	bundles, err := LoadBundles(tmpFile.Name())
	if err != nil {
		t.Errorf("LoadBundles() unexpected error: %v", err)
	}
	if len(bundles) != 2 {
		t.Errorf("LoadBundles() got %d bundles, want 2", len(bundles))
	}
}

func TestLoadBundlesJSONLWithArrayLine(t *testing.T) {
	// Test loading JSONL where each line is a JSON array
	tmpFile, err := os.CreateTemp("", "jsonl_array_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	validBundle := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}`

	// Line is a JSON array (some tools output this way)
	jsonl := "[" + validBundle + "," + validBundle + "]\n"
	if _, err := tmpFile.WriteString(jsonl); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	bundles, err := LoadBundles(tmpFile.Name())
	if err != nil {
		t.Errorf("LoadBundles() unexpected error: %v", err)
	}
	if len(bundles) != 2 {
		t.Errorf("LoadBundles() got %d bundles, want 2", len(bundles))
	}
}

func TestLoadBundlesJSONLUnparseableLine(t *testing.T) {
	// Test loading JSONL where a line can't be parsed as bundle or array
	tmpFile, err := os.CreateTemp("", "jsonl_unparseable_*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// First line is valid, second line is not a valid bundle
	jsonl := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VDZXJ0CkZha2VDZXJ0Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="}}, "dsseEnvelope": {"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}
{"not": "a valid bundle"}`
	if _, err := tmpFile.WriteString(jsonl); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	_ = tmpFile.Close()

	_, err = LoadBundles(tmpFile.Name())
	if err == nil {
		t.Error("LoadBundles() with unparseable line expected error, got nil")
	}
}
