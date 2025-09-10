package bundle

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a test bundle with a given statement
func createTestBundle(statement map[string]interface{}) *bundle.Bundle {
	b := &bundle.Bundle{}

	// Marshal the statement to JSON
	stmtJSON, _ := json.Marshal(statement)
	payload := base64.StdEncoding.EncodeToString(stmtJSON)

	// Create a minimal bundle
	bundleJSON := `{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {},
		"dsseEnvelope": {
			"payload": "` + payload + `",
			"payloadType": "application/vnd.in-toto+json",
			"signatures": []
		}
	}`
	_ = b.UnmarshalJSON([]byte(bundleJSON))
	return b
}

func TestDetectType(t *testing.T) {
	tests := []struct {
		name     string
		bundle   *bundle.Bundle
		expected string
	}{
		{
			name:     "nil bundle",
			bundle:   nil,
			expected: "unknown",
		},
		{
			name:     "bundle with nil internal bundle",
			bundle:   &bundle.Bundle{},
			expected: "unknown",
		},
		{
			name: "bundle with SLSA predicate",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"subject":       []interface{}{map[string]interface{}{"name": "test"}},
				"predicate":     map[string]interface{}{},
			}),
			expected: "https://slsa.dev/provenance/v1",
		},
		{
			name: "bundle with SBOM predicate",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://cyclonedx.org/bom",
				"subject":       []interface{}{map[string]interface{}{"name": "test"}},
				"predicate":     map[string]interface{}{},
			}),
			expected: "https://cyclonedx.org/bom",
		},
		{
			name: "bundle with vulnerability predicate",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
				"subject":       []interface{}{map[string]interface{}{"name": "test"}},
				"predicate":     map[string]interface{}{},
			}),
			expected: "https://in-toto.io/attestation/vulns/v0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectType(tt.bundle)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractSubject(t *testing.T) {
	tests := []struct {
		name         string
		bundle       *bundle.Bundle
		expectedName string
		expectedDgst map[string]string
	}{
		{
			name:         "nil bundle",
			bundle:       nil,
			expectedName: "",
			expectedDgst: nil,
		},
		{
			name:         "bundle with nil internal bundle",
			bundle:       &bundle.Bundle{},
			expectedName: "",
			expectedDgst: nil,
		},
		{
			name: "bundle with single subject",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"subject": []interface{}{
					map[string]interface{}{
						"name":   "ghcr.io/test/image",
						"digest": map[string]interface{}{"sha256": "abc123"},
					},
				},
				"predicate": map[string]interface{}{},
			}),
			expectedName: "ghcr.io/test/image",
			expectedDgst: map[string]string{"sha256": "abc123"},
		},
		{
			name: "bundle with multiple subjects",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"subject": []interface{}{
					map[string]interface{}{
						"name":   "first-subject",
						"digest": map[string]interface{}{"sha256": "first123"},
					},
					map[string]interface{}{
						"name":   "second-subject",
						"digest": map[string]interface{}{"sha256": "second456"},
					},
				},
				"predicate": map[string]interface{}{},
			}),
			expectedName: "first-subject",
			expectedDgst: map[string]string{"sha256": "first123"},
		},
		{
			name: "bundle with no subjects",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/provenance/v1",
				"subject":       []interface{}{},
				"predicate":     map[string]interface{}{},
			}),
			expectedName: "",
			expectedDgst: nil,
		},
		{
			name: "bundle with blob subject",
			bundle: createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://cosign.sigstore.dev/attestation/v1",
				"subject": []interface{}{
					map[string]interface{}{
						"name":   "bundle.tar.gz",
						"digest": map[string]interface{}{"sha256": "b7921f04a354f4ea51d32e3d619addd7b737b64ca6bb19ddcc7f5b560a62bea5"},
					},
				},
				"predicate": map[string]interface{}{},
			}),
			expectedName: "bundle.tar.gz",
			expectedDgst: map[string]string{"sha256": "b7921f04a354f4ea51d32e3d619addd7b737b64ca6bb19ddcc7f5b560a62bea5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, digest := ExtractSubject(tt.bundle)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedDgst, digest)
		})
	}
}

func TestExtractSubjectComplexDigests(t *testing.T) {
	// test with multiple digest algorithms
	bundle := createTestBundle(map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []interface{}{
			map[string]interface{}{
				"name": "complex-subject",
				"digest": map[string]interface{}{
					"sha256": "abc123",
					"sha512": "def456",
					"sha1":   "789ghi",
				},
			},
		},
		"predicate": map[string]interface{}{},
	})

	name, digest := ExtractSubject(bundle)
	assert.Equal(t, "complex-subject", name)
	assert.Equal(t, map[string]string{
		"sha256": "abc123",
		"sha512": "def456",
		"sha1":   "789ghi",
	}, digest)
}

func TestDetectTypeVariousPredicateTypes(t *testing.T) {
	predicateTypes := []struct {
		predicateType string
		description   string
	}{
		{"https://slsa.dev/provenance/v0.2", "SLSA v0.2"},
		{"https://slsa.dev/provenance/v1", "SLSA v1"},
		{"https://cosign.sigstore.dev/attestation/v1", "Cosign"},
		{"https://cyclonedx.org/bom", "CycloneDX SBOM"},
		{"https://spdx.dev/Document", "SPDX"},
		{"https://in-toto.io/attestation/vulns/v0.2", "Vulnerability"},
		{"custom/predicate/type", "Custom"},
	}

	for _, pt := range predicateTypes {
		t.Run(pt.description, func(t *testing.T) {
			bundle := createTestBundle(map[string]interface{}{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": pt.predicateType,
				"subject":       []interface{}{map[string]interface{}{"name": "test"}},
				"predicate":     map[string]interface{}{},
			})

			result := DetectType(bundle)
			assert.Equal(t, pt.predicateType, result)
		})
	}
}
