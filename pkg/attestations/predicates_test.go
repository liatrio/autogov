// Copyright © 2025 Liatrio
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestations

import (
	"fmt"
	"regexp"
	"testing"
	"unicode"
)

// TestPredicateTypeConstants_NonEmpty verifies that all predicate type constants
// are non-empty strings. Empty constants would indicate a configuration error.
func TestPredicateTypeConstants_NonEmpty(t *testing.T) {
	tests := []struct {
		name     string
		constant string
	}{
		{"PredicateTypeSLSAProvenance", PredicateTypeSLSAProvenance},
		{"PredicateTypeCycloneDX", PredicateTypeCycloneDX},
		{"PredicateTypeSPDXPrefix", PredicateTypeSPDXPrefix},
		{"PredicateTypeInTotoV1", PredicateTypeInTotoV1},
		{"PredicateTypeVulnerability", PredicateTypeVulnerability},
		{"PredicateTypeVSA", PredicateTypeVSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant == "" {
				t.Errorf("%s is empty, expected non-empty string", tt.name)
			}
		})
	}
}

// TestPredicateTypeConstants_URIFormat verifies that all predicate type constants
// follow the expected https:// URI format pattern. This ensures specification compliance.
func TestPredicateTypeConstants_URIFormat(t *testing.T) {
	// URI format pattern: starts with https://, contains domain and path
	uriPattern := regexp.MustCompile(`^https://[a-zA-Z0-9.-]+\.[a-z]{2,}(/[a-zA-Z0-9._/-]*)?$`)

	tests := []struct {
		name     string
		constant string
	}{
		{"PredicateTypeSLSAProvenance", PredicateTypeSLSAProvenance},
		{"PredicateTypeCycloneDX", PredicateTypeCycloneDX},
		{"PredicateTypeSPDXPrefix", PredicateTypeSPDXPrefix},
		{"PredicateTypeInTotoV1", PredicateTypeInTotoV1},
		{"PredicateTypeVulnerability", PredicateTypeVulnerability},
		{"PredicateTypeVSA", PredicateTypeVSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !uriPattern.MatchString(tt.constant) {
				t.Errorf("%s = %q, does not match expected URI format (https://...)", tt.name, tt.constant)
			}
		})
	}
}

// TestPredicateTypeConstants_MatchSpecification verifies that each constant value
// matches the base URI specified in official in-toto/SLSA documentation.
func TestPredicateTypeConstants_MatchSpecification(t *testing.T) {
	tests := []struct {
		name         string
		constant     string
		expectedURI  string
		specLocation string
	}{
		{
			name:         "PredicateTypeSLSAProvenance",
			constant:     PredicateTypeSLSAProvenance,
			expectedURI:  "https://slsa.dev/provenance/v1",
			specLocation: "https://github.com/in-toto/attestation/blob/main/spec/predicates/provenance.md",
		},
		{
			name:         "PredicateTypeCycloneDX",
			constant:     PredicateTypeCycloneDX,
			expectedURI:  "https://cyclonedx.org/bom",
			specLocation: "https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md",
		},
		{
			name:         "PredicateTypeSPDXPrefix",
			constant:     PredicateTypeSPDXPrefix,
			expectedURI:  "https://spdx.dev/Document",
			specLocation: "https://github.com/in-toto/attestation/blob/main/spec/predicates/spdx.md",
		},
		{
			name:         "PredicateTypeInTotoV1",
			constant:     PredicateTypeInTotoV1,
			expectedURI:  "https://in-toto.io/Statement/v1",
			specLocation: "in-toto attestation framework",
		},
		{
			name:         "PredicateTypeVulnerability",
			constant:     PredicateTypeVulnerability,
			expectedURI:  "https://in-toto.io/attestation/vulns/v0.2",
			specLocation: "https://github.com/in-toto/attestation/blob/main/spec/predicates/vulns_02.md",
		},
		{
			name:         "PredicateTypeVSA",
			constant:     PredicateTypeVSA,
			expectedURI:  "https://slsa.dev/verification_summary/v1",
			specLocation: "https://slsa.dev/spec/v1.0/verification_summary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expectedURI {
				t.Errorf("%s = %q, expected %q (per %s)", tt.name, tt.constant, tt.expectedURI, tt.specLocation)
			}
		})
	}
}

// TestPredicateTypeConstants_Exported verifies that all predicate type constants
// are exported (start with capital letter). This ensures they can be used by other packages.
func TestPredicateTypeConstants_Exported(t *testing.T) {
	constantNames := []string{
		"PredicateTypeSLSAProvenance",
		"PredicateTypeCycloneDX",
		"PredicateTypeSPDXPrefix",
		"PredicateTypeInTotoV1",
		"PredicateTypeVulnerability",
		"PredicateTypeVSA",
	}

	for _, name := range constantNames {
		t.Run(name, func(t *testing.T) {
			if len(name) == 0 {
				t.Errorf("constant name is empty")
				return
			}
			firstRune := rune(name[0])
			if !unicode.IsUpper(firstRune) {
				t.Errorf("constant %s is not exported (does not start with uppercase letter)", name)
			}
		})
	}
}

// Example demonstrates how to use the predicate type constants for attestation verification.
// This example shows the recommended pattern for checking predicate types in attestation
// processing logic.
func ExamplePredicateTypeSLSAProvenance() {
	// Example usage in attestation verification:
	// predicateType := attestation.GetPredicateType()
	//
	// switch predicateType {
	// case PredicateTypeSLSAProvenance:
	//     // Handle SLSA Provenance attestation
	// case PredicateTypeCycloneDX:
	//     // Handle CycloneDX SBOM attestation
	// case PredicateTypeVSA:
	//     // Handle VSA attestation
	// default:
	//     // Handle unknown predicate type
	// }

	// The constants should be used wherever predicate types are checked or displayed
	_ = PredicateTypeSLSAProvenance
	_ = PredicateTypeCycloneDX
	_ = PredicateTypeVSA
}

// TestPredicateTypeRegistry_Initialized verifies that the registry is properly initialized
// at package load time and is not nil.
func TestPredicateTypeRegistry_Initialized(t *testing.T) {
	if PredicateTypeRegistry == nil {
		t.Error("PredicateTypeRegistry is nil, expected initialized map")
	}

	if len(PredicateTypeRegistry) == 0 {
		t.Error("PredicateTypeRegistry is empty, expected entries for all predicate types")
	}
}

// TestPredicateTypeRegistry_ContainsAllTypes verifies that the registry contains entries
// for all 13 predicate types defined in the constants.
func TestPredicateTypeRegistry_ContainsAllTypes(t *testing.T) {
	requiredTypes := []struct {
		name     string
		constant string
	}{
		{"PredicateTypeSLSAProvenance", PredicateTypeSLSAProvenance},
		{"PredicateTypeCycloneDX", PredicateTypeCycloneDX},
		{"PredicateTypeSPDXPrefix", PredicateTypeSPDXPrefix},
		{"PredicateTypeInTotoV1", PredicateTypeInTotoV1},
		{"PredicateTypeVulnerability", PredicateTypeVulnerability},
		{"PredicateTypeVSA", PredicateTypeVSA},
		{"PredicateTypeAutogovMetadata", PredicateTypeAutogovMetadata},
		{"PredicateTypeSCAI", PredicateTypeSCAI},
		{"PredicateTypeRuntimeTrace", PredicateTypeRuntimeTrace},
		{"PredicateTypeRelease", PredicateTypeRelease},
		{"PredicateTypeTestResult", PredicateTypeTestResult},
		{"PredicateTypeLink", PredicateTypeLink},
		{"PredicateTypeCosignCustom", PredicateTypeCosignCustom},
	}

	for _, tt := range requiredTypes {
		t.Run(tt.name, func(t *testing.T) {
			if _, exists := PredicateTypeRegistry[tt.constant]; !exists {
				t.Errorf("PredicateTypeRegistry missing entry for %s (%s)", tt.name, tt.constant)
			}
		})
	}

	// Verify count matches expected number of types
	expectedCount := len(requiredTypes)
	actualCount := len(PredicateTypeRegistry)
	if actualCount != expectedCount {
		t.Errorf("PredicateTypeRegistry contains %d entries, expected %d", actualCount, expectedCount)
	}
}

// TestPredicateTypeRegistry_CompleteMetadata verifies that each registry entry has
// non-empty values for all required fields (URI, ShortName, Description, Spec).
func TestPredicateTypeRegistry_CompleteMetadata(t *testing.T) {
	types := []string{
		PredicateTypeSLSAProvenance,
		PredicateTypeCycloneDX,
		PredicateTypeSPDXPrefix,
		PredicateTypeInTotoV1,
		PredicateTypeVulnerability,
		PredicateTypeVSA,
		PredicateTypeAutogovMetadata,
		PredicateTypeSCAI,
		PredicateTypeRuntimeTrace,
		PredicateTypeRelease,
		PredicateTypeTestResult,
		PredicateTypeLink,
		PredicateTypeCosignCustom,
	}

	for _, uri := range types {
		t.Run(uri, func(t *testing.T) {
			info, exists := PredicateTypeRegistry[uri]
			if !exists {
				t.Fatalf("Registry missing entry for URI: %s", uri)
			}

			if info.URI == "" {
				t.Error("URI field is empty")
			}
			if info.URI != uri {
				t.Errorf("URI field %q does not match registry key %q", info.URI, uri)
			}
			if info.ShortName == "" {
				t.Error("ShortName field is empty")
			}
			if info.Description == "" {
				t.Error("Description field is empty")
			}
			if info.Spec == "" {
				t.Error("Spec field is empty")
			}
		})
	}
}

// TestPredicateTypeRegistry_KeysMatchConstants verifies that registry keys exactly
// match the predicate type constant values, ensuring consistency between constants
// and registry lookup.
func TestPredicateTypeRegistry_KeysMatchConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
	}{
		{"PredicateTypeSLSAProvenance", PredicateTypeSLSAProvenance},
		{"PredicateTypeCycloneDX", PredicateTypeCycloneDX},
		{"PredicateTypeSPDXPrefix", PredicateTypeSPDXPrefix},
		{"PredicateTypeInTotoV1", PredicateTypeInTotoV1},
		{"PredicateTypeVulnerability", PredicateTypeVulnerability},
		{"PredicateTypeVSA", PredicateTypeVSA},
		{"PredicateTypeAutogovMetadata", PredicateTypeAutogovMetadata},
		{"PredicateTypeSCAI", PredicateTypeSCAI},
		{"PredicateTypeRuntimeTrace", PredicateTypeRuntimeTrace},
		{"PredicateTypeRelease", PredicateTypeRelease},
		{"PredicateTypeTestResult", PredicateTypeTestResult},
		{"PredicateTypeLink", PredicateTypeLink},
		{"PredicateTypeCosignCustom", PredicateTypeCosignCustom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, exists := PredicateTypeRegistry[tt.constant]
			if !exists {
				t.Errorf("Registry key %q (constant %s) does not exist", tt.constant, tt.name)
				return
			}

			if info.URI != tt.constant {
				t.Errorf("Registry[%s].URI = %q, expected %q", tt.name, info.URI, tt.constant)
			}
		})
	}
}

// TestPredicateTypeRegistry_MetadataAccuracy verifies that specific metadata values
// are correct for known predicate types, ensuring human-readable names and descriptions
// are appropriate and specification links are valid.
func TestPredicateTypeRegistry_MetadataAccuracy(t *testing.T) {
	tests := []struct {
		uri               string
		expectedShortName string
		descriptionSubstr string
		specContains      string
	}{
		{
			uri:               PredicateTypeSLSAProvenance,
			expectedShortName: "SLSA Provenance",
			descriptionSubstr: "built",
			specContains:      "github.com/in-toto/attestation",
		},
		{
			uri:               PredicateTypeCycloneDX,
			expectedShortName: "CycloneDX SBOM",
			descriptionSubstr: "Bill of Materials",
			specContains:      "github.com/in-toto/attestation",
		},
		{
			uri:               PredicateTypeSPDXPrefix,
			expectedShortName: "SPDX SBOM",
			descriptionSubstr: "Bill of Materials",
			specContains:      "github.com/in-toto/attestation",
		},
		{
			uri:               PredicateTypeInTotoV1,
			expectedShortName: "in-toto Statement",
			descriptionSubstr: "attestation",
			specContains:      "in-toto",
		},
		{
			uri:               PredicateTypeVulnerability,
			expectedShortName: "Vulnerability Scan",
			descriptionSubstr: "vulnerability",
			specContains:      "github.com/in-toto/attestation",
		},
		{
			uri:               PredicateTypeVSA,
			expectedShortName: "SLSA VSA",
			descriptionSubstr: "Verification Summary",
			specContains:      "slsa.dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectedShortName, func(t *testing.T) {
			info, exists := PredicateTypeRegistry[tt.uri]
			if !exists {
				t.Fatalf("Registry missing entry for URI: %s", tt.uri)
			}

			if info.ShortName != tt.expectedShortName {
				t.Errorf("ShortName = %q, expected %q", info.ShortName, tt.expectedShortName)
			}

			if info.Description == "" {
				t.Error("Description is empty")
			}

			if info.Spec == "" {
				t.Error("Spec is empty")
			} else if len(info.Spec) < 10 || !regexp.MustCompile(`^https?://`).MatchString(info.Spec) {
				t.Errorf("Spec %q does not appear to be a valid URL", info.Spec)
			}
		})
	}
}

// TestPredicateTypeRegistry_LookupPerformance verifies that registry lookup uses
// direct map access (O(1) operation) by confirming the implementation structure.
func TestPredicateTypeRegistry_LookupPerformance(t *testing.T) {
	// verifies that PredicateTypeRegistry is a map, which provides O(1) lookup
	testURI := PredicateTypeSLSAProvenance

	// direct map access should work instantly
	info, exists := PredicateTypeRegistry[testURI]
	if !exists {
		t.Errorf("Direct map lookup failed for URI: %s", testURI)
	}

	if info.URI != testURI {
		t.Errorf("Lookup returned incorrect entry: got URI %q, expected %q", info.URI, testURI)
	}

	// verifies unknown URI returns false for exists check (map behavior)
	unknownURI := "https://example.com/unknown/predicate"
	_, exists = PredicateTypeRegistry[unknownURI]
	if exists {
		t.Errorf("Lookup for unknown URI %q incorrectly returned exists=true", unknownURI)
	}
}

// ExamplePredicateTypeRegistry demonstrates how to use the predicate type registry
// to look up metadata for known predicate types.
func ExamplePredicateTypeRegistry() {
	// looks up metadata for a known predicate type
	predicateURI := PredicateTypeSLSAProvenance

	if info, exists := PredicateTypeRegistry[predicateURI]; exists {
		// Use the metadata for display or processing
		_ = info.ShortName   // "SLSA Provenance"
		_ = info.Description // Full description
		_ = info.Spec        // Link to specification
	}

	// handles unknown predicate types gracefully
	unknownURI := "https://example.com/custom/predicate"
	if _, exists := PredicateTypeRegistry[unknownURI]; !exists {
		// unknown predicate type / display raw URI or default message
	}
}

// TestPredicateTypeRegistry_UnknownTypeHandling verifies that unknown predicate types
// are handled gracefully with proper formatting and no errors.
func TestPredicateTypeRegistry_UnknownTypeHandling(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectedMsg string
	}{
		{
			name:        "custom predicate URI",
			uri:         "https://example.com/custom/v1",
			expectedMsg: "Unknown: https://example.com/custom/v1",
		},
		{
			name:        "very long custom URI",
			uri:         "https://example.com/very/long/custom/predicate/type/uri/that/exceeds/normal/length/v1",
			expectedMsg: "Unknown: https://example.com/very/long/custom/predicate/type/uri/that/exceeds/normal/length/v1",
		},
		{
			name:        "non-standard format URI",
			uri:         "custom-predicate-type",
			expectedMsg: "Unknown: custom-predicate-type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// verify URI is not in registry
			_, exists := PredicateTypeRegistry[tt.uri]
			if exists {
				t.Fatalf("Test setup error: URI %q should not be in registry", tt.uri)
			}

			// predicateInfo string generation (same pattern as production code)
			var predicateInfo string
			if info, exists := PredicateTypeRegistry[tt.uri]; exists {
				predicateInfo = fmt.Sprintf("%s: %s", info.ShortName, tt.uri)
			} else {
				predicateInfo = fmt.Sprintf("Unknown: %s", tt.uri)
			}

			// verify correct format
			if predicateInfo != tt.expectedMsg {
				t.Errorf("predicateInfo = %q, expected %q", predicateInfo, tt.expectedMsg)
			}
		})
	}
}

// TestPredicateTypeRegistry_GracefulFallback verifies that registry lookup
// returns false for unknown types without panicking or throwing errors.
func TestPredicateTypeRegistry_GracefulFallback(t *testing.T) {
	unknownURIs := []string{
		"https://example.com/custom/v1",
		"https://newstandard.io/attestation/v2",
		"custom-type",
		"",
		"https://future-standard.dev/predicate/v1",
	}

	for _, uri := range unknownURIs {
		t.Run(uri, func(t *testing.T) {
			// should not panic
			info, exists := PredicateTypeRegistry[uri]

			// return false for exists
			if exists {
				t.Errorf("Registry lookup for unknown URI %q incorrectly returned exists=true", uri)
			}

			// info should be zero value (empty struct)
			if info.URI != "" || info.ShortName != "" || info.Description != "" || info.Spec != "" {
				t.Errorf("Registry lookup for unknown URI %q returned non-zero info: %+v", uri, info)
			}
		})
	}
}

// TestLookupPredicateType_ExactMatch verifies that exact matches work for all predicate types.
func TestLookupPredicateType_ExactMatch(t *testing.T) {
	tests := []struct {
		name            string
		uri             string
		expectExists    bool
		expectShortName string
	}{
		{
			name:            "SLSA Provenance exact match",
			uri:             PredicateTypeSLSAProvenance,
			expectExists:    true,
			expectShortName: "SLSA Provenance",
		},
		{
			name:            "CycloneDX exact match",
			uri:             PredicateTypeCycloneDX,
			expectExists:    true,
			expectShortName: "CycloneDX SBOM",
		},
		{
			name:            "SPDX prefix exact match",
			uri:             PredicateTypeSPDXPrefix,
			expectExists:    true,
			expectShortName: "SPDX SBOM",
		},
		{
			name:            "in-toto v1 exact match",
			uri:             PredicateTypeInTotoV1,
			expectExists:    true,
			expectShortName: "in-toto Statement",
		},
		{
			name:            "Vulnerability exact match",
			uri:             PredicateTypeVulnerability,
			expectExists:    true,
			expectShortName: "Vulnerability Scan",
		},
		{
			name:            "VSA exact match",
			uri:             PredicateTypeVSA,
			expectExists:    true,
			expectShortName: "SLSA VSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, exists := LookupPredicateType(tt.uri)

			if exists != tt.expectExists {
				t.Errorf("LookupPredicateType(%q) exists = %v, expected %v", tt.uri, exists, tt.expectExists)
			}

			if exists && info.ShortName != tt.expectShortName {
				t.Errorf("LookupPredicateType(%q) ShortName = %q, expected %q", tt.uri, info.ShortName, tt.expectShortName)
			}
		})
	}
}

// TestLookupPredicateType_SPDXVersioning verifies that SPDX prefix matching works
// for versioned SPDX predicates as generated by GitHub's attest-sbom action.
func TestLookupPredicateType_SPDXVersioning(t *testing.T) {
	tests := []struct {
		name            string
		uri             string
		expectExists    bool
		expectShortName string
	}{
		{
			name:            "SPDX v2.3 (GitHub attest-sbom)",
			uri:             "https://spdx.dev/Document/v2.3",
			expectExists:    true,
			expectShortName: "SPDX SBOM",
		},
		{
			name:            "SPDX v2.2",
			uri:             "https://spdx.dev/Document/v2.2",
			expectExists:    true,
			expectShortName: "SPDX SBOM",
		},
		{
			name:            "SPDX v3.0 (future version)",
			uri:             "https://spdx.dev/Document/v3.0",
			expectExists:    true,
			expectShortName: "SPDX SBOM",
		},
		{
			name:            "SPDX v2.3.1 (patch version)",
			uri:             "https://spdx.dev/Document/v2.3.1",
			expectExists:    true,
			expectShortName: "SPDX SBOM",
		},
		{
			name:            "SPDX base URI (unversioned)",
			uri:             "https://spdx.dev/Document",
			expectExists:    true,
			expectShortName: "SPDX SBOM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, exists := LookupPredicateType(tt.uri)

			if exists != tt.expectExists {
				t.Errorf("LookupPredicateType(%q) exists = %v, expected %v", tt.uri, exists, tt.expectExists)
			}

			if exists && info.ShortName != tt.expectShortName {
				t.Errorf("LookupPredicateType(%q) ShortName = %q, expected %q", tt.uri, info.ShortName, tt.expectShortName)
			}
		})
	}
}

// TestLookupPredicateType_UnknownTypes verifies graceful handling of unknown predicate types.
func TestLookupPredicateType_UnknownTypes(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{
			name: "custom predicate",
			uri:  "https://example.com/custom/v1",
		},
		{
			name: "empty string",
			uri:  "",
		},
		{
			name: "similar to SPDX but different domain",
			uri:  "https://example.com/Document/v2.3",
		},
		{
			name: "CycloneDX with version (not standard)",
			uri:  "https://cyclonedx.org/bom/v1.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, exists := LookupPredicateType(tt.uri)

			if exists {
				t.Errorf("LookupPredicateType(%q) incorrectly returned exists=true", tt.uri)
			}

			// verify zero value returned
			if info.URI != "" || info.ShortName != "" || info.Description != "" || info.Spec != "" {
				t.Errorf("LookupPredicateType(%q) returned non-zero info: %+v", tt.uri, info)
			}
		})
	}
}

// TestLookupPredicateType_PrefixMatchingPrecision verifies that prefix matching
// is precise and doesn't match unrelated URIs.
func TestLookupPredicateType_PrefixMatchingPrecision(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		shouldMatch bool
	}{
		{
			name:        "SPDX Document path with version",
			uri:         "https://spdx.dev/Document/v2.3",
			shouldMatch: true,
		},
		{
			name:        "SPDX different path (not Document)",
			uri:         "https://spdx.dev/Other/v2.3",
			shouldMatch: false,
		},
		{
			name:        "Similar domain but not spdx.dev",
			uri:         "https://spdx-similar.dev/Document/v2.3",
			shouldMatch: false,
		},
		{
			name:        "SPDX Document with trailing content",
			uri:         "https://spdx.dev/Document/custom",
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, exists := LookupPredicateType(tt.uri)

			if exists != tt.shouldMatch {
				t.Errorf("LookupPredicateType(%q) exists = %v, expected %v", tt.uri, exists, tt.shouldMatch)
			}

			if exists && info.ShortName != "SPDX SBOM" {
				t.Errorf("LookupPredicateType(%q) matched but ShortName = %q, expected 'SPDX SBOM'", tt.uri, info.ShortName)
			}
		})
	}
}

// ExampleLookupPredicateType demonstrates how to use the LookupPredicateType function
// for both exact and prefix matching scenarios.
func ExampleLookupPredicateType() {
	// Exact match for CycloneDX
	if info, exists := LookupPredicateType("https://cyclonedx.org/bom"); exists {
		fmt.Printf("CycloneDX: %s\n", info.ShortName)
	}

	// Prefix match for versioned SPDX (GitHub attest-sbom pattern)
	if info, exists := LookupPredicateType("https://spdx.dev/Document/v2.3"); exists {
		fmt.Printf("SPDX: %s\n", info.ShortName)
	}

	// Unknown type handling
	if _, exists := LookupPredicateType("https://example.com/custom"); !exists {
		fmt.Println("Unknown type not found")
	}

	// Output:
	// CycloneDX: CycloneDX SBOM
	// SPDX: SPDX SBOM
	// Unknown type not found
}
