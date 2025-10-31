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

// Package attestations provides GitHub artifact attestation verification functionality
// using the Sigstore ecosystem, with standardized predicate type handling.
//
// # Predicate Type Standardization
//
// This package implements predicate type standardization following the in-toto attestation
// framework and SLSA specifications. Predicate types are identified by full URIs to ensure
// consistency with official specifications and eliminate ambiguity.
//
// The standardization approach includes:
//   - Constants for all standard predicate type URIs (PredicateTypeSLSAProvenance, etc.)
//   - PredicateTypeRegistry for O(1) lookup of predicate type metadata
//   - Graceful degradation for unknown predicate types
//
// Usage Pattern:
//
//	// Lookup predicate type metadata
//	if info, exists := PredicateTypeRegistry[predicateURI]; exists {
//	    fmt.Printf("Verifying %s: %s\n", info.ShortName, info.URI)
//	} else {
//	    // Graceful fallback for unknown types
//	    fmt.Printf("Verifying Unknown: %s\n", predicateURI)
//	}
//
// Verification continues regardless of whether the predicate type is in the registry.
// Unknown types display "Unknown: <uri>" and log a warning, but do not block verification.
//
// References:
//   - in-toto Attestation Framework: https://github.com/in-toto/attestation
//   - SLSA Specification: https://slsa.dev/spec/v1.0/
package attestations

const (
	// PredicateTypeSLSAProvenance represents SLSA Provenance v1.0 - build provenance attestation.
	// This predicate type describes the build process and materials used to create a software artifact.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/provenance.md
	PredicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"

	// PredicateTypeCycloneDX represents CycloneDX SBOM - software bill of materials.
	// This predicate type contains a comprehensive inventory of software components and dependencies.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md
	PredicateTypeCycloneDX = "https://cyclonedx.org/bom"

	// PredicateTypeSPDX represents SPDX SBOM - alternative SBOM format.
	// This predicate type provides software package data in the SPDX standard format.
	PredicateTypeSPDX = "https://spdx.dev/Document"

	// PredicateTypeInTotoV1 represents in-toto Attestation v1 - generic attestation statement.
	// This is the base predicate type for generic in-toto attestations.
	PredicateTypeInTotoV1 = "https://in-toto.io/Statement/v1"

	// PredicateTypeVulnerability represents vulnerability scan results.
	// This predicate type contains security vulnerability scan findings for a software artifact.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/vulns_02.md
	PredicateTypeVulnerability = "https://in-toto.io/attestation/vulns/v0.2"

	// PredicateTypeVSA represents SLSA VSA v1.0 - verification summary attestation.
	// This predicate type summarizes the verification status of an artifact against security policies.
	// Spec: https://slsa.dev/spec/v1.0/verification_summary
	PredicateTypeVSA = "https://slsa.dev/verification_summary/v1"
)

// PredicateTypeInfo provides metadata about a predicate type, including its human-readable
// name, description, and specification link. This metadata is used to enhance CLI output
// and provide context for attestation verification results.
type PredicateTypeInfo struct {
	// URI is the full predicate type URI (matches the constant value)
	URI string

	// ShortName is a human-readable short name for display purposes (e.g., "SLSA Provenance")
	ShortName string

	// Description provides a concise explanation of what this predicate type represents
	Description string

	// Spec is a link to the official specification document for this predicate type
	Spec string
}

// PredicateTypeRegistry maps predicate type URIs to their metadata, enabling O(1) lookup
// of human-readable names, descriptions, and specification links for known predicate types.
// This registry is initialized at package load time and contains all standard predicate types
// defined by the in-toto attestation framework and SLSA specification.
//
// Graceful Degradation:
// The registry lookup is non-blocking. When a predicate type is not found in the registry,
// verification continues normally with the type displayed as "Unknown: <uri>". A warning
// is logged to stderr suggesting the registry be updated if the type is a standard one.
// This ensures backward compatibility and allows verification of custom or newly-introduced
// predicate types without system failures.
//
// Usage Example:
//
//	// Lookup with graceful fallback
//	var predicateInfo string
//	if info, exists := PredicateTypeRegistry[predicateURI]; exists {
//	    predicateInfo = fmt.Sprintf("%s: %s", info.ShortName, info.URI)
//	} else {
//	    predicateInfo = fmt.Sprintf("Unknown: %s", predicateURI)
//	    if !quiet {
//	        fmt.Fprintf(os.Stderr, "⚠ Warning: Unknown predicate type: %s\n", predicateURI)
//	    }
//	}
//	fmt.Printf("Verifying attestation (%s)...\n", predicateInfo)
//	// Continue with verification regardless of registry status
//
// See Stories 1.3-1.4 for implementation details of output formatting and graceful handling.
var PredicateTypeRegistry = map[string]PredicateTypeInfo{
	PredicateTypeSLSAProvenance: {
		URI:         PredicateTypeSLSAProvenance,
		ShortName:   "SLSA Provenance",
		Description: "SLSA Build Provenance attestation describing how an artifact was built",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/provenance.md",
	},
	PredicateTypeCycloneDX: {
		URI:         PredicateTypeCycloneDX,
		ShortName:   "CycloneDX SBOM",
		Description: "CycloneDX Software Bill of Materials",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md",
	},
	PredicateTypeSPDX: {
		URI:         PredicateTypeSPDX,
		ShortName:   "SPDX SBOM",
		Description: "SPDX Software Bill of Materials",
		Spec:        "https://spdx.dev/",
	},
	PredicateTypeInTotoV1: {
		URI:         PredicateTypeInTotoV1,
		ShortName:   "in-toto Statement",
		Description: "Generic in-toto attestation statement",
		Spec:        "https://github.com/in-toto/attestation",
	},
	PredicateTypeVulnerability: {
		URI:         PredicateTypeVulnerability,
		ShortName:   "Vulnerability Scan",
		Description: "Security vulnerability scan results for a software artifact",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/vulns_02.md",
	},
	PredicateTypeVSA: {
		URI:         PredicateTypeVSA,
		ShortName:   "SLSA VSA",
		Description: "SLSA Verification Summary Attestation",
		Spec:        "https://slsa.dev/spec/v1.0/verification_summary",
	},
}
