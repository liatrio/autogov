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
//   - SLSA Specification: https://slsa.dev/spec/v1/
package attestations

import "strings"

const (
	// PredicateTypeSLSAProvenance represents SLSA Provenance v1 predicate type - build provenance attestation.
	// This predicate type describes the build process and materials used to create a software artifact.
	// Compatible with SLSA v1 specifications.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/provenance.md
	PredicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"

	// PredicateTypeCycloneDX represents CycloneDX SBOM - software bill of materials.
	// This predicate type contains a comprehensive inventory of software components and dependencies.
	// Note: GitHub's attest-sbom action uses the unversioned URI in practice, though the in-toto
	// spec documents versioned URIs (e.g., /bom/v1.4).
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md
	PredicateTypeCycloneDX = "https://cyclonedx.org/bom"

	// PredicateTypeSPDXPrefix represents the SPDX SBOM predicate type prefix.
	// SPDX predicates include dynamic version suffixes (e.g., /v2.3, /v2.2) extracted from
	// the SBOM's spdxVersion field. This constant is used for prefix matching to support
	// all SPDX versions. GitHub's attest-sbom action generates versioned URIs like
	// "https://spdx.dev/Document/v2.3" based on the SBOM content.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/spdx.md
	PredicateTypeSPDXPrefix = "https://spdx.dev/Document"

	// PredicateTypeInTotoV1 represents in-toto Attestation v1 - generic attestation statement.
	// This is the base predicate type for generic in-toto attestations.
	PredicateTypeInTotoV1 = "https://in-toto.io/Statement/v1"

	// PredicateTypeVulnerability represents vulnerability scan results.
	// This predicate type contains security vulnerability scan findings for a software artifact.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/vulns_02.md
	PredicateTypeVulnerability = "https://in-toto.io/attestation/vulns/v0.2"

	// PredicateTypeVSA represents SLSA VSA v1 predicate type - verification summary attestation.
	// This predicate type summarizes the verification status of an artifact against security policies.
	// Compatible with SLSA v1 specifications.
	// Spec: https://slsa.dev/spec/v1.1/verification_summary
	PredicateTypeVSA = "https://slsa.dev/verification_summary/v1"

	// PredicateTypeAutogovMetadata represents AutoGov-specific metadata attestation.
	// This custom predicate type contains comprehensive metadata about artifacts including
	// artifact details, repository data, owner information, runner environment, workflow data,
	// job data, commit information, compliance references, and security permissions.
	// Used for AutoGov policy validation and governance workflows.
	// Spec: https://github.com/liatrio/autogov (custom predicate type)
	PredicateTypeAutogovMetadata = "https://autogov.dev/attestation/metadata/v1"

	// PredicateTypeAutogovCodeScan represents AutoGov-specific code-scan attestation.
	// This custom predicate type summarizes static analysis (SARIF) results — findings
	// bucketed by SARIF level and security-severity — for policy gating. No in-toto
	// standard exists for SARIF/code-scanning, so this mirrors the metadata precedent.
	// Spec: https://github.com/liatrio/autogov (custom predicate type)
	PredicateTypeAutogovCodeScan = "https://autogov.dev/attestation/code-scan/v0.1"

	// PredicateTypeAutogovSourceReview represents AutoGov-specific source-review attestation.
	// This custom predicate type records the human PR-review/approval evidence for the
	// source revision that produced an artifact (which PR merged it, who approved, how
	// many distinct approvals, whether self-approval was excluded, whether changes were
	// requested) — the change-management/two-person-review evidence for SLSA's source
	// track. No in-toto/SLSA standard exists for source review, so this mirrors the
	// metadata/code-scan precedent.
	// Spec: https://github.com/liatrio/autogov (custom predicate type)
	PredicateTypeAutogovSourceReview = "https://autogov.dev/attestation/source-review/v0.1"

	// PredicateTypeSCAI represents SCAI (Software Supply Chain Attribute Integrity) report.
	// This predicate type provides evidence-based assertions about software artifact and
	// supply chain attributes or behavior.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
	PredicateTypeSCAI = "https://in-toto.io/attestation/scai/v0.3"

	// PredicateTypeRuntimeTrace represents runtime traces of supply chain operations.
	// This predicate type captures system events during supply chain operations like build processes.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
	PredicateTypeRuntimeTrace = "https://in-toto.io/attestation/runtime-trace/v0.1"

	// PredicateTypeRelease represents release version details.
	// This predicate type authoritatively links release versions in package registries
	// to their corresponding artifact names and cryptographic hashes.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/release.md
	PredicateTypeRelease = "https://in-toto.io/attestation/release/v0.1"

	// PredicateTypeTestResult represents test execution results.
	// This predicate type expresses results of any type of tests run in the software supply chain.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
	PredicateTypeTestResult = "https://in-toto.io/attestation/test-result/v0.1"

	// PredicateTypeLink represents the legacy in-toto link format.
	// This predicate type is for migration from in-toto 0.9 format to the attestation framework.
	// Spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md
	PredicateTypeLink = "https://in-toto.io/attestation/link/v0.3"

	// PredicateTypeCosignCustom represents Cosign's custom attestation predicate type.
	// This is a generic predicate type used by Cosign for custom attestations that don't fit
	// into other standard predicate types. The predicate contains Data (base64-encoded bytes)
	// and Timestamp fields.
	// Note: AutoGov previously used this but now uses PredicateTypeAutogovMetadata for metadata attestations.
	// Spec: https://github.com/sigstore/cosign/blob/main/specs/COSIGN_PREDICATE_SPEC.md
	PredicateTypeCosignCustom = "https://cosign.sigstore.dev/attestation/v1"
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
	PredicateTypeSPDXPrefix: {
		URI:         PredicateTypeSPDXPrefix,
		ShortName:   "SPDX SBOM",
		Description: "SPDX Software Bill of Materials",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/spdx.md",
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
		Spec:        "https://slsa.dev/spec/v1.1/verification_summary",
	},
	PredicateTypeAutogovMetadata: {
		URI:         PredicateTypeAutogovMetadata,
		ShortName:   "AutoGov Metadata",
		Description: "AutoGov custom metadata attestation containing artifact, repository, owner, runner, workflow, and compliance information",
		Spec:        "https://github.com/liatrio/autogov",
	},
	PredicateTypeAutogovCodeScan: {
		URI:         PredicateTypeAutogovCodeScan,
		ShortName:   "AutoGov Code Scan",
		Description: "AutoGov custom code-scan attestation summarizing static analysis (SARIF) results by level and security-severity",
		Spec:        "https://github.com/liatrio/autogov",
	},
	PredicateTypeAutogovSourceReview: {
		URI:         PredicateTypeAutogovSourceReview,
		ShortName:   "AutoGov Source Review",
		Description: "AutoGov custom source-review attestation recording PR-approval evidence (approvers, distinct approvals, changes-requested) for the source revision",
		Spec:        "https://github.com/liatrio/autogov",
	},
	PredicateTypeSCAI: {
		URI:         PredicateTypeSCAI,
		ShortName:   "SCAI Report",
		Description: "Software Supply Chain Attribute Integrity report with evidence-based assertions",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md",
	},
	PredicateTypeRuntimeTrace: {
		URI:         PredicateTypeRuntimeTrace,
		ShortName:   "Runtime Trace",
		Description: "Runtime traces of supply chain operations and system events",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md",
	},
	PredicateTypeRelease: {
		URI:         PredicateTypeRelease,
		ShortName:   "Release",
		Description: "Release version details linking package registry versions to artifact hashes",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/release.md",
	},
	PredicateTypeTestResult: {
		URI:         PredicateTypeTestResult,
		ShortName:   "Test Result",
		Description: "Test execution results for software supply chain validation",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md",
	},
	PredicateTypeLink: {
		URI:         PredicateTypeLink,
		ShortName:   "in-toto Link",
		Description: "Legacy in-toto 0.9 link format for migration to attestation framework",
		Spec:        "https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md",
	},
	PredicateTypeCosignCustom: {
		URI:         PredicateTypeCosignCustom,
		ShortName:   "Cosign Custom",
		Description: "Cosign generic custom attestation predicate with Data and Timestamp fields",
		Spec:        "https://github.com/sigstore/cosign/blob/main/specs/COSIGN_PREDICATE_SPEC.md",
	},
}

// LookupPredicateType looks up predicate type metadata with support
// for prefix matching on versioned predicates (specifically SPDX).
//
// Lookup Strategy:
// 1. Exact match - Try direct registry lookup first (O(1))
// 2. Prefix match - For SPDX predicates with dynamic versions (e.g., https://spdx.dev/Document/v2.3)
//
// Handles attestations from GitHub's attest-sbom action:
//   - CycloneDX: Uses unversioned URI "https://cyclonedx.org/bom" (exact match)
//   - SPDX: Uses versioned URIs like "https://spdx.dev/Document/v2.3" (prefix match)
//
// Returns:
//   - info: PredicateTypeInfo containing metadata (ShortName, Description, Spec)
//   - exists: true if predicate type was recognized (exact or prefix match), false otherwise
//
// Example:
//
//	info, exists := LookupPredicateType("https://spdx.dev/Document/v2.3")
//	if exists {
//	    fmt.Printf("%s: %s\n", info.ShortName, predicateURI)  // "SPDX SBOM: https://spdx.dev/Document/v2.3"
//	}
func LookupPredicateType(predicateURI string) (PredicateTypeInfo, bool) {
	// Try exact match first (O(1))
	if info, exists := PredicateTypeRegistry[predicateURI]; exists {
		return info, true
	}

	// Try prefix matching for SPDX (supports dynamic versioning)
	if strings.HasPrefix(predicateURI, PredicateTypeSPDXPrefix) {
		if info, exists := PredicateTypeRegistry[PredicateTypeSPDXPrefix]; exists {
			return info, true
		}
	}

	// No match found
	return PredicateTypeInfo{}, false
}
