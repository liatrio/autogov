# Predicate Type Standardization

The tool implements predicate type standardization following the [in-toto attestation framework](https://github.com/in-toto/attestation) and [SLSA specifications](https://slsa.dev/spec/v1.2/). This ensures consistent, human-readable display of attestation types during verification.

## Supported Predicate Types

The tool recognizes all standard in-toto attestation framework predicate types:

| Predicate Type | Short Name | Description |
|----------------|------------|-------------|
| `https://slsa.dev/provenance/v1` | SLSA Provenance | Build provenance attestation |
| `https://cyclonedx.org/bom` | CycloneDX SBOM | Software bill of materials (CycloneDX format) |
| `https://spdx.dev/Document` | SPDX SBOM | Software bill of materials (SPDX format, version-aware) |
| `https://in-toto.io/Statement/v1` | in-toto Statement | Base in-toto attestation statement envelope |
| `https://in-toto.io/attestation/vulns/v0.2` | Vulnerability Scan | Security vulnerability scan results |
| `https://slsa.dev/verification_summary/v1` | SLSA VSA | Verification summary attestation |
| `https://autogov.dev/attestation/metadata/v1` | AutoGov Metadata | Custom autogov metadata with artifact/workflow/compliance details |
| `https://autogov.dev/attestation/code-scan/v0.1` | AutoGov Code Scan | Custom autogov static-analysis (SARIF) summary by level and security-severity |
| `https://in-toto.io/attestation/scai/v0.3` | SCAI Report | Software supply chain attribute integrity assertions |
| `https://in-toto.io/attestation/runtime-trace/v0.1` | Runtime Trace | Runtime traces of supply chain operations |
| `https://in-toto.io/attestation/release/v0.1` | Release | Release version and artifact hash linkage |
| `https://in-toto.io/attestation/test-result/v0.1` | Test Result | Test execution results |
| `https://in-toto.io/attestation/link/v0.3` | in-toto Link | Legacy in-toto 0.9 format (migration support) |
| `https://cosign.sigstore.dev/attestation/v1` | Cosign Custom | Cosign generic custom attestation |

## How It Works

During verification, the tool:

1. Extracts the predicate type URI from each attestation
2. Looks up the URI in the predicate type registry
3. Displays the short name if found, or "Unknown: \<uri\>" if not found
4. Continues verification regardless of registry status

## Graceful Handling of Unknown Types

If the tool encounters a predicate type not in the registry (e.g., custom or newly-introduced types):

- Verification proceeds normally without errors
- The type is displayed as `Unknown: <full-uri>`
- A warning is logged suggesting the registry be updated (if not in quiet mode)
- Signature and certificate validation remain unchanged

## Example Output

```shell
Verifying attestation 1 (SLSA Provenance: https://slsa.dev/provenance/v1)...
✓ Attestation 1 verified successfully
---
Verifying attestation 2 (CycloneDX SBOM: https://cyclonedx.org/bom)...
✓ Attestation 2 verified successfully
---
Verifying attestation 3 (Unknown: https://example.com/custom/v1)...
⚠ Warning: Unknown predicate type: https://example.com/custom/v1
  Consider updating PredicateTypeRegistry if this is a standard type.
✓ Attestation 3 verified successfully
```

This approach ensures backward compatibility with all attestations while providing enhanced context for known types.
