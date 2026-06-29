# VSA Metadata Structure

The generated VSA includes comprehensive metadata about the verification and policy evaluation:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [...],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": {...},
    "timeVerified": "2024-01-20T15:30:00Z",
    "policy": {...},
    "inputAttestations": [...],
    "verificationResult": "PASSED",
    "verifiedLevels": [...]
  },
  "metadata": {
    "autogov.policy.evaluation": {
      "result": "PASSED",
      "violations": [],
      "evaluation_time": "2024-01-20T15:30:00Z",
      "policy_bundle": "ghcr.io/liatrio/autogov-policy-library:latest",
      "opa_version": "v1.17.1",
      "governance_rules": ["governance.allow", "governance.violations"],
      "details": {
        "total_policies": 15,
        "policies_evaluated": 15,
        "policies_passed": 15
      }
    },
    "autogov.policy.violation_summary": {...},
    "autogov.policy.metrics": {
      "total_violations": 0,
      "compliance_status": "PASSED",
      "input_attestations": 4,
      "evaluation_duration": 125
    },
    "autogov.verification.details": {
      "attestation.slsa_provenance": true,
      "attestation.sbom": true,
      "attestation.vulnerability": true,
      "attestation.metadata": true
    }
  }
}
```

## Metadata Fields

- **`autogov.policy.evaluation`**: Core policy evaluation results including pass/fail status, violations, and policy details
- **`autogov.policy.violation_summary`**: Violations grouped by policy type for quick identification of issues
- **`autogov.policy.metrics`**: Compliance metrics and statistics for reporting
- **`autogov.verification.details`**: Attestation verification results by type

## VSA Generation with Policy Evaluation

The tool generates SLSA v1.2 compliant Verification Summary Attestations (VSAs) with integrated OPA policy evaluation:

```go
// Verification workflow
1. Collect attestations from GitHub
2. Verify signatures using sigstore-go
3. Evaluate OPA/Rego policies
4. Generate comprehensive VSA
5. Write VSA to output file
```

**Enhanced VSA Features:**

- **Comprehensive Validation**: Detailed field validation with structured error types
- **SLSA Level Parsing**: Robust parsing of SLSA levels with track extraction (e.g., `SLSA_BUILD_LEVEL_3`)
- **Multi-Format Digest Support**: Validation for multiple hash algorithms beyond SHA256
- **Policy Integration**: OPA policy evaluation results included in VSA metadata

**SLSA v1.2 Compliance**: The tool validates against official SLSA Build track levels (L0-L3) as defined in the [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/about)
