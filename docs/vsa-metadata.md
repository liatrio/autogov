# VSA metadata structure

The generated VSA records verification and policy-evaluation metadata:

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

## Predicate and specification versions

The VSA predicate type is `https://slsa.dev/verification_summary/v1`, as
described in the [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/verification_summary).
The URI's `/v1` identifies the predicate's major schema version. Compatible
minor revisions of the specification retain that URI.

The separate `predicate.slsaVersion` field records the SLSA specification
version used by the verifier. Both artifact and source VSAs currently emit
`"slsaVersion": "1.1"`. References here to the SLSA v1.2 documentation do not
change that emitted value or the `/v1` predicate URI.

## Offline input-attestation binding

When offline verification generates a VSA, every verified statement admitted
to OPA evaluation is also recorded in `predicate.inputAttestations`. Its
resource descriptor uses the exact DSSE payload bytes:

```json
{
  "uri": "urn:attestation:sha256:<payload-sha256>",
  "digest": {"sha256": "<payload-sha256>"}
}
```

This applies to every predicate type handled by the offline path. The resource
URI identifies one immutable statement; it is not the statement's
`predicateType` and it is not a schema URL. Predicate types still contribute
separately to the VSA's verification facts. Offline VSA output remains
unsigned. The standalone
[`agent-governance-evidence`](https://github.com/liatrio/agent-governance-evidence)
repository exercises this generic contract with a custom deployment statement
and a standard test-result statement; `autogov` contains no
companion-specific input-binding code.

## Metadata fields

- **`autogov.policy.evaluation`**: Policy result, violations, and bundle details
- **`autogov.policy.violation_summary`**: Violations grouped by policy type
- **`autogov.policy.metrics`**: Counts and timing
- **`autogov.verification.details`**: Verification results by predicate type

## VSA generation with policy evaluation

The tool generates Verification Summary Attestations (VSAs) using the
`https://slsa.dev/verification_summary/v1` predicate and can include OPA policy
evaluation:

```go
// Verification workflow
1. Collect attestations from GitHub
2. Verify signatures using sigstore-go
3. Evaluate OPA/Rego policies
4. Generate VSA
5. Write VSA to output file
```

Key behavior:

- **Validation**: Structured field validation
- **SLSA level parsing**: Track extraction such as `SLSA_BUILD_LEVEL_3`
- **Multi-format digest support**: Validation for hashes beyond SHA-256
- **Policy integration**: OPA results recorded in VSA metadata

The tool validates against the official SLSA Build track levels (L0-L3) in the
[SLSA v1.2 specification](https://slsa.dev/spec/v1.2/about).
