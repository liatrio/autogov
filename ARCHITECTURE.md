# AutoGov Architecture Deep Dive

## System Overview

AutoGov implements a comprehensive supply chain security framework with multiple validation layers:

```mermaid
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Developer     │    │   CI/CD Pipeline │    │   Kubernetes    │
│   Workstation   │───▶│   Validation     │───▶│   Admission     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Pre-commit    │    │   autogov-gate   │    │   Kyverno       │
│   Hooks         │    │   CLI Tool       │    │   Policies      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                       ┌──────────────────┐
                       │   autogov-verify │
                       │   Library        │
                       └──────────────────┘
                                  │
                                  ▼
                       ┌──────────────────┐
                       │   Sigstore       │
                       │   Verification   │
                       └──────────────────┘
```

## Component Responsibilities

### autogov-gate CLI

- **Purpose**: Primary deployment gating tool
- **Responsibilities**:
  - Manifest validation against policies
  - Image digest verification
  - Attestation retrieval and validation
  - Policy evaluation using OPA/Rego
- **Integration Points**: CI/CD pipelines, ArgoCD pre-sync hooks

### autogov-verify Library

- **Purpose**: Core attestation verification engine
- **Responsibilities**:
  - Sigstore signature verification
  - Certificate chain validation
  - Attestation parsing and validation
  - GitHub Actions workflow verification
- **Future**: VSA (Verification Summary Attestation) support

### Policy Engine (OPA/Rego)

- **Purpose**: Flexible policy evaluation integrated with VSA generation
- **Responsibilities**:
  - Custom rule definition and evaluation
  - Policy composition and inheritance
  - Violation reporting and attestation
  - **NEW**: Policy validation results included in VSA generation
- **Integration**: Unified verification job combining attestation verification and policy evaluation
- **Extensibility**: Custom functions via Go integration

## Security Model

### Trust Boundaries

1. **Developer Environment**: Pre-commit validation
2. **CI/CD Pipeline**: Automated policy enforcement
3. **Kubernetes Cluster**: Runtime admission control

### Attestation Chain

```mermaid
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Build System  │───▶│   Container      │───▶│   Deployment    │
│   Attestations  │    │   Registry       │    │   Validation    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
    SLSA Provenance          Vulnerability           Policy Compliance
    SBOM Generation           Scan Results            Verification
    Code Signing             Attestation Storage      Runtime Checks
```

## VSA Integration (SLSA v1.1)

### Verification Summary Attestation (VSA)

AutoGov implements SLSA v1.1 compliant VSAs to provide:

- **Aggregated Verification Results**: Single attestation summarizing all checks
- **Policy Compliance Statements**: Formal assertions about policy adherence
- **Audit Trail**: Complete verification history with input attestations
- **Cross-System Interoperability**: Standard format for verification results
- **Dependency Analysis**: SLSA level tracking for transitive dependencies

### VSA Architecture

```mermaid
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Attestation   │───▶│   autogov-verify │───▶│   VSA           │
│   Collection    │    │   Verification   │    │   Generation    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   GitHub        │    │   SLSA-Verifier  │    │   ORAS-Go       │
│   Attestations  │    │   Integration    │    │   Storage       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### VSA v1.1 Schema Implementation

```go
type VSA struct {
    Type          string                 `json:"_type"`
    PredicateType string                 `json:"predicateType"`
    Subject       []VSASubject           `json:"subject"`
    Predicate     VSAPredicate           `json:"predicate"`
}

type VSAPredicate struct {
    Verifier           VSAVerifier              `json:"verifier"`
    TimeVerified       *time.Time               `json:"timeVerified,omitempty"`
    ResourceURI        string                   `json:"resourceUri"`
    Policy             ResourceDescriptor       `json:"policy"`
    InputAttestations  []ResourceDescriptor     `json:"inputAttestations,omitempty"`
    VerificationResult string                   `json:"verificationResult"`
    VerifiedLevels     []string                 `json:"verifiedLevels"`
    DependencyLevels   map[string]int           `json:"dependencyLevels,omitempty"`
    SlsaVersion        string                   `json:"slsaVersion,omitempty"`
}

type VSAVerifier struct {
    ID      string            `json:"id"`
    Version map[string]string `json:"version,omitempty"`
}

type ResourceDescriptor struct {
    URI    string            `json:"uri,omitempty"`
    Digest map[string]string `json:"digest,omitempty"`
}
```

### Implementation Roadmap

#### Phase 1: VSA v1.1 Schema Update (Week 1-2)

- Update VSA data structures to v1.1 specification
- Implement ResourceDescriptor for policy and input attestations
- Add verifier version tracking and SLSA version support
- Enhance dependency level counting

#### Phase 2: Tool Integration (Week 3-4)

- **ORAS-Go Integration**: VSA storage and retrieval from OCI registries
- **SLSA-Verifier Integration**: Leverage existing verification capabilities
- **Policy Enhancement**: Support external policy files with digest verification
- **Input Attestation Tracking**: Record all attestations used in verification

#### Phase 3: CLI Enhancement (Week 5-6)

- New CLI commands: `generate-vsa`, `validate-vsa`, `publish-vsa`
- Automatic VSA generation after successful verification
- VSA caching for performance optimization
- Integration with existing certificate identity validation

#### Phase 4: Advanced Features (Week 7-8)

- Multi-party VSA signing and verification
- VSA-based policy composition and inheritance
- Cross-system VSA consumption
- Comprehensive testing and documentation

### Integration Points

#### ORAS-Go Integration

```go
// VSA storage using ORAS-Go
func (s *VSAStorage) StoreVSA(ctx context.Context, vsa *VSA, target string) error {
    vsaBytes, err := json.Marshal(vsa)
    if err != nil {
        return err
    }
    
    return s.orasClient.Push(ctx, target, vsaBytes, "application/vnd.in-toto+json")
}

func (s *VSAStorage) RetrieveVSA(ctx context.Context, target string) (*VSA, error) {
    vsaBytes, err := s.orasClient.Pull(ctx, target)
    if err != nil {
        return nil, err
    }
    
    var vsa VSA
    return &vsa, json.Unmarshal(vsaBytes, &vsa)
}
```

#### SLSA-Verifier Pattern Adoption

**Important**: slsa-verifier VSA support currently **does not work with VSAs wrapped in Sigstore bundles**, only with simple DSSE envelopes. Our implementation will:

- Generate VSAs as simple DSSE envelopes (compatible with slsa-verifier patterns)
- Maintain separate verification paths for GitHub Artifact Attestations (Sigstore bundles) and VSAs (DSSE envelopes)
- Support both SHA256 hash key IDs and well-known identifiers for key management

```go
// Adopt proven verification patterns from slsa-verifier
func (v *VSAValidator) VerifyVSAWithProvenPatterns(ctx context.Context, attestation []byte, opts *VSAOpts) ([]byte, error) {
    // 1. Parse DSSE envelope (slsa-verifier pattern)
    envelope, err := utils.EnvelopeFromBytes(attestation)
    if err != nil {
        return nil, err
    }
    
    // 2. Verify envelope signature (slsa-verifier pattern)
    vsa, err := v.extractSignedVSA(ctx, envelope, opts.VerificationOpts)
    if err != nil {
        return nil, err
    }
    
    // 3. Comprehensive field validation (slsa-verifier pattern)
    if err := v.matchExpectedValues(vsa, opts); err != nil {
        return nil, err
    }
    
    // 4. SLSA level parsing (slsa-verifier pattern)
    if err := v.validateSLSALevels(vsa.Predicate.VerifiedLevels, opts.ExpectedLevels); err != nil {
        return nil, err
    }
    
    return envelope.DecodeB64Payload()
}

// Subject digest matching with slsa-verifier efficiency patterns
func (v *VSAValidator) matchSubjectDigests(vsa *VSA, expectedDigests []string) error {
    // Efficient digest collection pattern from slsa-verifier
    allDigests := make(map[string]map[string]bool)
    for _, subject := range vsa.Subject {
        for digestType, digestValue := range subject.Digest {
            if _, ok := allDigests[digestType]; !ok {
                allDigests[digestType] = make(map[string]bool)
            }
            allDigests[digestType][digestValue] = true
        }
    }
    
    // Efficient search pattern from slsa-verifier
    for _, expected := range expectedDigests {
        parts := strings.SplitN(expected, ":", 2)
        if len(parts) != 2 {
            return fmt.Errorf("invalid digest format: %s", expected)
        }
        digestType, digestValue := parts[0], parts[1]
        
        if !allDigests[digestType][digestValue] {
            return fmt.Errorf("expected digest not found: %s", expected)
        }
    }
    return nil
}
```

#### Enhanced Verification Workflow with OPA/Rego Integration

```go
func (av *AutoGovVerifier) VerifyAndGenerateVSA(imageRef string, policyPath string) (*VSA, error) {
    // 1. Collect input attestations
    attestations, err := av.collectAttestations(imageRef)
    if err != nil {
        return nil, err
    }
    
    // 2. Perform attestation verification using existing logic
    attestationResults, err := av.verifyAttestations(attestations)
    if err != nil {
        return nil, err
    }
    
    // 3. NEW: Perform OPA/Rego policy evaluation
    policyResults, err := av.evaluateOPAPolicy(imageRef, attestations, policyPath)
    if err != nil {
        return nil, err
    }
    
    // 4. Combine attestation and policy results
    combinedResults := combineVerificationResults(attestationResults, policyResults)
    
    // 5. Generate VSA with v1.1 compliance including policy validation
    vsa := &VSA{
        Type:          "https://in-toto.io/Statement/v1",
        PredicateType: "https://slsa.dev/verification_summary/v1",
        Subject:       []VSASubject{{Name: imageRef, Digest: extractDigest(imageRef)}},
        Predicate: VSAPredicate{
            Verifier: VSAVerifier{
                ID: "https://github.com/liatrio/autogov-verify",
                Version: map[string]string{
                    "autogov-verify": av.version,
                    "opa":            av.opaVersion,
                    "slsa-verifier":  av.slsaVerifierVersion,
                },
            },
            TimeVerified:       &time.Now(),
            ResourceURI:        imageRef,
            Policy:             av.createPolicyDescriptor(policyPath),
            InputAttestations:  av.inputAttestationDescriptors,
            VerificationResult: determineResult(combinedResults),
            VerifiedLevels:     av.determineVerifiedLevels(combinedResults),
            DependencyLevels:   av.analyzeDependencies(attestations),
            SlsaVersion:        "1.1",
        },
        Metadata: map[string]interface{}{
            "autogov.attestation.results": attestationResults,
            "autogov.policy.results":      policyResults,
            "autogov.policy.path":         policyPath,
        },
    }
    
    // 6. Store VSA using ORAS-Go
    if err := av.storage.StoreVSA(context.Background(), vsa, imageRef); err != nil {
        return nil, err
    }
    
    return vsa, nil
}

// evaluateOPAPolicy performs OPA/Rego policy evaluation as part of verification
func (av *AutoGovVerifier) evaluateOPAPolicy(imageRef string, attestations [][]byte, policyPath string) (map[string]bool, error) {
    // Load and compile Rego policy
    policy, err := av.loadRegoPolicy(policyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load policy: %w", err)
    }
    
    // Prepare input data for policy evaluation
    input := map[string]interface{}{
        "image":        imageRef,
        "attestations": attestations,
        "metadata":     av.collectMetadata(imageRef),
    }
    
    // Evaluate policy
    results, err := policy.Eval(context.Background(), input)
    if err != nil {
        return nil, fmt.Errorf("policy evaluation failed: %w", err)
    }
    
    // Convert results to verification format
    return av.convertPolicyResults(results), nil
}

// createPolicyDescriptor creates a ResourceDescriptor for the policy
func (av *AutoGovVerifier) createPolicyDescriptor(policyPath string) ResourceDescriptor {
    policyContent, err := av.readPolicyFile(policyPath)
    if err != nil {
        return ResourceDescriptor{URI: policyPath}
    }
    
    policyHash := av.calculateHash(policyContent)
    return ResourceDescriptor{
        URI: policyPath,
        Digest: map[string]string{
            "sha256": policyHash,
        },
    }
}

// combineVerificationResults merges attestation and policy verification results
func combineVerificationResults(attestationResults, policyResults map[string]bool) map[string]bool {
    combined := make(map[string]bool)
    
    // Add attestation results
    for key, value := range attestationResults {
        combined["attestation."+key] = value
    }
    
    // Add policy results
    for key, value := range policyResults {
        combined["policy."+key] = value
    }
    
    return combined
}
```

### Unified Verification Job Benefits

**Replaces Separate OPA Job**: Instead of running attestation verification and policy evaluation as separate jobs (like `rw-hp-run-opa.yaml`), the unified approach provides:

1. **Single Verification Point**: One job that performs both attestation and policy verification
2. **Comprehensive VSA**: VSA includes both attestation and policy validation results
3. **Audit Trail**: Complete verification history in a single attestation
4. **Reduced Complexity**: Fewer CI/CD jobs to manage and coordinate
5. **Better Performance**: Shared context and reduced overhead
6. **Enhanced Security**: Atomic verification operation with complete results

## Performance Considerations

### Caching Strategy

- **Attestation Caching**: Reduce redundant Sigstore queries
- **Policy Compilation**: Cache compiled Rego policies
- **Certificate Validation**: Cache trusted certificate chains

### Scalability

- **Parallel Processing**: Concurrent attestation verification
- **Batch Operations**: Bulk manifest validation
- **Resource Limits**: Configurable memory and CPU constraints

## Monitoring and Observability

### Metrics

- Validation success/failure rates
- Attestation verification latency
- Policy evaluation performance
- Cache hit/miss ratios

### Logging

- Structured logging with correlation IDs
- Audit trails for all validation decisions
- Security event logging for violations

### Alerting

- Policy violation notifications
- System health monitoring
- Performance degradation alerts
