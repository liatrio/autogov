# VSA v1.1 Implementation Plan for AutoGov-Verify

## Overview

This document outlines the comprehensive implementation plan for upgrading AutoGov-Verify's Verification Summary Attestation (VSA) support to comply with SLSA v1.1 specification, using slsa-verifier as a guide for proven patterns and integrating with oras-go for storage.

## Current State Analysis

### Existing Implementation

- **Location**: `pkg/vsa/vsa.go`
- **Status**: Basic VSA v1.0 implementation
- **Issues**:
  - Missing v1.1 fields (`inputAttestations`, `dependencyLevels`, `slsaVersion`)
  - Verifier version tracking incomplete
  - No integration with oras-go or slsa-verifier
  - Limited policy support

### Dependencies Available

- ✅ `oras.land/oras-go/v2` - Already in go.mod
- ✅ `github.com/in-toto/attestation` - Already in go.mod
- ✅ `github.com/secure-systems-lab/go-securesystemslib/dsse` - For DSSE envelope handling
- ✅ `github.com/sigstore/sigstore/pkg/signature` - For signature verification

### Revised Approach: Using slsa-verifier as a Guide

After analyzing the slsa-verifier project's VSA implementation, we've determined that **adopting their proven patterns** rather than integrating as a dependency is the superior approach:

#### Important Compatibility Considerations

**Sigstore Bundle Limitation**: The slsa-verifier VSA support currently **does not work with VSAs wrapped in Sigstore bundles**, only with simple DSSE envelopes. This has implications for our GitHub Artifact Attestations integration:

- **GitHub Artifact Attestations**: Use Sigstore for signing, but we need to verify if they use Sigstore bundles or simple DSSE envelopes
- **VSA Generation**: We'll generate VSAs as simple DSSE envelopes (compatible with slsa-verifier patterns)
- **VSA Verification**: Our verification logic will handle simple DSSE envelopes with public key verification
- **Key ID Handling**: Must support both SHA256 hash key IDs and well-known identifiers

**Mitigation Strategy**:

```go
// Support both Sigstore bundles (for GitHub attestations) and simple DSSE (for VSAs)
func (v *VSAVerifier) VerifyAttestation(attestation []byte, attestationType string) error {
    switch attestationType {
    case "github-attestation":
        // Use existing Sigstore bundle verification for GitHub attestations
        return v.verifySigstoreBundle(attestation)
    case "vsa":
        // Use simple DSSE envelope verification for VSAs (slsa-verifier pattern)
        return v.verifyDSSEEnvelope(attestation)
    default:
        return fmt.Errorf("unsupported attestation type: %s", attestationType)
    }
}
```

#### Key Insights from slsa-verifier Analysis

##### **✅ Production-Ready VSA v1.1 Implementation**

- Already implements SLSA v1.1 specification correctly
- Comprehensive verification logic with proper error handling
- Extensive test coverage with real-world test data
- Follows SLSA verification best practices

##### **✅ Proven Architecture Patterns**

```go
// Clean modular design we can adopt:
verifiers/
├── verifier.go           // Main entry point
├── internal/vsa/
│   ├── verifier.go       // Core VSA verification logic
│   └── v1.0/vsa.go      // VSA data structures (v1.1 compliant)
```

##### **✅ Comprehensive Verification Workflow**

```go
// They implement the full SLSA v1.1 verification steps:
// 1. Verify DSSE envelope signature
// 2. Match subject digests with efficient parsing
// 3. Verify predicate type
// 4. Match verifier ID
// 5. Match resource URI
// 6. Confirm verification result is "PASSED"
// 7. Match verified levels with SLSA track parsing
```

##### **✅ Advanced Features We Can Adopt**

- **SLSA Level Parsing**: Sophisticated logic for `SLSA_BUILD_LEVEL_2` → track: "BUILD", level: 2
- **Multi-Digest Support**: Handles `sha256:abc123`, `gce_image_id:456`, etc.
- **Robust Error Handling**: Specific error types for different failure modes
- **DSSE Integration**: Proper envelope verification with sigstore

#### Benefits of This Approach

1. **Faster Development** - Leverage battle-tested code patterns
2. **Higher Quality** - Build on proven foundations
3. **SLSA Compliance** - Guaranteed correct implementation
4. **Maintainability** - Well-understood patterns
5. **Interoperability** - VSAs work with other SLSA tools
6. **Reduced Timeline** - 4-6 weeks instead of 8 weeks

### OPA/Rego Integration for Unified Verification

**Key Enhancement**: Integrate OPA/Rego policy evaluation directly into VSA generation, replacing separate policy validation jobs (like `rw-hp-run-opa.yaml`) with a unified verification workflow.

#### Unified Verification Workflow

```go
// Enhanced verification combining attestation and policy validation
func (av *AutoGovVerifier) VerifyAndGenerateVSA(imageRef string, policyPath string) (*VSA, error) {
    // 1. Collect input attestations
    attestations, err := av.collectAttestations(imageRef)
    if err != nil {
        return nil, err
    }
    
    // 2. Perform attestation verification
    attestationResults, err := av.verifyAttestations(attestations)
    if err != nil {
        return nil, err
    }
    
    // 3. NEW: Perform OPA/Rego policy evaluation
    policyResults, err := av.evaluateOPAPolicy(imageRef, attestations, policyPath)
    if err != nil {
        return nil, err
    }
    
    // 4. Combine results and generate comprehensive VSA
    combinedResults := combineVerificationResults(attestationResults, policyResults)
    
    vsa := &VSA{
        Predicate: VSAPredicate{
            Verifier: VSAVerifier{
                ID: "https://github.com/liatrio/autogov-verify",
                Version: map[string]string{
                    "autogov-verify": av.version,
                    "opa":            av.opaVersion,
                },
            },
            Policy: av.createPolicyDescriptor(policyPath),
            VerificationResult: determineResult(combinedResults),
            VerifiedLevels: av.determineVerifiedLevels(combinedResults),
        },
        Metadata: map[string]interface{}{
            "autogov.attestation.results": attestationResults,
            "autogov.policy.results":      policyResults,
            "autogov.policy.path":         policyPath,
        },
    }
    
    return vsa, nil
}
```

#### Benefits of Unified Approach

1. **Single Verification Job**: Replaces separate attestation and policy validation jobs
2. **Comprehensive VSA**: Includes both attestation and policy validation results
3. **Complete Audit Trail**: All verification details in one attestation
4. **Reduced CI/CD Complexity**: Fewer jobs to manage and coordinate
5. **Better Performance**: Shared context and reduced overhead
6. **Enhanced Security**: Atomic verification operation with complete results

## Implementation Phases

### Phase 1: VSA v1.1 Schema Update (Week 1-2)

#### 1.1 Update Data Structures

**Current VSA Structure Issues:**

```go
// Current (v1.0 style)
type VSAVerifier struct {
    ID      string `json:"id"`
    Version string `json:"version,omitempty"` // Single version string
}

type VSAPolicy struct {
    URI    string `json:"uri,omitempty"`
    Digest string `json:"digest,omitempty"` // Single digest string
}
```

**Target v1.1 Structure:**

```go
// Updated (v1.1 compliant)
type VSAVerifier struct {
    ID      string            `json:"id"`
    Version map[string]string `json:"version,omitempty"` // Tool version map
}

type ResourceDescriptor struct {
    URI    string            `json:"uri,omitempty"`
    Digest map[string]string `json:"digest,omitempty"` // Multi-hash support
}

type VSAPredicate struct {
    Verifier           VSAVerifier              `json:"verifier"`
    TimeVerified       *time.Time               `json:"timeVerified,omitempty"` // Optional
    ResourceURI        string                   `json:"resourceUri"`
    Policy             ResourceDescriptor       `json:"policy"`                 // NEW: ResourceDescriptor
    InputAttestations  []ResourceDescriptor     `json:"inputAttestations,omitempty"` // NEW
    VerificationResult string                   `json:"verificationResult"`
    VerifiedLevels     []string                 `json:"verifiedLevels"`
    DependencyLevels   map[string]int           `json:"dependencyLevels,omitempty"` // NEW
    SlsaVersion        string                   `json:"slsaVersion,omitempty"`      // NEW
}
```

#### 1.2 Update Generation Logic

**Enhanced VSA Generation:**

```go
func GenerateVSA(imageRef string, policyURI string, verificationResults map[string]bool, opts VSAOptions) (*VSA, error) {
    // 1. Collect input attestations used in verification
    inputAttestations := opts.InputAttestations
    
    // 2. Analyze dependencies and their SLSA levels
    dependencyLevels := analyzeDependencyLevels(opts.Dependencies)
    
    // 3. Generate v1.1 compliant VSA
    vsa := &VSA{
        Type:          "https://in-toto.io/Statement/v1",
        PredicateType: "https://slsa.dev/verification_summary/v1",
        Subject:       []VSASubject{{Name: imageRef, Digest: extractDigest(imageRef)}},
        Predicate: VSAPredicate{
            Verifier: VSAVerifier{
                ID: "https://github.com/liatrio/autogov-verify",
                Version: map[string]string{
                    "autogov-verify": opts.AutoGovVersion,
                    "slsa-verifier":  opts.SLSAVerifierVersion,
                    "oras-go":        opts.OrasGoVersion,
                },
            },
            TimeVerified: &time.Now(),
            ResourceURI:  imageRef,
            Policy: ResourceDescriptor{
                URI:    policyURI,
                Digest: opts.PolicyDigest,
            },
            InputAttestations:  inputAttestations,
            VerificationResult: determineResult(verificationResults),
            VerifiedLevels:     determineVerifiedLevels(verificationResults),
            DependencyLevels:   dependencyLevels,
            SlsaVersion:        "1.1",
        },
    }
    
    return vsa, nil
}
```

#### 1.3 Update Validation Logic

**Enhanced VSA Validation:**

```go
func ValidateVSA(vsaBytes []byte, opts ValidationOptions) (*VSA, error) {
    var vsa VSA
    if err := json.Unmarshal(vsaBytes, &vsa); err != nil {
        return nil, fmt.Errorf("failed to unmarshal VSA: %w", err)
    }

    // v1.1 validation steps
    if err := validateBasicStructure(&vsa); err != nil {
        return nil, err
    }
    
    if err := validateVerifier(&vsa.Predicate.Verifier, opts.TrustedVerifiers); err != nil {
        return nil, err
    }
    
    if err := validatePolicy(&vsa.Predicate.Policy, opts.ExpectedPolicy); err != nil {
        return nil, err
    }
    
    if err := validateInputAttestations(&vsa.Predicate.InputAttestations); err != nil {
        return nil, err
    }
    
    if err := validateVerifiedLevels(&vsa.Predicate.VerifiedLevels, opts.RequiredLevels); err != nil {
        return nil, err
    }
    
    return &vsa, nil
}
```

### Phase 2: Tool Integration (Week 3-4)

#### 2.1 ORAS-Go Integration

**VSA Storage Implementation:**

```go
package storage

import (
    "context"
    "encoding/json"
    "oras.land/oras-go/v2"
    "oras.land/oras-go/v2/registry/remote"
)

type VSAStorage struct {
    registry *remote.Registry
    repo     *remote.Repository
}

func NewVSAStorage(registryURL string) (*VSAStorage, error) {
    registry, err := remote.NewRegistry(registryURL)
    if err != nil {
        return nil, err
    }
    
    return &VSAStorage{registry: registry}, nil
}

func (s *VSAStorage) StoreVSA(ctx context.Context, vsa *VSA, imageRef string) error {
    vsaBytes, err := json.Marshal(vsa)
    if err != nil {
        return fmt.Errorf("failed to marshal VSA: %w", err)
    }
    
    // Create descriptor for VSA
    desc := oras.Descriptor{
        MediaType: "application/vnd.in-toto+json",
        Digest:    digest.FromBytes(vsaBytes),
        Size:      int64(len(vsaBytes)),
        Annotations: map[string]string{
            "org.opencontainers.image.title": "Verification Summary Attestation",
            "dev.slsa.verification_summary.version": "v1",
        },
    }
    
    // Push VSA as attestation
    return s.repo.PushReference(ctx, desc, bytes.NewReader(vsaBytes), imageRef+".vsa")
}

func (s *VSAStorage) RetrieveVSA(ctx context.Context, imageRef string) (*VSA, error) {
    // Pull VSA from registry
    desc, reader, err := s.repo.FetchReference(ctx, imageRef+".vsa")
    if err != nil {
        return nil, fmt.Errorf("failed to fetch VSA: %w", err)
    }
    defer reader.Close()
    
    vsaBytes, err := io.ReadAll(reader)
    if err != nil {
        return nil, fmt.Errorf("failed to read VSA: %w", err)
    }
    
    var vsa VSA
    if err := json.Unmarshal(vsaBytes, &vsa); err != nil {
        return nil, fmt.Errorf("failed to unmarshal VSA: %w", err)
    }
    
    return &vsa, nil
}
```

#### 2.2 Adopt slsa-verifier Verification Patterns

**Key Patterns to Adopt from slsa-verifier:**

```go
// 1. DSSE Envelope Verification (from slsa-verifier/verifiers/internal/vsa/verifier.go)
func verifyEnvelopeSignature(ctx context.Context, envelope *dsse.Envelope, verificationOpts *options.VerificationOpts) error {
    signatureVerifier, err := sigstoreSignature.LoadVerifier(verificationOpts.PublicKey, verificationOpts.PublicKeyHashAlgo)
    if err != nil {
        return fmt.Errorf("loading sigstore DSSE envelope verifier: %w", err)
    }
    
    envelopeVerifier, err := dsse.NewEnvelopeVerifier(&sigstoreDSSE.VerifierAdapter{
        SignatureVerifier: signatureVerifier,
        Pub:               verificationOpts.PublicKey,
        PubKeyID:          *verificationOpts.PublicKeyID,
    })
    if err != nil {
        return fmt.Errorf("creating sigstore DSSE envelope verifier: %w", err)
    }
    
    _, err = envelopeVerifier.Verify(ctx, envelope)
    if err != nil {
        return fmt.Errorf("verifying envelope: %w", err)
    }
    return nil
}

// 2. Subject Digest Matching (adapted from slsa-verifier)
func matchExpectedSubjectDigests(vsa *VSA, expectedDigests []string) error {
    // Collect all digests from VSA for efficient searching
    allVSASubjectDigests := make(map[string]map[string]bool)
    for _, subject := range vsa.Subject {
        for digestType, digestValue := range subject.Digest {
            if _, ok := allVSASubjectDigests[digestType]; !ok {
                allVSASubjectDigests[digestType] = make(map[string]bool)
            }
            allVSASubjectDigests[digestType][digestValue] = true
        }
    }
    
    // Search for expected digests
    for _, expectedDigest := range expectedDigests {
        parts := strings.SplitN(expectedDigest, ":", 2)
        if len(parts) != 2 {
            return fmt.Errorf("expected digest %s is not in format <type>:<value>", expectedDigest)
        }
        digestType, digestValue := parts[0], parts[1]
        
        if _, ok := allVSASubjectDigests[digestType]; !ok {
            return fmt.Errorf("expected digest not found: %s", expectedDigest)
        }
        if _, ok := allVSASubjectDigests[digestType][digestValue]; !ok {
            return fmt.Errorf("expected digest not found: %s", expectedDigest)
        }
    }
    return nil
}

// 3. SLSA Level Parsing (from slsa-verifier)
func extractSLSALevels(trackLevels []string) (map[string]int, error) {
    vsaSLSATrackLadder := make(map[string]int)
    for _, trackLevel := range trackLevels {
        if !strings.HasPrefix(trackLevel, "SLSA_") {
            continue
        }
        parts := strings.SplitN(trackLevel, "_", 4)
        if len(parts) != 4 || parts[2] != "LEVEL" {
            return nil, fmt.Errorf("invalid SLSA level: %s", trackLevel)
        }
        
        track := parts[1]
        level, err := strconv.Atoi(parts[3])
        if err != nil {
            return nil, fmt.Errorf("invalid SLSA level: %s", trackLevel)
        }
        
        if currentLevel, exists := vsaSLSATrackLadder[track]; exists {
            vsaSLSATrackLadder[track] = max(currentLevel, level)
        } else {
            vsaSLSATrackLadder[track] = level
        }
    }
    return vsaSLSATrackLadder, nil
}

// 4. Comprehensive VSA Verification (following slsa-verifier workflow)
func VerifyVSA(ctx context.Context, attestation []byte, vsaOpts *VSAOpts, verificationOpts *VerificationOpts) ([]byte, error) {
    // 1. Parse DSSE envelope
    envelope, err := utils.EnvelopeFromBytes(attestation)
    if err != nil {
        return nil, err
    }
    
    // 2. Verify envelope signature and extract VSA
    vsa, err := extractSignedVSA(ctx, envelope, verificationOpts)
    if err != nil {
        return nil, err
    }
    
    // 3. Match expected values (following SLSA v1.1 verification steps)
    err = matchExpectedValues(vsa, vsaOpts)
    if err != nil {
        return nil, err
    }
    
    // 4. Return decoded payload
    vsaBytes, err := envelope.DecodeB64Payload()
    if err != nil {
        return nil, fmt.Errorf("decoding DSSE payload: %w", err)
    }
    return vsaBytes, nil
}
```

**Benefits of Adopting These Patterns:**

- **Proven Correctness**: Battle-tested verification logic
- **SLSA Compliance**: Guaranteed v1.1 specification adherence
- **Robust Error Handling**: Comprehensive failure mode coverage
- **Performance**: Efficient digest matching and level parsing
- **Maintainability**: Well-structured, understandable code

### Phase 3: CLI Enhancement (Week 5-6)

#### 3.1 New CLI Commands

**VSA Command Structure:**

```go
// cmd/vsa.go
package cmd

import (
    "github.com/spf13/cobra"
    "github.com/liatrio/autogov-verify/pkg/vsa"
)

var vsaCmd = &cobra.Command{
    Use:   "vsa",
    Short: "VSA operations",
    Long:  "Generate, validate, and manage Verification Summary Attestations",
}

var generateVSACmd = &cobra.Command{
    Use:   "generate",
    Short: "Generate VSA for verified artifact",
    RunE:  runGenerateVSA,
}

var validateVSACmd = &cobra.Command{
    Use:   "validate",
    Short: "Validate existing VSA",
    RunE:  runValidateVSA,
}

var publishVSACmd = &cobra.Command{
    Use:   "publish",
    Short: "Publish VSA to registry",
    RunE:  runPublishVSA,
}

func init() {
    // Add VSA commands
    rootCmd.AddCommand(vsaCmd)
    vsaCmd.AddCommand(generateVSACmd)
    vsaCmd.AddCommand(validateVSACmd)
    vsaCmd.AddCommand(publishVSACmd)
    
    // Generate VSA flags
    generateVSACmd.Flags().String("image-ref", "", "Image reference")
    generateVSACmd.Flags().String("policy-uri", "", "Policy URI")
    generateVSACmd.Flags().String("output", "", "Output file path")
    generateVSACmd.Flags().Bool("publish", false, "Publish to registry")
    
    // Validate VSA flags
    validateVSACmd.Flags().String("vsa-path", "", "Path to VSA file")
    validateVSACmd.Flags().StringSlice("expected-levels", []string{}, "Expected SLSA levels")
    validateVSACmd.Flags().String("policy-uri", "", "Expected policy URI")
    
    // Publish VSA flags
    publishVSACmd.Flags().String("vsa-path", "", "Path to VSA file")
    publishVSACmd.Flags().String("registry", "", "Registry URL")
    publishVSACmd.Flags().String("image-ref", "", "Image reference")
}
```

#### 3.2 Integration with Main Verification

**Enhanced Main Command:**

```go
func run(cmd *cobra.Command, args []string) error {
    // ... existing verification logic ...
    
    // Generate VSA if requested
    if viper.GetBool("generate-vsa") {
        vsaOpts := vsa.VSAOptions{
            InputAttestations:     collectInputAttestations(sigs),
            AutoGovVersion:        getVersion(),
            SLSAVerifierVersion:   getSLSAVerifierVersion(),
            OrasGoVersion:         getOrasGoVersion(),
            PolicyDigest:          calculatePolicyDigest(policyURI),
            Dependencies:          extractDependencies(sigs),
        }
        
        generatedVSA, err := vsa.GenerateVSA(artifactDigest, policyURI, verificationResults, vsaOpts)
        if err != nil {
            return fmt.Errorf("failed to generate VSA: %w", err)
        }
        
        // Save VSA to file
        if outputPath := viper.GetString("vsa-output"); outputPath != "" {
            if err := saveVSAToFile(generatedVSA, outputPath); err != nil {
                return fmt.Errorf("failed to save VSA: %w", err)
            }
            fmt.Printf("VSA saved to: %s\n", outputPath)
        }
        
        // Publish VSA if requested
        if viper.GetBool("publish-vsa") {
            storage := storage.NewVSAStorage(viper.GetString("registry"))
            if err := storage.StoreVSA(context.Background(), generatedVSA, artifactDigest); err != nil {
                return fmt.Errorf("failed to publish VSA: %w", err)
            }
            fmt.Println("VSA published to registry")
        }
    }
    
    return nil
}
```

### Phase 4: Advanced Features (Week 7-8)

#### 4.1 Multi-Party VSA Support

```go
type MultiPartyVSA struct {
    Verifiers []VSAVerifier `json:"verifiers"`
    Threshold int           `json:"threshold"`
    Results   []VSAResult   `json:"results"`
}

func GenerateMultiPartyVSA(verifiers []Verifier, results []VerificationResult, threshold int) (*VSA, error) {
    // Aggregate results from multiple verifiers
    // Implement threshold-based verification logic
    // Generate combined VSA with multiple signatures
}
```

#### 4.2 VSA-Based Policy Composition

```go
type VSAPolicy struct {
    RequiredVerifiers []string          `json:"required_verifiers"`
    MinimumLevels     map[string]string `json:"minimum_levels"`
    DependencyRules   DependencyRules   `json:"dependency_rules"`
}

func EvaluateVSAPolicy(vsa *VSA, policy *VSAPolicy) error {
    // Evaluate VSA against policy requirements
    // Check verifier trust
    // Validate SLSA levels
    // Verify dependency requirements
}
```

## Testing Strategy

### Unit Tests

```go
func TestVSAv11Generation(t *testing.T) {
    opts := VSAOptions{
        InputAttestations: []ResourceDescriptor{
            {URI: "https://example.com/attestation1", Digest: map[string]string{"sha256": "abc123"}},
        },
        AutoGovVersion: "v1.0.0",
        PolicyDigest:   map[string]string{"sha256": "def456"},
    }
    
    vsa, err := GenerateVSA("example.com/image@sha256:123", "https://policy.example.com", 
        map[string]bool{"slsa_build": true}, opts)
    
    assert.NoError(t, err)
    assert.Equal(t, "https://slsa.dev/verification_summary/v1", vsa.PredicateType)
    assert.Equal(t, "1.1", vsa.Predicate.SlsaVersion)
    assert.NotEmpty(t, vsa.Predicate.InputAttestations)
    assert.IsType(t, map[string]string{}, vsa.Predicate.Verifier.Version)
}
```

### Integration Tests

```go
func TestOrasGoIntegration(t *testing.T) {
    // Test VSA storage and retrieval using oras-go
    storage := NewVSAStorage("localhost:5000")
    
    vsa := createTestVSA()
    err := storage.StoreVSA(context.Background(), vsa, "test-image")
    assert.NoError(t, err)
    
    retrievedVSA, err := storage.RetrieveVSA(context.Background(), "test-image")
    assert.NoError(t, err)
    assert.Equal(t, vsa.PredicateType, retrievedVSA.PredicateType)
}
```

## Documentation Updates

### API Documentation

- Update VSA struct documentation with v1.1 fields
- Document ORAS-Go integration patterns
- Provide SLSA-Verifier integration examples

### User Guide

- CLI command examples for VSA operations
- Configuration file examples
- Best practices for VSA generation and validation

### Migration Guide

- Steps to upgrade from v1.0 to v1.1
- Breaking changes and compatibility notes
- Migration scripts and tools

## Success Criteria

### Technical Requirements

- ✅ Full SLSA v1.1 VSA specification compliance
- ✅ ORAS-Go integration for registry storage
- ✅ SLSA-Verifier integration for enhanced validation
- ✅ Backward compatibility with existing VSA consumers
- ✅ Comprehensive test coverage (>90%)

### Performance Requirements

- VSA generation: < 1 second for typical artifacts
- VSA validation: < 500ms for typical VSAs
- Registry operations: < 5 seconds for push/pull

### Quality Requirements

- Zero breaking changes to existing API
- Full documentation coverage
- Integration test coverage for all major workflows

## Risk Mitigation

### Technical Risks

- **SLSA-Verifier API Changes**: Pin to specific version, monitor for updates
- **ORAS-Go Compatibility**: Test with multiple registry implementations
- **Performance Regression**: Benchmark all operations, implement caching

### Operational Risks

- **Migration Complexity**: Provide comprehensive migration tools and documentation
- **Registry Dependencies**: Support multiple storage backends
- **Backward Compatibility**: Maintain v1.0 support during transition period

## Implementation Progress

### ✅ COMPLETED (Phase 1 - Day 1)

**VSA v1.1 Schema Update:**

- ✅ Updated VSA data structures to SLSA v1.1 specification
- ✅ Added ResourceDescriptor for policy and input attestations
- ✅ Updated VSAVerifier to support multiple tool versions (map[string]string)
- ✅ Added new v1.1 fields: InputAttestations, DependencyLevels, SlsaVersion
- ✅ Made TimeVerified optional (*time.Time)
- ✅ Simplified VerificationResult to string
- ✅ Created VSAOptions struct for enhanced generation
- ✅ Added GenerateVSAWithOptions function with v1.1 features
- ✅ Added dependency level analysis function
- ✅ Updated ValidateVSA with enhanced validation
- ✅ Maintained backward compatibility with deprecated types
- ✅ All tests passing

### 🔄 NEXT STEPS (Phase 1 - Day 2)

**Complete SLSA Level Parsing Utilities:**

```go
// Add these functions to pkg/vsa/vsa.go
func ExtractSLSALevels(trackLevels []string) (map[string]int, error)
func IsSLSATrackLevel(level string) bool
func ValidateSLSALevel(level string) error
func MatchVerifiedLevels(vsa *VSA, expectedLevels []string) error
```

**Enhanced Unit Tests:**

```go
// Add comprehensive tests for v1.1 features
func TestGenerateVSAWithOptions(t *testing.T)
func TestDependencyLevelAnalysis(t *testing.T)
func TestSLSALevelParsing(t *testing.T)
func TestResourceDescriptorValidation(t *testing.T)
```

### 📋 REMAINING PHASES

| Phase | Status | Key Deliverables |
|-------|--------|------------------|
| Phase 1 | 🔄 80% Complete | VSA v1.1 schema update, enhanced generation/validation |
| Phase 2 | ⏳ Pending | ORAS-Go integration, DSSE envelope verification patterns |
| Phase 3 | ⏳ Pending | CLI enhancements, workflow integration |
| Phase 4 | ⏳ Pending | Advanced features, comprehensive testing |

**Estimated Remaining Duration**: 3-4 weeks
**Key Milestone**: Full SLSA v1.1 VSA compliance with tool integration

## Current Implementation Status

**✅ Working Features:**

- SLSA v1.1 compliant VSA data structures
- Enhanced VSA generation with options
- Dependency level analysis
- Backward compatible validation
- All existing tests passing

**🔄 In Progress:**

- SLSA level parsing utilities (imports added, functions needed)

**⏳ Next Priority:**

- Complete SLSA level parsing functions
- Add comprehensive unit tests for v1.1 features
- Begin ORAS-Go integration for VSA storage

This implementation plan provides a comprehensive roadmap for upgrading AutoGov-Verify's VSA support to SLSA v1.1 while integrating with the recommended tooling ecosystem.
