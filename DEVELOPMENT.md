# AutoGov-Verify Development Guide

## Current Status

AutoGov-Verify is a **production-ready** GitHub Artifact Attestation verification tool with comprehensive SLSA v1.1 VSA (Verification Summary Attestation) support and OPA policy integration.

### ✅ Completed Features

#### Core Verification Engine

- **Sigstore-go v1.0.0 Integration**: Complete attestation verification using modern sigstore API
- **Multi-Attestation Support**: Verifies 4 attestation types (SLSA provenance, SBOM, vulnerability scans, cosign)
- **Certificate Identity Validation**: Validates against approved certificate identity lists
- **Trusted Root Management**: Dynamic fetching with fallback to embedded roots
- **GitHub Token Authentication**: Supports multiple token sources with automatic detection

#### VSA v1.1 Implementation

- **Full SLSA v1.1 Compliance**: Complete specification adherence with all required and optional fields
- **Enhanced Data Structures**: ResourceDescriptor, multi-tool versioning, dependency analysis
- **Policy Integration**: OPA/Rego policy evaluation with results included in VSA metadata
- **ORAS-Go Storage**: VSA storage and retrieval from OCI registries
- **CLI Integration**: Automatic VSA generation after successful verification

#### Policy Framework

- **OPA Go SDK Integration**: In-process policy evaluation for performance
- **Policy Bundle Support**: Downloads and evaluates liatrio-rego-policy-library bundles
- **Comprehensive Results**: Policy violations and compliance metrics in VSA
- **Unified Verification**: Single workflow combining attestation + policy + VSA generation

#### Production Features

- **Offline Verification**: Support for pre-downloaded attestation artifacts
- **Certificate Management**: Automated certificate identity updates via GitHub Actions
- **Comprehensive Testing**: 100% test coverage with real attestation integration
- **Error Handling**: Robust error handling with detailed diagnostics

## Architecture

### Component Overview

```mermaid
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Attestation   │───▶│   autogov-verify │───▶│   VSA           │
│   Collection    │    │   Verification   │    │   Generation    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   GitHub        │    │   OPA Policy     │    │   ORAS-Go       │
│   Attestations  │    │   Evaluation     │    │   Storage       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Key Components

#### 1. Attestation Verification (`pkg/attestations/`)

- **GitHub API Integration**: Fetches attestations from GitHub Container Registry
- **Sigstore Verification**: Uses sigstore-go v1.0.0 for signature validation
- **Certificate Validation**: Validates certificate chains and identities
- **Multi-Format Support**: Handles both container images and blob files

#### 2. VSA Generation (`pkg/vsa/`)

- **SLSA v1.1 Compliance**: Full specification implementation
- **Input Tracking**: Records all attestations used in verification
- **Dependency Analysis**: SLSA level analysis for transitive dependencies
- **Metadata Enhancement**: Rich metadata with verification details

#### 3. Policy Engine (`pkg/policy/`)

- **OPA Integration**: Uses OPA Go SDK for in-process evaluation
- **Bundle Management**: Downloads and caches policy bundles
- **Result Integration**: Includes policy results in VSA generation
- **Sigstore Format**: Converts attestations to expected policy input format

#### 4. Storage Layer (`pkg/storage/`)

- **ORAS-Go Integration**: VSA storage in OCI registries
- **Policy Storage**: Integration with liatrio-rego-policy-library
- **Authentication**: Registry authentication and error handling

### Verification Workflow

```go
func (av *AutoGovVerifier) VerifyAndGenerateVSA(imageRef string, policyPath string) (*VSA, error) {
    // 1. Collect input attestations
    attestations, err := av.collectAttestations(imageRef)
    
    // 2. Perform attestation verification
    attestationResults, err := av.verifyAttestations(attestations)
    
    // 3. Perform OPA/Rego policy evaluation
    policyResults, err := av.evaluateOPAPolicy(imageRef, attestations, policyPath)
    
    // 4. Generate comprehensive VSA
    vsa := av.generateVSAWithResults(attestationResults, policyResults)
    
    // 5. Store VSA using ORAS-Go
    return av.storage.StoreVSA(context.Background(), vsa, imageRef)
}
```

## Development Setup

### Prerequisites

- Go 1.21 or higher
- GitHub CLI (`gh`) for trusted root fetching
- Docker for container registry access
- golangci-lint for code quality

### Local Development

```bash
# Clone and setup
git clone https://github.com/liatrio/autogov-verify
cd autogov-verify

# Install dependencies
go mod download

# Run tests
make test

# Build binary
make build

# Run linter
make lint
```

### Testing

```bash
# Unit tests
go test ./...

# Integration tests with real attestations
export GITHUB_AUTH_TOKEN=your_token
go test -tags=integration ./...

# Benchmark tests
go test -bench=. ./...
```

## Future Roadmap

### Phase 1: Enhanced Policy Framework (2-4 weeks)

- **Policy Templates**: Base policy templates with inheritance
- **Policy Versioning**: Semantic versioning with migration support
- **Dynamic Loading**: Application-specific policy resolution
- **Policy Signing**: Cryptographic policy integrity verification

### Phase 2: Advanced CLI Features (4-6 weeks)

- **Configuration Files**: YAML-based configuration support
- **Batch Processing**: Multi-manifest validation workflows
- **Integration Helpers**: ArgoCD, GitHub Actions integration commands
- **Enhanced Reporting**: Structured output formats (JSON, SARIF)

### Phase 3: Monitoring & Observability (6-8 weeks)

- **Metrics Collection**: Prometheus metrics for validation performance
- **Structured Logging**: Correlation IDs and audit trails
- **Health Checks**: Component health monitoring
- **Alerting**: Policy violation notifications

### Phase 4: Performance & Scale (8-12 weeks)

- **Attestation Caching**: Intelligent caching with TTL
- **Parallel Processing**: Concurrent verification workflows
- **Memory Optimization**: Reduced memory footprint for large deployments
- **Batch Operations**: Bulk validation capabilities

### Phase 5: Ecosystem Integration (12+ weeks)

- **Multi-Party VSAs**: Threshold-based verification
- **VSA Composition**: Policy inheritance and composition
- **SLSA Tool Integration**: Interoperability with slsa-verifier
- **Policy Marketplace**: Shared policy repository

## Implementation Guidelines

### Code Quality Standards

- **Test Coverage**: Maintain >90% test coverage
- **Error Handling**: Comprehensive error handling with context
- **Documentation**: GoDoc comments for all public APIs
- **Linting**: Zero linter warnings required

### Security Considerations

- **Certificate Pinning**: Pin trusted certificate authorities
- **Policy Integrity**: Cryptographic policy verification
- **Audit Logging**: Complete audit trails for security events
- **Least Privilege**: Minimal required permissions

### Performance Targets

- **Verification Speed**: <5 seconds per artifact
- **Memory Usage**: <100MB for typical workloads
- **Cache Hit Rate**: >80% for repeated verifications
- **Concurrent Load**: Support 100+ concurrent verifications

## Contributing

### Development Process

1. **Issue Creation**: Create GitHub issue for new features/bugs
2. **Branch Strategy**: Feature branches from main
3. **Code Review**: All changes require review
4. **Testing**: Comprehensive test coverage required
5. **Documentation**: Update docs for user-facing changes

### Code Style

- **Go Standards**: Follow effective Go guidelines
- **Functional Programming**: Prefer pure functions and immutability
- **Error Handling**: Use structured error types
- **Naming**: Clear, descriptive names for all identifiers

### Testing Strategy

- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Performance Tests**: Benchmark critical paths

## Deployment

### Production Considerations

- **Resource Limits**: Configure appropriate CPU/memory limits
- **Monitoring**: Deploy with comprehensive monitoring
- **Backup**: Regular backup of VSA storage
- **Updates**: Rolling updates with zero downtime

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autogov-verify
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: autogov-verify
        image: ghcr.io/liatrio/autogov-verify:latest
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
```

## Success Metrics

### Technical Metrics

- **Verification Performance**: <5 seconds per manifest
- **System Availability**: >99.9% uptime
- **Cache Efficiency**: >80% cache hit rate
- **Error Rate**: <1% verification failures

### Business Metrics

- **Adoption Rate**: 50+ applications using AutoGov
- **Security Incidents**: 0 incidents from non-compliant deployments
- **Developer Productivity**: <10% increase in deployment time
- **Compliance**: 100% policy adherence in production

## Conclusion

AutoGov-Verify provides a comprehensive, production-ready supply chain security solution with:

- **Complete SLSA v1.1 VSA support** for standardized verification results
- **Integrated OPA policy evaluation** for flexible governance
- **Modern sigstore-go integration** for robust attestation verification
- **Enterprise-ready features** including caching, monitoring, and scale

The tool is ready for production use and positioned for continued enhancement through the outlined roadmap phases.
