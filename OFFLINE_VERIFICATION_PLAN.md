# Offline Verification Development Plan

## Overview

Enable `autogov-verify` to verify attestations offline, similar to GitHub CLI's offline verification capability. This allows verification in air-gapped environments or when API access is unavailable.

## Current State

- ✅ Trusted root available (`pkg/root/github-trusted-root.json`)
- ❌ Requires GitHub API for attestation fetching
- ❌ Requires online Sigstore/Fulcio verification
- ❌ No local attestation storage

## Architecture Changes

### 1. Attestation Bundle Management

#### 1.1 Download Command

```go
// cmd/download.go
autogov-verify download --artifact <path|digest> --output <bundle.jsonl>
autogov-verify download --repo owner/repo --tag v1.0.0 --output <bundle.jsonl>
```

- Fetch attestations from GitHub API
- Save as Sigstore bundle format (JSONL)
- Include all attestation types (SLSA, SBOM, vulnerability, custom)

#### 1.2 Bundle Storage Format

```json
// Each line in bundle.jsonl
{
  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
  "verificationMaterial": {...},
  "messageSignature": {...},
  "dsseEnvelope": {...}
}
```

### 2. Offline Verification Implementation

#### 2.1 New Package Structure

```
pkg/
├── offline/
│   ├── verifier.go       # Main offline verification logic
│   ├── bundle.go          # Bundle parsing and validation
│   └── trust.go           # Trusted root handling
├── root/
│   └── github-trusted-root.json  # Existing trusted root
```

#### 2.2 Core Verification Logic

```go
// pkg/offline/verifier.go
type OfflineVerifier struct {
    trustedRoot *root.TrustedRoot
    bundles     []Bundle
}

func (v *OfflineVerifier) Verify(artifactPath string) (*VerificationResult, error) {
    // 1. Calculate artifact digest
    // 2. Load bundles from file
    // 3. Verify signatures using trusted root
    // 4. Validate certificate chains
    // 5. Check policy compliance
}
```

### 3. CLI Command Structure

#### 3.1 New Commands

```bash
# Download attestations for later offline use
autogov-verify download \
  --artifact bundle.tar.gz \
  --repo liatrio/liatrio-rego-policy-library \
  --output attestations.jsonl

# Verify offline using downloaded attestations
autogov-verify verify-offline \
  --artifact bundle.tar.gz \
  --attestations attestations.jsonl \
  --cert-identity "https://github.com/org/repo/.github/workflows/build.yaml@refs/heads/main"
```

#### 3.2 Modified Verify Command

```bash
# Add offline flag to existing verify command
autogov-verify verify \
  --artifact bundle.tar.gz \
  --offline \
  --attestations attestations.jsonl
```

## Implementation Phases

### Phase 1: Foundation (Week 1-2)

- [ ] Create `pkg/offline` package structure
- [ ] Implement bundle parser for Sigstore format
- [ ] Add trusted root loader and validator
- [ ] Create attestation storage interface

### Phase 2: Download Capability (Week 2-3)

- [ ] Implement `download` command
- [ ] Add GitHub API attestation fetcher
- [ ] Support multiple artifact types (blob, container)
- [ ] Create bundle writer with proper formatting

### Phase 3: Offline Verification (Week 3-4)

- [ ] Implement offline verifier using trusted root
- [ ] Add certificate chain validation
- [ ] Port existing policy evaluation to offline mode
- [ ] Handle multiple attestation types

### Phase 4: CLI Integration (Week 4-5)

- [ ] Add `verify-offline` command
- [ ] Modify existing `verify` with `--offline` flag
- [ ] Add progress indicators and error handling
- [ ] Update help documentation

### Phase 5: Testing & Documentation (Week 5-6)

- [ ] Unit tests for offline verification
- [ ] Integration tests with sample bundles
- [ ] Update README with offline examples
- [ ] Add troubleshooting guide

## Code Examples

### Download Implementation

```go
// pkg/offline/download.go
func DownloadAttestations(ctx context.Context, opts DownloadOptions) error {
    client := github.NewClient(nil).WithAuthToken(opts.Token)
    
    // Fetch attestations
    attestations, err := client.GetAttestations(opts.Digest)
    if err != nil {
        return fmt.Errorf("failed to fetch attestations: %w", err)
    }
    
    // Convert to Sigstore bundles
    bundles := make([]Bundle, 0, len(attestations))
    for _, att := range attestations {
        bundle := convertToBundle(att)
        bundles = append(bundles, bundle)
    }
    
    // Write to file
    return writeBundles(opts.Output, bundles)
}
```

### Offline Verification

```go
// pkg/offline/verify.go
func VerifyOffline(artifactPath, bundlePath string, certIdentity string) error {
    // Load trusted root
    trustedRoot, err := root.LoadTrustedRoot()
    if err != nil {
        return err
    }
    
    // Load bundles
    bundles, err := LoadBundles(bundlePath)
    if err != nil {
        return err
    }
    
    // Calculate artifact digest
    digest, err := calculateDigest(artifactPath)
    if err != nil {
        return err
    }
    
    // Verify each bundle
    for _, bundle := range bundles {
        // Verify signature
        if err := verifySignature(bundle, trustedRoot); err != nil {
            continue
        }
        
        // Verify certificate identity
        if err := verifyCertIdentity(bundle, certIdentity); err != nil {
            continue
        }
        
        // Check digest matches
        if bundle.Subject != digest {
            continue
        }
        
        return nil // Success
    }
    
    return fmt.Errorf("no valid attestations found")
}
```

## Testing Strategy

### Unit Tests

- Bundle parsing and validation
- Signature verification with mock data
- Certificate chain validation
- Policy evaluation

### Integration Tests

- Download real attestations from GitHub
- Verify known good/bad bundles
- Test with different artifact types
- Validate error handling

### Test Data

```bash
testdata/
├── bundles/
│   ├── valid-bundle.jsonl
│   ├── invalid-signature.jsonl
│   └── expired-cert.jsonl
├── artifacts/
│   ├── test-blob.tar.gz
│   └── test-image.tar
```

## Dependencies

### Required Libraries

- `github.com/sigstore/sigstore-go` - Sigstore verification
- `github.com/secure-systems-lab/go-securesystemslib` - TUF/trusted root
- Existing GitHub client library

### Configuration

```yaml
# .autogov-verify.yaml
offline:
  trusted_root: pkg/root/github-trusted-root.json
  bundle_cache: ~/.autogov-verify/bundles/
  verify_tlog: false  # Skip transparency log in offline mode
```

## Success Criteria

- [ ] Can download attestations for any GitHub artifact
- [ ] Offline verification produces same results as online
- [ ] Works in air-gapped environments
- [ ] Performance: <1s for typical verification
- [ ] Clear error messages for troubleshooting

## Migration Guide

```bash
# Before (online only)
autogov-verify verify --artifact bundle.tar.gz

# After (offline capable)
# Step 1: Download while online
autogov-verify download --artifact bundle.tar.gz -o bundle.jsonl

# Step 2: Verify offline
autogov-verify verify --artifact bundle.tar.gz --offline --attestations bundle.jsonl
```

## References

- [GitHub Offline Verification Docs](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
- [Sigstore Bundle Specification](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
- [TUF Trusted Root Format](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto)
