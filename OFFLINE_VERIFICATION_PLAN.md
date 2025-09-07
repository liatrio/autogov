# Offline Verification Development Plan

## Overview

Offline verification allows verification of GitHub attestations without network access by using pre-downloaded Sigstore bundles and trusted roots. This is crucial for air-gapped environments and archival verification.

## Current Status

✅ Download command with GitHub API integration
✅ Offline CLI (`offline`) supports attestation-only or blob+attestation
✅ Working end-to-end with real GitHub bundles

🔄 Refactor in progress: migrate offline verification to upstream sigstore-go APIs

- Use `github.com/sigstore/sigstore-go/pkg/bundle` for parsing/validation
- Use `github.com/sigstore/sigstore-go/pkg/verify` for signature, timestamp, identity, and (optional) tlog verification
- Use `github.com/sigstore/sigstore-go/pkg/root` for trusted root loading

❌ To be removed during refactor:

- Custom bundle model and manual DSSE/signature verification
- Custom trusted root types and ad hoc CA/tlog/timestamp checks
- PEM certificate handling (switch to DER-only via `rawBytes` in bundles)

## Implementation Status

### ✅ Successfully Implemented Features

#### Download Command

- **Command**: `download` with flags for blob path, output, and repository
- **Working Example**:

```bash
# Download attestations from GitHub API
./autogov-verify download \
  --blob-path bundle.tar.gz \
  --output attestations.jsonl \
  --repo liatrio/liatrio-gh-autogov-workflows
```

#### Offline Attestation Verification

- **Command**: `offline` (renamed from `verify-offline`) with flags for attestations, cert identity, and trusted root
- **Working Examples**:

```bash
# Without blob (attestation-only verification)
./autogov-verify offline \
  --attestations attestations.jsonl \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@82f5947f7892f9a10ca272ac0136ac777f49e3d1" \
  --trusted-root github-trusted-root.json

# With blob (includes digest matching)
./autogov-verify offline \
  --attestations attestations.jsonl \
  --blob-path bundle.tar.gz \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@82f5947f7892f9a10ca272ac0136ac777f49e3d1" \
  --trusted-root github-trusted-root.json
```

- **Status**: ✅ Working with real GitHub data
- **Blob optional**: Attestations can be verified independently (digest check applied only when blob/digest provided)

#### Key Technical Direction (refactor)

1. **Adopt sigstore-go types**: Parse bundles with `sigstore-go/pkg/bundle.Bundle` (JSON/JSONL)
2. **Trusted roots via sigstore-go**: Load with `sigstore-go/pkg/root` (file path or dynamic fetch outside offline mode)
3. **Verification via sigstore-go**: `verify.NewVerifier(trustedRoot, verify.WithObserverTimestamps(1))`
4. **Artifact policies**: `verify.WithArtifact()` or `verify.WithArtifactDigest()`; `verify.WithoutArtifactUnsafe()` when blob is omitted
5. **Identity policy**: `verify.WithCertificateIdentity(verify.NewShortCertificateIdentity(issuer, "", san, ""))`
6. **Drop PEM handling**: Rely on DER `rawBytes` in GitHub bundles

### ❌ Not Yet Implemented

1. Full removal of custom offline verification/trust code (Phase 2)
2. Test updates to remove PEM-based fixtures and align with DER-only bundles

### 📋 Current Working Offline Verification Process

1. **Prerequisites**:
   - Pre-downloaded attestation JSONL file (from GitHub CLI or API)
   - Blob artifact file to verify
   - GitHub trusted root JSON file
   - Certificate identity with full commit SHA

2. **Certificate Identity Format**: Must include commit SHA, not just branch:
   - ❌ `https://github.com/org/repo/.github/workflows/build.yaml@refs/heads/main`
   - ✅ `https://github.com/org/repo/.github/workflows/build.yaml@82f5947f7892f9a10ca272ac0136ac777f49e3d1`

3. **Expected Behavior**:
   - Certificate verification performed with observer timestamps (RFC3161 and/or log integrated timestamps present in bundle)
   - Transparency log and SCTs are optional in offline mode unless explicitly required via verifier options

## Next Steps for Future Development

### Final Implementation Details

#### Key Design Decisions

1. **Blob-Optional Verification**: Attestations can be verified without the artifact file since bundles contain subject digests
2. **Identity Policy**: Enforce SAN + Issuer via sigstore-go policy api
3. **Offline Defaults**: Do not require Rekor or SCTs by default; can be enabled explicitly later
4. **DER-only Certificates**: Use `rawBytes` (DER) from bundles; no PEM support required

#### Technical Implementation

- **No Network Calls**: The offline package imports no HTTP libraries and makes no network requests
- **Local Crypto Verification**: Uses standard Go crypto libraries for all verification
- **Trusted Root Flexibility**: Can use embedded GitHub trusted root or user-provided file
- **Clean User Experience**: No verbose warnings or confusing flags

#### Alignment with Industry Standards

- **Cosign Compatibility**: Follows cosign's `Offline: true` approach
- **Sigstore-go Alignment**: Similar to using `WithObserverTimestamps()` for offline scenarios
- **GitHub Bundle Format**: Full support for GitHub's attestation bundle format

### Current Status Summary

✅ **Offline verification is fully functional** - Successfully verifies real GitHub attestations with:

- **Blob-optional verification**: Attestations can be verified without requiring the artifact file
- **Proper certificate identity matching**: Requires full commit SHA for accurate identity verification
- **Dual-format certificate parsing**: Supports both PEM and DER certificate formats
- **Lenient validation for offline mode**: Allows expired certificates and CA validation failures with warnings
- **Complete subcommand support**: `verify-offline` and `download` commands properly integrated

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
│   ├── verifier.go       # Thin wrapper over sigstore-go verifier
│   ├── bundle.go         # JSON/JSONL loaders (emit sigstore-go bundles)
│   └── trust.go          # (to be removed) use sigstore-go root directly
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

### Phase 1: Bridge to sigstore-go ✅ COMPLETED

- [x] Keep existing CLI and file formats
- [x] Use sigstore-go verifier under the hood for offline verification
- [x] Pass issuer + SAN to identity policy
- [x] Keep current tests passing (map results accordingly)

### Phase 2: Remove custom code ✅ COMPLETED

- [x] Delete custom offline `Bundle` model and manual crypto/tlog/timestamp code
- [x] Delete custom trusted root types and validations
- [x] Tests continue to work with sigstore-go implementation

### Phase 3: Enhancements ✅ COMPLETED

- [x] Fixed large attestation handling (increased scanner buffer)
- [x] Added artifact digest support for container images
- [x] Result mapping shows predicate types

### Phase 4: Documentation & DX (IN PROGRESS)

- [ ] Update README to reflect sigstore-go usage
- [x] Identity requirements clear (SAN + Issuer)
- [x] Fixed common bundle issues (token too long)

### Phase 5: Testing ✅ COMPLETED

- [x] Unit tests build and pass
- [x] Integration tests with real GitHub bundles (JSON/JSONL)

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

- `github.com/sigstore/sigstore-go` - bundles, verifier, roots
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
