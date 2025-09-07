# AutoGov-Verify

A tool for verifying GitHub Artifact Attestations using [cosign](https://docs.sigstore.dev/cosign/overview/) with SLSA v1.1 VSA (Verification Summary Attestation) support and integrated OPA policy evaluation.

> **Note**: This tool supports attestations for container images in the GitHub Container Registry (ghcr.io) and blob attestations with comprehensive attestation verification, VSA generation, and policy evaluation capabilities.

## Requirements

- Go 1.21 or higher
- GitHub personal access token with read access to packages
- Access to the GitHub Container Registry (ghcr.io)
- Docker login to ghcr.io (`docker login ghcr.io`) for container image verification

## Features

- **Multi-Attestation Verification**: Supports SLSA provenance, SBOM, vulnerability scans, and cosign attestations
- **SLSA v1.1 VSA Generation**: Creates comprehensive Verification Summary Attestations
- **OPA Policy Integration**: Evaluates Rego policies with results included in VSA metadata
- **Certificate Identity Validation**: Validates against approved certificate identity lists
- **Offline Verification**: Complete offline verification using sigstore-go APIs with separate download command
- **Container Image Support**: Verify container images by digest without pulling the image
- **Dynamic Trusted Root**: Automatically fetches latest GitHub trusted roots
- **VSA Validation**: Comprehensive field validation, structured error handling, and multi-format digest support
- **Production Ready**: Comprehensive error handling, caching, and monitoring support

This tool verifies GitHub Artifact Attestations using the sigstore-go v1.0.0 API and supports attestations in the Sigstore bundle format used by [GitHub Artifact Attestations, npm Provenance, Homebrew Provenance, etc](https://blog.sigstore.dev/cosign-verify-bundles/).

## Verification Process

The tool performs several steps for each attestation:

1. **Trusted Root Fetching**: Dynamically fetches GitHub's trusted root using `gh attestation trusted-root`, with fallback to embedded trusted root
2. **Parses the OCI reference** to extract organization, repository, and digest
3. **Retrieves attestations** from GitHub's container registry
4. **Verifies the certificate chain** for each attestation using sigstore-go v1.0.0 API
5. **Validates the attestation signature** with proper timestamp verification
6. **Checks the certificate identity and issuer** against expected values
7. **Verifies the attestation payload** structure and content
8. **(Optional) Validates certificate identity** against an approved source of truth list

Each attestation is verified against:

- **GitHub's trusted root certificates** (including both certificate authorities and timestamp authorities)
- **The specified certificate identity** (GitHub Actions workflow)
- **The certificate issuer** (GitHub Actions OIDC provider)
- **(Optional) An approved list** of certificate identities from a source of truth

## Authentication

The tool supports two methods of GitHub authentication:

1. **Auto-detection** (Recommended):
   - Uses `go-gh` to automatically detect credentials from:
     - Environment variables (`GH_TOKEN`, `GITHUB_TOKEN`, `GITHUB_AUTH_TOKEN`)
     - GitHub CLI configuration
     - System keyring

2. **Manual Configuration**:
   - Set environment variables directly:

     ```bash
     export GH_TOKEN=your_token_here
     # or
     export GITHUB_TOKEN=your_token_here
     # or
     export GITHUB_AUTH_TOKEN=your_token_here
     ```

If testing locally, use a PAT (e.g., a [Classic Personal Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)) with the following permissions:

- `read:packages` permission to access GitHub Container Registry (required for container image verification)
- `repo` permission if verifying private repository artifacts
- Access to the organization/repository you're trying to verify

> **Note**: For container image verification, you must be logged into ghcr.io:
>
>```bash
> echo $GH_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
> ```
>
> The same token can be used for both GitHub API access and Docker login.

## Installation

```bash
go install github.com/liatrio/autogov-verify@latest
```

## Development

### Prerequisites

- Go 1.21 or higher
- GitHub CLI (`gh`) for trusted root fetching
- Docker for container registry access
- golangci-lint for code quality checks
- GitHub Personal Access Token with appropriate permissions

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

### Available Make Targets

```bash
make help         # Show all available make targets
make all         # Run verify and build (default)
make build       # Build the binary
make test        # Run tests with coverage
make lint        # Run linter
make format      # Format code
make verify      # Run format, lint, and test
make install     # Install binary to /usr/local/bin
```

### Testing

```bash
# Unit tests
go test ./...

# Integration tests with real attestations
export GITHUB_AUTH_TOKEN=your_token
go test -tags=integration ./...

# Test with coverage
go test -cover ./...

# Benchmark tests
go test -bench=. ./...
```

### Architecture Overview

The tool is organized into several key packages:

- **`pkg/attestations/`**: GitHub API integration, sigstore verification, certificate validation
- **`pkg/vsa/`**: SLSA v1.1 VSA generation with comprehensive validation
- **`pkg/policy/`**: OPA integration for policy evaluation
- **`pkg/storage/`**: ORAS-Go integration for VSA storage in OCI registries
- **`pkg/certid/`**: Certificate identity validation against approved lists
- **`pkg/github/`**: GitHub client and token management

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to contribute to this project.

## Usage

### Online Verification

```bash
autogov-verify -cert-identity <identity> [options]
```

#### Required Flags

- `--cert-identity, -i`: Certificate identity to verify against (GitHub Actions workflow URL)
  - For blob verification, the organization and repository are extracted from this URL
  - Format: `https://github.com/OWNER/REPO/.github/workflows/...`

And one of the following:

- `--artifact-digest, -d`: Full OCI reference for container verification in the format `[registry/]org/repo[:tag]@sha256:hash` (e.g., `ghcr.io/owner/repo@sha256:hash` or `owner/repo@sha256:hash`)
  - The registry is optional and defaults to ghcr.io
  - The tag is optional and doesn't affect verification
- `--blob-path`: Path to a blob file to verify attestations against (e.g., `--blob-path /path/to/file.txt`)

### Offline Verification

The tool supports offline verification for air-gapped environments or archived attestations:

#### Download Attestations

First, download attestations while online (requires GitHub token):

```bash
# Download attestations for a blob artifact
autogov-verify download \
  --blob-path artifact.tar.gz \
  --repo owner/repo \
  --output attestations.jsonl

# Download attestations by digest (for container images)
autogov-verify download \
  --repo owner/repo \
  --output attestations.jsonl \
  sha256:abc123...
```

#### Verify Offline

Then verify offline using the downloaded attestations:

```bash
# Verify with blob file
autogov-verify offline \
  --attestations attestations.jsonl \
  --blob-path artifact.tar.gz \
  --cert-identity "https://github.com/owner/repo/.github/workflows/build.yml@sha" \
  --cert-issuer "https://token.actions.githubusercontent.com"

# Verify container image by digest
autogov-verify offline \
  --attestations attestations.jsonl \
  --artifact-digest "sha256:46a0df552ddbd5bfb4cc738a0f316e4060cc5b06e5fc0a8dac3a8c7e33b6992f" \
  --cert-identity "https://github.com/owner/repo/.github/workflows/build.yml@sha" \
  --cert-issuer "https://token.actions.githubusercontent.com"

# Attestation-only verification (no artifact)
autogov-verify offline \
  --attestations attestations.jsonl \
  --cert-identity "https://github.com/owner/repo/.github/workflows/build.yml@sha" \
  --cert-issuer "https://token.actions.githubusercontent.com"

#### Offline Verification Flags

- `--attestations`: Path to pre-downloaded attestation bundles file (required)
- `--blob-path`: Path to artifact file to verify (optional, calculates SHA256 digest)
- `--artifact-digest`: SHA256 digest of artifact for verification (optional, alternative to blob-path)
- `--cert-identity`: Certificate identity (workflow URL with commit SHA) (required)
- `--cert-issuer`: Certificate issuer (defaults to GitHub Actions)
- `--trusted-root`: Path to trusted root JSON file (defaults to embedded GitHub trusted root) if not provided)
- `-q, --quiet`: Only show errors and final results

**Implementation Notes**:
- Uses pure sigstore-go v1.0.0 APIs for all verification
- Handles large attestations (up to 10MB per line in JSONL files)
- Transparency log verification is automatically skipped in offline mode
- Supports both JSON and JSONL attestation formats

### Optional Flags

- `--cert-issuer, -s`: Certificate issuer to verify against (default: <https://token.actions.githubusercontent.com>)
- `--source-ref, -r`: Source repository ref to verify against (e.g., refs/heads/main)
- `--quiet, -q`: Only show errors and final results

#### Certificate Identity Validation Flags

The tool supports validating certificate identities against a source of truth list:

- `--cert-identity-list`: URL to the certificate identity list for validation. If provided, validates the cert-identity against this source (optional). Example: `https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/refs/heads/main/cert-identities.json`
- `--no-cache`: Disable caching of the certificate identity list

#### VSA and Policy Flags

The tool supports generating SLSA v1.1 Verification Summary Attestations (VSAs) with enhanced validation and evaluating OPA policies:

- `--generate-vsa`: Generate a VSA after successful verification with comprehensive validation
- `--vsa-output`: Path to save the generated VSA (e.g., `./verification-summary.json`)
- `--policy-bundle-path`: Path or URL to OPA policy bundle for evaluation
- `--policy-uri`: Policy URI for VSA generation (required if --generate-vsa is used)
- `--attestations-path`: Path to directory containing attestation files for offline verification

**Enhanced VSA Features:**

- **Comprehensive Validation**: Detailed field validation with structured error types
- **SLSA Level Parsing**: Robust parsing of SLSA levels with track extraction (e.g., `SLSA_BUILD_LEVEL_3`)
- **Multi-Format Digest Support**: Validation for multiple hash algorithms beyond SHA256
- **Policy Integration**: OPA policy evaluation results included in VSA metadata

The certificate identity source of truth is a JSON file with the following structure:

```json
{
  "identities": [
    {
      "version": "0.4.0",
      "sha": "d709edc9cc501e27f390b7818c9262075ee9e0da",
      "status": "latest",
      "identities": [
        "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
      ],
      "added": "2025-03-14"
    },
    {
      "version": "0.3.0",
      "sha": "a8d9bc3a1e5601d657f87f089a234717899712b1",
      "status": "approved",
      "identities": [
        "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-lp-attest-blob.yaml@a8d9bc3a1e5601d657f87f089a234717899712b1"
      ],
      "added": "2025-02-22",
      "expires": "2026-02-22"
    },
    {
      "version": "0.1.0",
      "sha": "3f1e90cc8b4fd742c2cd3e4d81d6079c63fbaf67",
      "status": "revoked",
      "identities": [
        "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-blob.yaml@3f1e90cc8b4fd742c2cd3e4d81d6079c63fbaf67"
      ],
      "added": "2024-11-29",
      "revoked": "2025-01-30",
      "reason": "Multiple security fixes and bug fixes in later versions"
    }
  ],
  "metadata": {
    "last_updated": "2025-03-14",
    "version": "v0.4.0",
    "maintainer": "@liatrio/tag-autogov"
  }
}
```

### Environment Variables

The following environment variables can be used for authentication:

- `GH_TOKEN`, `GITHUB_TOKEN`, or `GITHUB_AUTH_TOKEN`: GitHub personal access token with read access to packages

All command line flags can be set via environment variables:

- `CERT_IDENTITY`: Alternative to --cert-identity flag
- `CERT_ISSUER`: Alternative to --cert-issuer flag
- `SOURCE_REF`: Alternative to --source-ref flag
- `QUIET`: Alternative to --quiet flag
- `CERT_IDENTITY_LIST`: Alternative to --cert-identity-list flag
- `NO_CACHE`: Alternative to --no-cache flag

## Examples

Verify a container image:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --artifact-digest "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --source-ref refs/heads/main
```

Verify a blob file:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-blob.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --blob-path path/to/your/file \
  --source-ref refs/heads/main
```

Using environment variables:

```bash
export GITHUB_AUTH_TOKEN=your_token
export CERT_IDENTITY="https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
export CERT_ISSUER=https://token.actions.githubusercontent.com
autogov-verify -d "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:702bea33d240c2f0a1d87fe649a49b52f533bde2005b3c1bc0be7859dd5e4226"
```

Verify with certificate identity validation:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --artifact-digest "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --cert-identity-list "https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/refs/heads/main/cert-identities.json"
```

Generate enhanced VSA with policy evaluation:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov-verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --artifact-digest "ghcr.io/liatrio/demo-gh-autogov-workflows@sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --generate-vsa \
  --vsa-output ./verification-summary.json \
  --policy-uri "https://github.com/liatrio/liatrio-rego-policy-library" \
  --policy-bundle-path "ghcr.io/liatrio/liatrio-rego-policy-library:latest"
```

**VSA Output Features:**

- **Comprehensive Validation**: All VSA fields validated with detailed error reporting
- **SLSA Level Details**: Verified levels include `SLSA_BUILD_LEVEL_3` (per SLSA v1.1 specification) plus custom autogov levels
- **Policy Results**: Complete OPA policy evaluation results and violations
- **Attestation Summary**: Details of all verified attestation types (vulnerability, SBOM, provenance, cosign)

**SLSA v1.1 Compliance**: The tool validates against official SLSA Build track levels (L0-L3) as defined in the [SLSA v1.1 specification](https://slsa.dev/spec/v1.1/levels)

### VSA Metadata Structure

The generated VSA includes comprehensive metadata about the verification and policy evaluation:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [...],
  "predicateType": "https://slsa.dev/verification_summary/v1.1",
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
      "policy_bundle": "ghcr.io/liatrio/liatrio-rego-policy-library:latest",
      "opa_version": "v1.8.0",
      "governance_rules": ["governance.allow", "governance.violations"],
      "details": {
        "total_policies": 15,
        "policies_evaluated": 15,
        "policies_passed": 15
      }
    },
    "autogov.policy.violation_summary": {
      // Grouped violations by policy type (if any)
    },
    "autogov.policy.metrics": {
      "total_violations": 0,
      "compliance_status": "PASSED",
      "input_attestations": 4,
      "evaluation_duration": 125
    },
    "autogov.verification.details": {
      "provenance": true,
      "sbom": true,
      "vulnerability": true,
      "cosign": true
    }
  }
}
```

**Metadata Fields:**

- **`autogov.policy.evaluation`**: Core policy evaluation results including pass/fail status, violations, and policy details
- **`autogov.policy.violation_summary`**: Violations grouped by policy type for quick identification of issues
- **`autogov.policy.metrics`**: Compliance metrics and statistics for reporting
- **`autogov.verification.details`**: Attestation verification results by type

## Output

The tool provides detailed output about the verification process:

```shell
Starting verification process...
---
Certificate identity validation enabled
Using identity source: https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json
---
✓ Certificate identity validated against source of truth
Verifying attestation 1 (https://in-toto.io/attestation/vulns/v0.1)...
✓ Attestation 1 verified successfully
---
[... additional attestations ...]

Summary:
✓ Successfully verified 4 attestations

Attestation Types:
1. https://in-toto.io/attestation/vulns/v0.1
2. https://cyclonedx.org/bom
3. https://slsa.dev/provenance/v1
4. https://cosign.sigstore.dev/attestation/v1
```

## Trusted Root Management

The tool uses GitHub's trusted root certificates for verification, which include both certificate authorities and timestamp authorities required for proper sigstore verification.

### Dynamic Trusted Root Fetching

By default, the tool attempts to fetch the latest trusted root dynamically:

1. **Primary Method**: Uses `gh attestation trusted-root` command to fetch the current trusted root
2. **Fallback Method**: Uses embedded trusted root if dynamic fetching fails
3. **Filtering**: Automatically filters for `fulcio.githubapp.com` certificate authority while preserving timestamp authorities

### Benefits of Dynamic Fetching

- **Always Up-to-Date**: Gets the latest trusted root certificates from GitHub
- **Automatic Updates**: No need to update the tool when GitHub rotates certificates
- **Robust Fallback**: Falls back to embedded root if GitHub CLI is unavailable

### Requirements for Dynamic Fetching

- GitHub CLI (`gh`) must be installed and authenticated
- Network access to GitHub's API
- Valid GitHub authentication token

If dynamic fetching fails, you'll see a message indicating fallback to embedded trusted root:

```text
✓ Using dynamically fetched trusted root
```

or

```text
⚠ Failed to fetch dynamic trusted root, using embedded fallback
```

## Advanced Features

### VSA Generation with Policy Evaluation

The tool generates SLSA v1.1 compliant Verification Summary Attestations (VSAs) with integrated OPA policy evaluation:

```go
// Verification workflow
1. Collect attestations from GitHub
2. Verify signatures using sigstore-go
3. Evaluate OPA/Rego policies
4. Generate comprehensive VSA
5. Store VSA in OCI registry
```

### Blob Verification

To verify signed blobs (files) with attestations stored in GitHub:

```bash
# Verify a blob file
autogov-verify \
  --blob-path file.txt \
  --cert-identity "..."
```

Note: The tool requires GitHub API access to fetch attestations. Ensure your GitHub token is set.

## Troubleshooting

Common issues and solutions:

1. **Authentication Errors**
   - Ensure your GitHub token has the necessary permissions (see Authentication section above)
   - Check that the token is properly set in environment variables
   - Verify you have access to the GitHub organization
   - For container image verification, ensure you're logged into ghcr.io

2. **Certificate Verification Failures**
   - Verify the certificate identity matches your GitHub Actions workflow
   - Ensure the workflow URL is correct, including the branch/tag
   - Check that the certificate issuer matches GitHub's OIDC provider

3. **No Attestations Found**
   - Confirm the image digest is correct
   - Verify the image exists in the GitHub Container Registry
   - Check that attestations were generated during the build process
   - Ensure you have permission to access the container image

4. **Invalid Digest Format**
   - Ensure the digest follows the format: `sha256:hash`
   - When using full OCI references, include the registry: `ghcr.io/owner/repo@sha256:hash`

If you encounter any other issues, please [open an issue](https://github.com/liatrio/autogov-verify/issues/new) and include as much detail as possible.

## License

Copyright 2025 The Liatrio Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
