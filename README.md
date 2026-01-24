# AutoGov-Verify

A tool for verifying GitHub Artifact Attestations using [cosign](https://docs.sigstore.dev/cosign/overview/) with SLSA v1.1 VSA (Verification Summary Attestation) support and integrated OPA policy evaluation.

> **Note**: This tool supports attestations for container images in the GitHub Container Registry (ghcr.io) and blob attestations with comprehensive attestation verification, VSA generation, and policy evaluation capabilities.

## Requirements

- Go 1.21 or higher
- GitHub personal access token with read access to packages
- Access to the GitHub Container Registry (ghcr.io)
- Docker login to ghcr.io (`docker login ghcr.io`) for container image verification

## Features

- **Multi-Attestation Verification**: Supports all standard in-toto predicate types (SLSA, SBOM, vulnerability, custom)
- **SLSA v1.1 VSA Generation**: Creates comprehensive Verification Summary Attestations
- **OPA Policy Integration**: Evaluates Rego policies with results included in VSA metadata
- **Certificate Identity Validation**: Validates against approved certificate identity lists
- **Offline Verification**: Supports pre-downloaded attestation artifacts (verify container images by digest without pulling the image)
- **Dynamic Trusted Root**: Automatically fetches latest GitHub trusted roots
- **VSA Validation**: Comprehensive field validation, structured error handling, and multi-format digest support
- **Production Ready**: Comprehensive error handling, caching, and monitoring support

This tool verifies GitHub Artifact Attestations using the sigstore-go v1.0.0 API and supports attestations in the Sigstore bundle format used by [GitHub Artifact Attestations, npm Provenance, Homebrew Provenance, etc](https://blog.sigstore.dev/cosign-verify-bundles/).

## Verification Process

The tool performs several steps for each attestation:

1. **Trusted Root Fetching**: Dynamically fetches GitHub's trusted root using `gh attestation trusted-root`, with fallback to embedded trusted root
2. **Parses the OCI reference** to extract organization, repository, and digest
3. **Retrieves attestations** from GitHub's container registry
4. **Verifies the certificate chain** for each attestation using sigstore-go
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

# Binary will be installed as 'autogov'
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
task test

# Build binary
task build

# Run linter
task lint
```

### Available Task Commands

The project uses [Task](https://taskfile.dev) for build automation.

```bash
task --list       # Show all available tasks
task              # Run verify and build (default)
task build        # Build the binary
task test         # Run tests with coverage
task lint         # Run linter
task format       # Format code
task verify       # Run format, lint, and test
task install      # Install binary to /usr/local/bin
task clean        # Clean build artifacts
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

### Predicate Type Standardization

The tool implements predicate type standardization following the [in-toto attestation framework](https://github.com/in-toto/attestation) and [SLSA specifications](https://slsa.dev/spec/v1.0/). This ensures consistent, human-readable display of attestation types during verification.

**Supported Predicate Types:**

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
| `https://in-toto.io/attestation/scai/v0.3` | SCAI Report | Software supply chain attribute integrity assertions |
| `https://in-toto.io/attestation/runtime-trace/v0.1` | Runtime Trace | Runtime traces of supply chain operations |
| `https://in-toto.io/attestation/release/v0.1` | Release | Release version and artifact hash linkage |
| `https://in-toto.io/attestation/test-result/v0.1` | Test Result | Test execution results |
| `https://in-toto.io/attestation/link/v0.3` | in-toto Link | Legacy in-toto 0.9 format (migration support) |
| `https://cosign.sigstore.dev/attestation/v1` | Cosign Custom | Cosign generic custom attestation |

**How It Works:**

During verification, the tool:

1. Extracts the predicate type URI from each attestation
2. Looks up the URI in the predicate type registry
3. Displays the short name if found, or "Unknown: <uri>" if not found
4. Continues verification regardless of registry status

**Graceful Handling of Unknown Types:**

If the tool encounters a predicate type not in the registry (e.g., custom or newly-introduced types):

- Verification proceeds normally without errors
- The type is displayed as `Unknown: <full-uri>`
- A warning is logged suggesting the registry be updated (if not in quiet mode)
- Signature and certificate validation remain unchanged

**Example Output:**

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

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to contribute to this project.

## Usage

### Online Verification

```bash
autogov verify --cert-identity <identity> [options]
```

#### Required Flags

- `--cert-identity, -i`: Certificate identity to verify against (GitHub Actions workflow URL)
  - For blob verification, the organization and repository are extracted from this URL
  - Format: `https://github.com/OWNER/REPO/.github/workflows/...`
- `--repo`: Repository to fetch attestations from (format: owner/repo) (required for both image and blob verification)

And one of the following:

- `--image-digest, -d`: Container image digest. Provide either:
  - A bare digest `sha256:<64-hex>` together with `--repo owner/repo` (recommended)
  - Or a full OCI reference `[registry/]owner/repo[:tag]@sha256:<64-hex>` (still requires `--repo owner/repo` for API scoping)
- `--blob-path`: Path to a blob file to verify attestations against (e.g., `--blob-path /path/to/file.txt`)
- Positional digest: you may pass the digest as a positional argument when neither `--image-digest` nor `--blob-path` is provided.

### Offline Verification

The tool supports offline verification for air-gapped environments or archived attestations:

#### Download Attestations

First, download attestations while online (requires GitHub token):

```bash
# Download attestations for a blob artifact
autogov download \
  --blob-path artifact.tar.gz \
  --repo owner/repo \
  --output attestations.jsonl

# Download attestations for a container image by digest
autogov download \
  --image-digest sha256:abc123... \
  --repo owner/repo \
  --output attestations.jsonl

# Download attestations using digest directly as argument (works for both blobs and images)
autogov download \
  --repo owner/repo \
  --output attestations.jsonl \
  sha256:abc123...
```

**Download Command Flags:**

- `--blob-path`: Path to a local blob file to download attestations for
- `--image-digest`: Container image digest (e.g., `sha256:...`)
- `--repo, -R`: Repository to download attestations from (format: `owner/repo`) (required)
- `--output, -o`: Output file path for attestation bundles (required)
- `--format`: Output format: `json` or `jsonl` (default: `jsonl`)

#### Verify Offline

Then verify offline using the downloaded attestations:

```bash
# Verify with blob file
autogov offline \
  --attestations attestations.jsonl \
  --blob-path artifact.tar.gz \
  --cert-identity "https://github.com/owner/repo/.github/workflows/build.yml@sha" \
  --cert-issuer "https://token.actions.githubusercontent.com"

# Verify container image by digest
autogov offline \
  --attestations attestations.jsonl \
  --image-digest "sha256:46a0df552ddbd5bfb4cc738a0f316e4060cc5b06e5fc0a8dac3a8c7e33b6992f" \
  --cert-identity "https://github.com/owner/repo/.github/workflows/build.yml@sha" \
  --cert-issuer "https://token.actions.githubusercontent.com"

# Attestation-only verification (no artifact)
autogov offline \
  --attestations attestations.jsonl \
  --cert-identity "https://github.com/owner/repo/.github/workflows/build.yml@sha" \
  --cert-issuer "https://token.actions.githubusercontent.com"

#### Offline Verification Flags

- `--attestations`: Path to pre-downloaded attestation bundles file (required)
- `--blob-path`: Path to artifact file or directory containing multiple artifacts to verify (optional, calculates SHA256 digest for single files)
- `--image-digest`: SHA256 digest for container image verification (optional, use when image cannot be pulled offline)
- `--cert-identity`: Certificate identity (workflow URL with commit SHA) (required)
- `--cert-issuer`: Certificate issuer (defaults to GitHub Actions)
- `--trusted-root`: Path to custom trusted root JSON file (takes precedence over `--trusted-root-source`)
- `--trusted-root-source`: Trusted root source selection: `github`, `public`, or `auto` (default: `auto`)
- `-q, --quiet`: Only show errors and final results

**Trusted Root Source Options:**

| Source | Description |
|--------|-------------|
| `github` | Use GitHub's private Sigstore deployment (fulcio.githubapp.com) |
| `public` | Use public Sigstore infrastructure (fulcio.sigstore.dev) |
| `auto` | Auto-detect based on certificate issuer (default) |

The `auto` mode examines the attestation certificate issuer to determine the appropriate trusted root:
- GitHub Actions (`https://token.actions.githubusercontent.com`) → GitHub trusted root
- Google OIDC (`https://accounts.google.com`) → Public Sigstore trusted root
- GitHub OAuth (`https://github.com/login/oauth`) → Public Sigstore trusted root
- GitLab (`https://gitlab.com`) → Public Sigstore trusted root

**Implementation Notes**:
- Uses sigstore-go for all verification
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
- `--policy-schemas-path`: Path to directory or .tar.gz file containing JSON schemas for OPA policy validation
- `--policy-data-path`: Path to JSON file containing additional OPA data (e.g., vulnerability thresholds)
- `--policy-uri`: Policy URI for VSA generation (required if --generate-vsa is used)
- `--fail-on-policy-error`: Exit with error code 1 when policy evaluation fails (default: false - exit code 0)
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
- `FAIL_ON_POLICY_ERROR`: Alternative to --fail-on-policy-error flag (set to "true" to exit with error on policy failures)
- `POLICY_DATA_PATH`: Alternative to --policy-data-path flag
- `TRUSTED_ROOT_SOURCE`: Alternative to --trusted-root-source flag (values: `github`, `public`, `auto`)

## Examples

Verify a container image:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo liatrio/demo-gh-autogov-workflows \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --source-ref refs/heads/main
```

Verify a blob file:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-blob.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo
  --blob-path path/to/your/file \
  --source-ref refs/heads/main
```

Using environment variables:

```bash
export GITHUB_AUTH_TOKEN=your_token
export CERT_IDENTITY="https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
export CERT_ISSUER=https://token.actions.githubusercontent.com
autogov verify --repo liatrio/demo-gh-autogov-workflows -d "sha256:702bea33d240c2f0a1d87fe649a49b52f533bde2005b3c1bc0be7859dd5e4226"
```

Verify with certificate identity validation:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo liatrio/demo-gh-autogov-workflows \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --cert-identity-list "https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/refs/heads/main/cert-identities.json"
```

Generate enhanced VSA with policy evaluation:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo liatrio/demo-gh-autogov-workflows \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --generate-vsa \
  --vsa-output ./verification-summary.json \
  --policy-uri "https://github.com/liatrio/liatrio-rego-policy-library" \
  --policy-bundle-path "ghcr.io/liatrio/liatrio-rego-policy-library:latest"
```

Verify a cosign-signed artifact using public Sigstore:

```bash
# Verify an artifact signed with cosign sign --yes (public Sigstore)
autogov offline \
  --attestations attestations.jsonl \
  --blob-path artifact.tar.gz \
  --cert-identity "https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main" \
  --cert-issuer "https://accounts.google.com" \
  --trusted-root-source public

# Or use auto-detection (recommended)
autogov offline \
  --attestations attestations.jsonl \
  --blob-path artifact.tar.gz \
  --trusted-root-source auto
```

Generate VSA with custom vulnerability thresholds:

```bash
# Create threshold configuration file
cat > thresholds.json << 'EOF'
{
  "vulnerability_thresholds": {
    "critical": 0,
    "high": 5,
    "medium": 20,
    "low": -1
  }
}
EOF

export GITHUB_AUTH_TOKEN=your_token
autogov verify \
  --cert-identity "https://github.com/liatrio/liatrio-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo liatrio/demo-gh-autogov-workflows \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --generate-vsa \
  --vsa-output ./verification-summary.json \
  --policy-uri "https://github.com/liatrio/liatrio-rego-policy-library" \
  --policy-bundle-path bundle.tar.gz \
  --policy-data-path thresholds.json \
  --fail-on-policy-error
```

**Threshold Values:**
- `0`: No vulnerabilities allowed (zero tolerance)
- Positive number: Maximum allowed count
- `-1`: Unlimited (disable check for that severity)

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
      "attestation.slsa_provenance": true,
      "attestation.sbom": true,
      "attestation.vulnerability": true,
      "attestation.metadata": true
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

The tool provides detailed output about the verification process, including human-readable predicate type names:

```shell
Starting verification process...
---
Certificate identity validation enabled
Using identity source: https://raw.githubusercontent.com/liatrio/liatrio-gh-autogov-workflows/main/cert-identities.json
---
✓ Certificate identity validated against source of truth
Verifying attestation 1 (Vulnerability Scan: https://in-toto.io/attestation/vulns/v0.2)...
✓ Attestation 1 verified successfully
---
Verifying attestation 2 (CycloneDX SBOM: https://cyclonedx.org/bom)...
✓ Attestation 2 verified successfully
---
Verifying attestation 3 (SLSA Provenance: https://slsa.dev/provenance/v1)...
✓ Attestation 3 verified successfully
---
Verifying attestation 4 (AutoGov Metadata: https://autogov.dev/attestation/metadata/v1)...
✓ Attestation 4 verified successfully
---

Summary:
✓ Successfully verified 4 attestations

Attestation Types:
1. Vulnerability Scan (https://in-toto.io/attestation/vulns/v0.2)
2. CycloneDX SBOM (https://cyclonedx.org/bom)
3. SLSA Provenance (https://slsa.dev/provenance/v1)
4. AutoGov Metadata (https://autogov.dev/attestation/metadata/v1)
```

Note: Predicate types not in the registry are displayed as "Unknown" with a warning, but verification continues normally.

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
