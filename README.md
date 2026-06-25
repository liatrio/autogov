# AutoGov

[![CI](https://github.com/liatrio/autogov/actions/workflows/build.yml/badge.svg)](https://github.com/liatrio/autogov/actions/workflows/build.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/liatrio/autogov.svg)](https://pkg.go.dev/github.com/liatrio/autogov)
[![Go Report Card](https://goreportcard.com/badge/github.com/liatrio/autogov)](https://goreportcard.com/report/github.com/liatrio/autogov)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/liatrio/autogov/badge)](https://scorecard.dev/viewer/?uri=github.com/liatrio/autogov)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A unified CLI for attestation verification and release management. Supports [cosign](https://docs.sigstore.dev/cosign/overview/)-based verification with SLSA v1.2 VSA (Verification Summary Attestation) support, integrated OPA policy evaluation, and a full release engine with changelog generation.

> **Note**: This tool supports attestation verification for container images (ghcr.io) and blobs, VSA generation, policy evaluation, and release management (plan, cut, publish) with conventional commit-based changelog generation.

## Table of Contents

- [Requirements](#requirements)
- [Features](#features)
- [Verification Process](#verification-process)
- [Authentication](#authentication)
- [Installation](#installation)
- [Usage](#usage)
  - [Online Verification](#online-verification)
  - [Offline Verification](#offline-verification)
  - [Optional Flags](#optional-flags)
  - [Environment Variables](#environment-variables)
  - [Changelog Generation](#changelog-generation)
  - [Release Management](#release-management)
- [Examples](#examples)
- [Output](#output)
- [Trusted Root Management](#trusted-root-management)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
  - [Architecture Overview](#architecture-overview)
- [License](#license)

## Requirements

- Go 1.26 or higher
- GitHub personal access token with read access to packages
- Access to the GitHub Container Registry (ghcr.io)
- Docker login to ghcr.io (`docker login ghcr.io`) for container image verification

## Features

- **Multi-Attestation Verification**: Supports all standard in-toto predicate types (SLSA, SBOM, vulnerability, custom)
- **SLSA v1.2 VSA Generation**: Creates comprehensive Verification Summary Attestations
- **OPA Policy Integration**: Evaluates Rego policies with results included in VSA metadata
- **Signer Allowlist**: Enforces an approved set of signer certificate identities via `--cert-identity-list` (a URL or local file). Accepts the union of `--cert-identity` and the list (multiple signers per run), and fails closed when a configured list resolves to zero valid identities.
- **Offline Verification**: Supports pre-downloaded attestation artifacts (verify container images by digest without pulling the image)
- **Attestation Download**: Download attestations from GitHub for offline verification workflows
- **Per-Attestation Trusted Root**: Selects the trusted root for each attestation from its signing certificate's Fulcio issuer — public-good Sigstore (`sigstore.dev`) or GitHub (`fulcio.githubapp.com`) — with `--trusted-root`/`--trusted-root-source` overrides
- **VSA Validation**: Comprehensive field validation, structured error handling, and multi-format digest support
- **Release Management**: Plan, cut, and publish releases with GitHub API-signed commits (SLSA v1.2 provenance)
- **Changelog Generation**: Automatic changelog from conventional commits with markdown or JSON output
- **Configuration Mutations**: Update version strings across JSON, YAML, and TOML files during releases
- **Production Ready**: Comprehensive error handling, caching, and monitoring support

This tool verifies GitHub Artifact Attestations using the sigstore-go v1.2.1 API and supports attestations in the Sigstore bundle format used by [GitHub Artifact Attestations, npm Provenance, Homebrew Provenance, etc](https://blog.sigstore.dev/cosign-verify-bundles/).

## Verification Process

The tool performs several steps for each attestation:

1. **Trusted Root Selection**: Selects the trusted root per attestation from the signing certificate's Fulcio issuer — a public-good Sigstore (`sigstore.dev`) cert uses the public-good Sigstore root, a GitHub (`fulcio.githubapp.com`) cert uses the GitHub root. The GitHub root is fetched dynamically via `gh attestation trusted-root` with fallback to an embedded copy; the public-good root is embedded.
2. **Parses the OCI reference** to extract organization, repository, and digest
3. **Retrieves attestations** from GitHub's container registry
4. **Verifies the certificate chain** for each attestation using sigstore-go
5. **Validates the attestation signature** with proper timestamp verification
6. **Checks the certificate identity and issuer** against expected values
7. **Verifies the attestation payload** structure and content
8. **(Optional) Validates certificate identity** against an approved source of truth list

Each attestation is verified against:

- **The trusted root for its signing certificate** (GitHub or public-good Sigstore, including both certificate authorities and timestamp authorities)
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
go install github.com/liatrio/autogov@latest

# Binary will be installed as 'autogov'
```

### Container image

The CLI is also published as a signed multi-arch (`linux/amd64`, `linux/arm64`) OCI image to `ghcr.io/liatrio/autogov`:

```bash
docker pull ghcr.io/liatrio/autogov:latest
docker run --rm ghcr.io/liatrio/autogov:latest version
```

`:latest` tracks the most recent `main` build; for an immutable, reproducible reference pin by digest (`ghcr.io/liatrio/autogov@sha256:<digest>`) — the verification commands below work against a digest reference too.

The image carries a GitHub-issued build-provenance attestation. Verify it with cosign before use:

```bash
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/liatrio/autogov/' \
  ghcr.io/liatrio/autogov:latest
```

Or with the GitHub CLI:

```bash
gh attestation verify oci://ghcr.io/liatrio/autogov:latest --owner liatrio
```

## Usage

### Online Verification

`verify` is a parent command with four subcommands: `attestation` (GitHub artifact attestations), `git` (gitsign commit signatures), `source` (source provenance), and `policy` (repository policy enforcement). Artifact verification uses the `attestation` subcommand:

```bash
autogov verify attestation --repo <owner/repo> [options]
```

#### Required Flags

- `--repo`: Repository to fetch attestations from (format: owner/repo) (required for both image and blob verification)

And one of the following:

- `--image-digest, -d`: Container image digest. Provide either:
  - A bare digest `sha256:<64-hex>` together with `--repo owner/repo` (recommended)
  - Or a full OCI reference `[registry/]owner/repo[:tag]@sha256:<64-hex>` (still requires `--repo owner/repo` for API scoping)
- `--blob-path`: Path to a blob file to verify attestations against (e.g., `--blob-path /path/to/file.txt`)
- Positional digest: you may pass the digest as a positional argument when neither `--image-digest` nor `--blob-path` is provided.

#### Multi-Signer Verification

Pass `--cert-identity` and/or `--cert-identity-list` to enforce a **signer allowlist**. A bundle is accepted if its signer matches the single `--cert-identity` **or** any identity in `--cert-identity-list` — their union, with OR semantics (match at least one). This is useful when an artifact's attestations are produced by more than one workflow (for example an image and its VSA, signed by different reusable workflows), and it lets the allowlist span multiple authorized signer versions so verification survives reusable-workflow version bumps.

```bash
# accept a signature matching --cert-identity OR any identity in --cert-identity-list
autogov verify attestation \
  --repo liatrio/autogov \
  --blob-path artifact.tar.gz \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --cert-identity-list "https://raw.githubusercontent.com/liatrio/autogov-workflows/refs/heads/main/cert-identities.json"
```

See [Certificate Identity Validation Flags](#certificate-identity-validation-flags) for the list format and allowlist semantics (revoked/expired entries are dropped and verification fails closed on zero valid identities). If you set **neither** flag, any valid Fulcio signature is accepted and an `unsafe` warning is printed.

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
- `-q, --quiet`: Only show errors and final results

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

# Multi-signer allowlist (union of --cert-identity and --cert-identity-list)
autogov offline \
  --attestations attestations.jsonl \
  --blob-path artifact.tar.gz \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --cert-identity-list "https://raw.githubusercontent.com/liatrio/autogov-workflows/refs/heads/main/cert-identities.json" \
  --cert-issuer "https://token.actions.githubusercontent.com"
```

#### Offline Verification Flags

- `--attestations`: Path to pre-downloaded attestation bundles file (required)
- `--blob-path`: Path to artifact file or directory containing multiple artifacts to verify (optional, calculates SHA256 digest for single files)
- `--image-digest`: SHA256 digest for container image verification (optional, use when image cannot be pulled offline)
- `--cert-identity`: Certificate identity (workflow URL with commit SHA). Supplying `--cert-identity` and/or `--cert-identity-list` enforces a signer allowlist; if neither is provided, any valid Fulcio signature is accepted (unsafe)
- `--cert-identity-list`: Signer allowlist — URL or local file path to a certificate identity list; enforced as a signer allowlist, usable with or without `--cert-identity` (their union is accepted)
- `--no-cache`: Disable caching of the certificate identity list
- `--policy-bundle-digest`: Expected SHA-256 (`sha256:...`) of the downloaded policy bundle asset; enforced for `ghrel://` bundle paths (distinct from `--image-digest`)
- `--cert-issuer`: Certificate issuer (defaults to GitHub Actions)
- `--source-ref`: Source repository ref to verify against (e.g., `refs/heads/main`)
- `--trusted-root`: Path to custom trusted root JSON file (takes precedence over `--trusted-root-source`)
- `--trusted-root-source`: Trusted root source selection: `github`, `public`, or `auto` (default: `auto`)
- `--generate-vsa`: Generate Verification Summary Attestation after successful verification
- `--vsa-output`: Output path for generated VSA (required if `--generate-vsa` is used)
- `--policy-uri`: Policy URI for VSA generation (required if `--generate-vsa` is used)
- `--policy-bundle-path`: Policy bundle source — local directory, `.tar.gz`, `http(s)://` URL, `oci://registry/repo:tag`, or `ghrel://owner/repo[@tag][?asset=bundle.tar.gz]` (without `@tag`, `ghrel://` uses the latest release)
- `--policy-data-path`: Path to JSON file containing additional OPA data (e.g., vulnerability thresholds)
- `--policy-schemas-path`: JSON schemas source for OPA validation — local directory, `.tar.gz`, `http(s)://` URL, `oci://`, or `ghrel://owner/repo[@tag][?asset=schemas.tar.gz]` (default asset `schemas.tar.gz`)
- `--fail-on-policy-error`: Exit with error when policy evaluation fails (default: false)
- `-q, --quiet`: Only show errors and final results

**Trusted Root Source Options:**

| Source | Description |
|--------|-------------|
| `github` | Use GitHub's private Sigstore deployment (fulcio.githubapp.com) |
| `public` | Use public Sigstore infrastructure (fulcio.sigstore.dev) |
| `auto` | Auto-detect based on certificate issuer (default) |

The `auto` mode examines each attestation's signing certificate to determine the appropriate trusted root. The discriminator is the **Fulcio CA that issued the certificate**, not the OIDC issuer — the OIDC issuer (`https://token.actions.githubusercontent.com`) is identical for both GitHub Actions on public repos (signed against public-good Sigstore) and on private repos (signed against GitHub's Fulcio), so it cannot distinguish them:
- Certificate issued by public-good Sigstore Fulcio (`sigstore.dev`) → Public Sigstore trusted root (the case for public repositories, whose attestations carry a Rekor integrated timestamp)
- Certificate issued by GitHub Fulcio (`fulcio.githubapp.com`) → GitHub trusted root (the case for private repositories)

**Implementation Notes**:
- Uses sigstore-go for all verification
- Handles large attestations (up to 10MB per line in JSONL files)
- Transparency log verification is automatically skipped in offline mode
- Supports both JSON and JSONL attestation formats

### Optional Flags

- `--cert-identity, -i`: Certificate identity to verify against (GitHub Actions workflow URL). If not provided, any valid signature will be accepted.
  - For blob verification, the organization and repository are extracted from this URL
  - Format: `https://github.com/OWNER/REPO/.github/workflows/...`
- `--cert-issuer, -s`: Certificate issuer to verify against (default: <https://token.actions.githubusercontent.com>)
- `--source-ref, -r`: Source repository ref to verify against (e.g., refs/heads/main)
- `--quiet, -q`: Only show errors and final results

#### Certificate Identity Validation Flags

The tool supports enforcing a signer allowlist via a certificate identity list:

- `--cert-identity-list`: Signer allowlist — a URL or local file path to a certificate identity list. Accepted identities are enforced as the set of allowed signers, usable with or without `--cert-identity` (their union is accepted). Revoked/expired entries are dropped, and verification fails closed if an enforced list resolves to zero valid identities. Example: `https://raw.githubusercontent.com/liatrio/autogov-workflows/refs/heads/main/cert-identities.json`
- `--no-cache`: Disable caching of the certificate identity list

#### VSA and Policy Flags

The tool supports generating SLSA v1.2 Verification Summary Attestations (VSAs) with enhanced validation and evaluating OPA policies:

- `--generate-vsa`: Generate a VSA after successful verification with comprehensive validation
- `--vsa-output`: Path to save the generated VSA (e.g., `./verification-summary.json`)
- `--policy-bundle-path`: Policy bundle source — local directory, `.tar.gz`, `http(s)://` URL, `oci://registry/repo:tag`, or `ghrel://owner/repo[@tag][?asset=bundle.tar.gz]`
- `--policy-schemas-path`: JSON schemas source — local directory, `.tar.gz`, `http(s)://` URL, `oci://`, or `ghrel://owner/repo[@tag][?asset=schemas.tar.gz]`
- `--policy-data-path`: Path to JSON file containing additional OPA data (e.g., vulnerability thresholds)
- `--policy-uri`: Policy URI for VSA generation (required if --generate-vsa is used)
- `--fail-on-policy-error`: Exit with error code 1 when policy evaluation fails (default: false - exit code 0)
- `--attestations-path`: Path to directory containing attestation files for offline verification

For enhanced VSA features and SLSA v1.2 compliance details, see [docs/vsa-metadata.md](docs/vsa-metadata.md).

The certificate identity source of truth is a JSON file with the following structure:

```json
{
  "identities": [
    {
      "version": "0.4.0",
      "sha": "d709edc9cc501e27f390b7818c9262075ee9e0da",
      "status": "latest",
      "identities": [
        "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
      ],
      "added": "2025-03-14"
    },
    {
      "version": "0.3.0",
      "sha": "a8d9bc3a1e5601d657f87f089a234717899712b1",
      "status": "approved",
      "identities": [
        "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@a8d9bc3a1e5601d657f87f089a234717899712b1"
      ],
      "added": "2025-02-22",
      "expires": "2026-02-22"
    },
    {
      "version": "0.1.0",
      "sha": "3f1e90cc8b4fd742c2cd3e4d81d6079c63fbaf67",
      "status": "revoked",
      "identities": [
        "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@3f1e90cc8b4fd742c2cd3e4d81d6079c63fbaf67"
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

### Changelog Generation

Generate a changelog from conventional commits:

```bash
autogov changelog [flags]
```

#### Changelog Flags

- `--from`: Starting ref (tag/branch/SHA); empty discovers latest tag
- `--to`: Ending ref (default: `HEAD`)
- `-o, --output`: Output file path (default: stdout)
- `--format`: Output format: `markdown`, `json` (default: `markdown`)
- `--repo-path`: Path to git repository (default: `.`)
- `--include-all`: Include non-releasable commit types (docs, chore, test, etc.)
- `--first-parent`: Follow only first parent (merge commits) for history
- `--version`: Version header; if empty and `--to` is a semver tag, derived from tag

#### Changelog Examples

```bash
# Generate changelog since last tag
autogov changelog

# Generate changelog between two tags
autogov changelog --from v0.3.0 --to v0.4.0

# Output as JSON
autogov changelog --format json

# Save to file
autogov changelog -o CHANGELOG.md

# Include all commit types (docs, chore, test, etc.)
autogov changelog --include-all
```

### Release Management

The `release` command provides a full release workflow with three subcommands.

#### `release plan` — Preview a release

```bash
autogov release plan [flags]
```

Analyzes commits since the last tag, determines the next semantic version, and shows what would be included in a release.

**Flags:**

- `--from`: Base ref to compare from (default: latest tag)
- `--to`: Target ref to compare to (default: `HEAD`)
- `--first-parent`: Only follow first parent commits in merge history
- `-o, --output`: Output format: `text`, `json`, `yaml` (default: `text`)
- `--repo`: Path to git repository (default: `.`)
- `--mutations-config`: Path to mutations config file for file update preview
- `--mode`: Git read mode — `auto` (default), `api` (discover tags/commits via the GitHub API; works without a full clone, needs a token), `local` (go-git only)

#### `release cut` — Execute a release

```bash
autogov release cut [flags]
```

Applies file mutations, creates a release commit and tag via GitHub API (providing SLSA v1.2 provenance through GitHub's auto-signing), and creates a draft GitHub release.

**Flags:**

- `--plan-file`: Path to pre-generated release plan (JSON/YAML)
- `--branch`: Expected branch to cut release from (default: `main`)
- `--remote`: Git remote to push to (default: `origin`)
- `--mutations-config`: Path to mutations config file
- `--dry-run`: Show what would be done without making changes
- `--publish`: Publish the release directly (skip the draft state)
- `--mode`: Git read mode: `auto` (default), `api` (require GitHub API), `local` (go-git only)
- `--asset`: File to upload as a release asset (repeatable)
- `--asset-label`: Display label for an asset as `name=label` (repeatable)
- `--repo`: Path to git repository (default: `.`)
- `--commit-author`: Author name for release commit (default: `autogov[bot]`)
- `--commit-email`: Author email for release commit (default: `autogov[bot]@users.noreply.github.com`)
- `-o, --output`: Output format: `text`, `json` (default: `text`)

#### `release publish` — Publish a draft release

```bash
autogov release publish [flags]
```

Publishes a draft GitHub release, making it visible to users.

**Flags:**

- `--tag`: Specific tag to publish (mutually exclusive with `--latest`; requires a user token, as GitHub App tokens cannot discover drafts)
- `--latest`: Publish latest draft release (mutually exclusive with `--tag`; requires a user token, as GitHub App tokens cannot discover drafts)
- `--release-id`: Publish by release ID (works with GitHub App tokens)
- `--dry-run`: Show what would be done without publishing
- `--repo`: Path to git repository (default: `.`)
- `-o, --output`: Output format: `text`, `json` (default: `text`)

#### Release Workflow Example

```bash
# 1. Preview the release
autogov release plan

# 2. Cut the release (creates commit, tag, and draft release)
autogov release cut --mutations-config .autogov-mutations.yaml

# 3. After CI passes, publish
autogov release publish --latest
```

### Version

Print build version information:

```bash
autogov version
```

## Examples

Verify a container image:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify attestation \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --source-ref refs/heads/main
```

Verify a blob file:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify attestation \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo \
  --blob-path path/to/your/file \
  --source-ref refs/heads/main
```

Using environment variables:

```bash
export GITHUB_AUTH_TOKEN=your_token
export CERT_IDENTITY="https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da"
export CERT_ISSUER=https://token.actions.githubusercontent.com
autogov verify attestation --repo owner/repo -d "sha256:702bea33d240c2f0a1d87fe649a49b52f533bde2005b3c1bc0be7859dd5e4226"
```

Verify with certificate identity validation:

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify attestation \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --cert-identity-list "https://raw.githubusercontent.com/liatrio/autogov-workflows/refs/heads/main/cert-identities.json"
```

Generate enhanced VSA with policy evaluation (policy bundle pulled from an OCI registry):

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify attestation \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --generate-vsa \
  --vsa-output ./verification-summary.json \
  --policy-uri "https://github.com/liatrio/autogov-policy-library" \
  --policy-bundle-path "oci://ghcr.io/liatrio/autogov-policy-library:latest"
```

The policy bundle can also be pulled from a GitHub release asset with the `ghrel://` scheme (omit `@tag` for the latest release):

```bash
export GITHUB_AUTH_TOKEN=your_token
autogov verify attestation \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --generate-vsa \
  --vsa-output ./verification-summary.json \
  --policy-uri "https://github.com/liatrio/autogov-policy-library" \
  --policy-bundle-path "ghrel://liatrio/autogov-policy-library?asset=bundle.tar.gz" \
  --policy-schemas-path "ghrel://liatrio/autogov-policy-library?asset=schemas.tar.gz"
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
autogov verify attestation \
  --cert-identity "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@d709edc9cc501e27f390b7818c9262075ee9e0da" \
  --repo owner/repo \
  --image-digest "sha256:ee911cb4dba66546ded541337f0b3079c55b628c5d83057867b0ef458abdb682" \
  --generate-vsa \
  --vsa-output ./verification-summary.json \
  --policy-uri "https://github.com/liatrio/autogov-policy-library" \
  --policy-bundle-path bundle.tar.gz \
  --policy-data-path thresholds.json \
  --fail-on-policy-error
```

**Threshold Values:**
- `0`: No vulnerabilities allowed (zero tolerance)
- Positive number: Maximum allowed count
- `-1`: Unlimited (disable check for that severity)

For VSA output features, metadata structure, and SLSA v1.2 compliance details, see [docs/vsa-metadata.md](docs/vsa-metadata.md).

## Output

The tool provides detailed output about the verification process, including human-readable predicate type names:

```shell
Starting verification process...
---
Certificate identity validation enabled
Using identity source: https://raw.githubusercontent.com/liatrio/autogov-workflows/main/cert-identities.json
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

The tool verifies each attestation against the trusted root that matches its signing certificate. Two roots are supported, both carrying the certificate authorities and timestamp authorities required for Sigstore verification:

- **Public-good Sigstore** — used by public repositories (their GitHub Actions attestations are signed against public-good Fulcio and carry a Rekor integrated timestamp). The root is embedded in the binary.
- **GitHub** — used by private repositories (signed against GitHub's `fulcio.githubapp.com` Fulcio). The root is fetched dynamically via `gh attestation trusted-root`, with fallback to an embedded copy.

### Per-Attestation Selection

In the default `auto` mode the root is chosen per attestation from the **Fulcio CA that issued the signing certificate**, not from the OIDC issuer. The OIDC issuer (`https://token.actions.githubusercontent.com`) is the same for both public and private GitHub Actions flows, so it cannot be the discriminator; the issuing Fulcio CA can:

- Certificate issued by public-good Sigstore Fulcio (`sigstore.dev`) → public-good Sigstore root
- Certificate issued by GitHub Fulcio (`fulcio.githubapp.com`) → GitHub root

Use `--trusted-root-source github|public|auto` to force a root, or `--trusted-root <file>` to supply a custom one (takes precedence over `--trusted-root-source`).

### Dynamic Fetching (GitHub root)

When the GitHub root is needed, the tool tries `gh attestation trusted-root` first (requires network access to GitHub's API and a valid token) and falls back to the embedded copy if the fetch fails:

```text
✓ Using dynamically fetched trusted root
```

or

```text
! Failed to fetch dynamic trusted root (...), falling back to embedded version
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

5. **`failed to verify timestamps: threshold not met ... 0 < 1`, or a persistently FAILED VSA**
   - A timestamp-threshold error (e.g. `threshold not met for verified signed & log entry integrated timestamps: 0 < 1`) on public-repo attestations, or a long-standing FAILED VSA caused by policy bundles/schemas not loading, is fixed by upgrading to **autogov v0.29.8 or later**, which adds public-good Sigstore verification, `ghrel://` policy-bundle/schema fetching, and schemas-extraction fixes.

If you encounter any other issues, please [open an issue](https://github.com/liatrio/autogov/issues/new) and include as much detail as possible.

## Development

### Prerequisites

- Go 1.26 or higher
- GitHub CLI (`gh`) for trusted root fetching
- Docker for container registry access
- golangci-lint for code quality checks
- [Task](https://taskfile.dev) for build automation
- GitHub Personal Access Token with appropriate permissions

### Local Development

```bash
# Clone and setup
git clone https://github.com/liatrio/autogov
cd autogov

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

### Reproducible Builds

`task build` produces a deterministic binary. The embedded `main.date` is derived from the commit timestamp (`git show -s --format=%cI HEAD`) rather than wall-clock time, so the build does not vary by when it runs. The binary is built with `-trimpath` and `CGO_ENABLED=0` to strip local filesystem paths and avoid C toolchain variance. As a result, rebuilding the same commit yields byte-identical output.

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

### Debugging

```bash
# build with debug symbols
go build -o bin/autogov-debug .

# run with delve
dlv debug . -- verify attestation --repo "owner/repo" -d "sha256:..."

# run tests with race detector
go test -race ./...

# cpu/memory profiling
go test -cpuprofile=cpu.prof -bench=. ./...
go tool pprof cpu.prof

go test -memprofile=mem.prof -bench=. ./...
go tool pprof mem.prof
```

### Architecture Overview

The tool is organized into several key packages:

- **`pkg/attestations/`**: GitHub API integration, sigstore verification, certificate validation
- **`pkg/bundle/`**: Common utilities for working with Sigstore bundles
- **`pkg/certid/`**: Certificate identity validation against approved lists with caching
- **`pkg/cli/`**: CLI-specific helpers for argument processing and digest handling
- **`pkg/digest/`**: Digest calculation utilities for files, directories, and streams
- **`pkg/download/`**: Attestation download from GitHub for offline workflows
- **`pkg/github/`**: GitHub client and token management
- **`pkg/mutate/`**: Configuration file mutations (JSON, YAML, TOML) for release versioning
- **`pkg/offline/`**: Offline attestation verification using pre-downloaded bundles
- **`pkg/orchestrate/`**: Verification workflow orchestration
- **`pkg/policy/`**: OPA integration for policy evaluation
- **`pkg/release/`**: Release management (plan, cut, publish, changelog, version bumping)
- **`pkg/root/`**: Trusted root management with dynamic fetching and fallback
- **`pkg/vsa/`**: SLSA v1.2 VSA generation with comprehensive validation

### Predicate Type Standardization

For the full predicate type registry, lookup behavior, and unknown-type handling, see [docs/predicate-types.md](docs/predicate-types.md).

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to contribute to this project.

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
