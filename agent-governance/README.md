# Agent-governance companion

A repository-local companion for authoring and demonstrating experimental
agent-deployment governance evidence. AutoGov remains the generic Sigstore
verification, OPA admission, and VSA engine; this companion owns the v0.1
agent model, schema, producer fixtures, authoring CLI, and opt-in policy.

Two evidence producers (one pinned Microsoft AGT fixture, one minimal non-AGT
fixture) each run the same four controlled conformance cases against the one
governed tool, emit the same runtime-neutral JSON evidence contract, and are
enforced through Auto Gov's **existing** offline path:

```text
producer evidence JSON (unbound test-result digest)
  -> demo/signing helper normalizes evidence, builds the standard test-result
     payload, and binds its exact payload digest into the deployment evidence
  -> agent-governance-evidence                       (consumes the completed/bound
     evidence and emits a deterministic predicate body;
     the demo exercises this companion CLI as a subprocess)
  -> signed in-toto deployment statement + separately signed standard
     test-result statement (demo signing helper, local demonstration CA)
  -> autogov offline (Sigstore verification)
  -> local opt-in Rego admission gate (OPA)
  -> unsigned VSA JSON statement + enforcing exit code
```

Expected admission per producer: `PASSED`, `PASSED`, `FAILED`, `FAILED` for
the allowed, denied, bypassed, and no-policy cases — plus a failing
`unknown-outcome` negative fixture.

The public `agent-governance-evidence` CLI accepts only the completed evidence
state: `case.testResult.statementDigest` must already bind the exact standard
test-result statement payload. Producer output is intentionally unbound. In
the demonstration, the private `internal/demokit` signing helper performs that
completion step before invoking the CLI; it is not a separate public command.

## honest scope and limits

- **One controlled tool.** The only governed action is the fixture-only
  `write-marker` tool (`fixtures/write_marker.py`): it writes fixed non-secret
  sentinel bytes at a fixed relative name under a harness-created temporary
  directory and accepts no user-controlled path or payload. Nothing here
  claims interception or coverage for any other tool, agent, or layer.
- **The VSA JSON is unsigned.** `autogov offline --generate-vsa` writes an
  unsigned VSA JSON statement after verifying the signed inputs. Signing or
  re-verifying that VSA is outside this spike.
- **Configured is not exercised.** Required intervention points and observed
  intervention points are separate facts; the admission gate never infers one
  from the other, never accepts an adapter-supplied aggregate
  `passed`/`compliant` claim, and never promotes an `unknown` outcome to
  verified.
- **Two different policy digests.** The `runtimePolicy.artifact.digest` inside
  the deployment predicate identifies the policy governing the *agent at
  runtime*. The policy digest recorded in the generated VSA identifies Auto
  Gov's *admission* policy (this directory's Rego gate). They are different
  artifacts and must never be described as the same thing.
- **Demonstration signing.** The demo signs with a local, ephemeral CA/TSA
  created per run (`demokit`); it chains to nothing public and exists so the
  offline Sigstore verification path runs for real. Adapters never sign their
  own claims.
- **AGT wheel provenance gap.** The AGT v4.1.0 release workflow attests the
  source archive and SBOM assets; the PyPI wheel itself is not directly
  attested. That gap is recorded in `adapters/agt/pins.json` and is never
  upgraded into a verified wheel-provenance claim.
- **Identifier, not a hosted schema.** The custom predicate-type URI is an
  identifier in an in-toto statement; it is not fetched or dereferenced. The
  companion-owned embedded schema is checked in at
  `internal/evidence/schemas/agent-governance-deployment-schema.json`.
- **Artifact and CLI boundary.** The supported interface between the companion
  and AutoGov is JSON/in-toto artifacts plus CLI execution. There is no public
  Go SDK contract, and neither Go dependency graph imports the other.

## Stewardship and extraction gates

The v0.1 contract remains under the `autogov.dev` namespace with its exact
published semantics. A community-neutral contract requires a new URI and
version; v0.1 will not be silently redefined. The companion is incubated in
this repository and Go module so the existing CI can exercise both sides of
the artifact boundary.

A later history-preserving move to a separate Apache-2.0 repository is gated
on all of the following: design-partner validation, an agreed neutral
namespace, named maintainers and security ownership, and a release/signing
process. This extraction creates no repository, release, package publication,
or production policy promotion. [`MOVE_MAP.md`](MOVE_MAP.md) records source
history, and [`checkpoint.sha256.json`](checkpoint.sha256.json) locks the
promotion baseline's deterministic outputs, policy digest, and frozen inputs.

## layout

```text
adapters/agt/        pinned AGT producer: producer.py, runtime_policy.yaml,
                     pins.json, requirements.lock.txt, setup.sh, lock.sh,
                     verify_pins.sh
adapters/non-agt/    minimal non-AGT producer: producer.py, toy_runtime.py,
                     runtime_policy.json
cmd/demo/            end-to-end demo runner (drives both built binaries)
cmd/agent-governance-evidence/
                     standalone predicate-body authoring CLI
cmd/checkpoint/      verifies the committed pre-extraction SHA-256 manifest
internal/evidence/  private v0.1 model, validation, schema, and wire helpers
internal/demokit/   demo/signing layer: statement building, local CA, bundles
internal/integration/
                     subprocess-only AutoGov admission and boundary tests
fixtures/            write_marker.py (the one controlled tool), the agent
                     artifact, and each producer's committed evidence + records
policy/              the local, opt-in Rego admission gate (NOT part of
                     autogov-policy-library; only used when explicitly passed
                     via --policy-bundle-path)
```

## pins (AGT producer)

| artifact | pin |
|---|---|
| package | `agent-governance-toolkit-core==4.1.0` (core only — no meta-package, no extras) |
| wheel sha256 | `e14a09eceaa88d3f5d572b09643138d95b1d6c349a6e23e5b222f3c0192cec1f` |
| source tag commit (v4.1.0) | `0de71ca6c95cf8b9b975ac96f48eaa7826bbe258` |
| CycloneDX SBOM sha256 | `07b5387905a780d39a3fbd88b9949cf7e1139c61e602ba58178f77797b886cb9` |
| SPDX SBOM sha256 | `fdc1d9632e3c83a1682216573967ee3f0ed2e0fd91e941b46992f03aa837c692` |
| python | 3.13 |
| transitives | hash-locked in `adapters/agt/requirements.lock.txt` |

Re-verify all pins against their official sources (network required):

```bash
./agent-governance/adapters/agt/verify_pins.sh
```

A mismatch or missing artifact is a hard stop — never substitute `latest`,
`main`, or a 5.0/ACS artifact. `setup.sh` installs the exact locally verified
core wheel first, records that wheel's identity in the isolated venv, and the
producer rechecks the receipt, hashes installed core files against `RECORD`
from that verified wheel, isolates bytecode, and binds core imports to those
verified files before emitting evidence. Hash-locked transitive wheels are
still trusted through pip's `--require-hashes` installation; the producer does
not independently rehash or import-bind their installed files, so that
transitive provenance limitation remains explicit.

## run the demonstration

From a clean checkout of this repository:

```bash
# Build both binaries, then run both producers' signed matrices through the
# companion authoring CLI and AutoGov's offline verifier.
task agent-governance-demo
```

The demo prints one row per case. Expected: `PASSED`, `PASSED`, `FAILED`,
`FAILED` per producer with exit code 0 for the two admissible cases and a
non-zero enforcing exit (after the failed VSA JSON is written) for the rest;
the `unknown-outcome*` negative also fails. The demo exits non-zero if any
observed result differs. Pass `-workdir <dir>` to create or reuse a retained
directory for the signed bundles, trusted root, predicate bodies, and VSA JSON
files. By default the temporary working directory is removed on exit; pass
`-keep` only to retain that automatically created temporary directory.

Equivalent focused tests (the black-box tests build isolated binaries):

```bash
task agent-governance-test
```

Repository-wide verification:

```bash
go test ./...
go vet ./...
task lint
task build
task agent-governance-build
```

## regenerating producer evidence

The evidence under `fixtures/evidence/` is committed and deterministic
(timestamps are pinned by each harness). `internal/demokit/fixtures_test.go` verifies
that the committed evidence and redacted records bind the committed fixture
files by digest; it does not execute either producer or prove a regenerated
file byte-for-byte. After regeneration, run the focused tests and review the
fixture diff. To regenerate:

```bash
# non-AGT producer (python 3 stdlib only)
python3 agent-governance/adapters/non-agt/producer.py

# AGT producer (isolated python 3.13 venv, hash-locked)
./agent-governance/adapters/agt/setup.sh
agent-governance/adapters/agt/.venv/bin/python \
  agent-governance/adapters/agt/producer.py
```

`setup.sh` refuses to install anything if the downloaded core wheel's sha256
does not match the pin. `lock.sh` regenerates `requirements.lock.txt`
(compiled wheels are platform-specific; the committed lock was generated on
macOS arm64 / CPython 3.13 — regenerate it on the platform you run on).

Producers never call Auto Gov: they stop at redacted JSON. Evidence and
records contain no prompts, tool arguments, model output, credentials, or
temporary paths — only bounded redacted references and digests. Each harness
creates its own temporary directory for `write-marker` and removes it.

## the four cases (and what they prove)

| case | facts in evidence | admission |
|---|---|---|
| `allowed-action` | policy loaded, `tool.pre` exercised, observed `allow`, separately signed outcome verified `occurred` | `PASSED` |
| `denied-action` | policy loaded, `tool.pre` exercised, observed `deny`, outcome verified `blocked` | `PASSED` |
| `adapter-bypass` | consequential write occurred with no correlated decision and no exercised point | `FAILED`, non-zero exit |
| `no-policy-loaded` | middleware present, zero policies loaded (`loaded=false`, engine default allowed the write) | `FAILED`, non-zero exit |
| `unknown-outcome` (negative) | observed `allow` but the outcome observation was dropped: state stays `unknown` | `FAILED`, non-zero exit |

Both producers must match on the schema contract's policy-semantic
portability projection for each case kind, while their producer, runtime,
adapter, runtime-policy, identity, audit, fixture, correlation, and evidence
digests stay distinct and individually bound
(`internal/integration/autogov_e2e_test.go`).

## evidence states

```text
declared -> discovered -> policy-tested -> deployment-attested
         -> decision-observed -> outcome-verified -> independently-assessed
```

This demonstration reaches `deployment-attested` for the signed deployment
statement, `decision-observed` for correlated decisions, and
`outcome-verified` only where a separately signed, cross-bound standard
test-result statement carries the bounded external observation.
`independently-assessed` is out of scope, and no output here claims a
stronger state than its evidence supports.

## cleanup

- The demo's automatically created working directory is removed on exit unless
  `-keep` is set. A caller-supplied `-workdir` is always retained.
- Producer harnesses remove their own `write-marker` temporary directories.
- The AGT fixture is fully contained in
  `agent-governance/adapters/agt/.venv` and `.wheels`; delete those
  directories to remove it. Nothing is installed outside this repository
  checkout.
