#!/usr/bin/env bash
# re-verifies the locked AGT v4.1.0 artifacts against their official sources
# without re-selecting them: pinned core wheel sha256, source tag commit, and
# both release SBOM sha256 values. any mismatch or missing artifact is an
# Ask First blocker for the spike — never fall forward to latest/main/5.0.
#
# note: the release workflow attests the source archive and SBOM assets; the
# PyPI wheel itself is not directly attested. this script verifies recorded
# hashes only and makes no provenance claim for the wheel.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PINS="${HERE}/pins.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1]));
for k in sys.argv[2].split("."): d=d[k]
print(d)' "$PINS" "$1"; }

fail=0

echo "1/3 pinned core wheel sha256"
curl -fsSL -o "${TMP}/core.whl" "$(field wheel.url)"
got="$(shasum -a 256 "${TMP}/core.whl" | awk '{print $1}')"
want="$(field wheel.sha256)"
if [ "$got" = "$want" ]; then echo "  ok: ${got}"; else echo "  MISMATCH: got ${got}, want ${want}"; fail=1; fi

echo "2/3 source tag commit"
got="$(git ls-remote https://github.com/microsoft/agent-governance-toolkit refs/tags/v4.1.0 | awk '{print $1}')"
want="$(field sourceTagCommit)"
if [ "$got" = "$want" ]; then echo "  ok: ${got}"; else echo "  MISMATCH: got ${got}, want ${want}"; fail=1; fi

echo "3/3 release SBOM sha256 (cyclonedx, spdx)"
for kind in cyclonedx spdx; do
  asset="$(field "sbom.${kind}.asset")"
  want="$(field "sbom.${kind}.sha256")"
  curl -fsSL -o "${TMP}/${asset}" "https://github.com/microsoft/agent-governance-toolkit/releases/download/v4.1.0/${asset}"
  got="$(shasum -a 256 "${TMP}/${asset}" | awk '{print $1}')"
  if [ "$got" = "$want" ]; then echo "  ok ${kind}: ${got}"; else echo "  MISMATCH ${kind}: got ${got}, want ${want}"; fail=1; fi
done

if [ "$fail" -ne 0 ]; then
  echo "pin verification FAILED — treat as an Ask First blocker; do not substitute artifacts" >&2
  exit 1
fi
echo "all pins verified"
