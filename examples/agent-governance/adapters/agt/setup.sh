#!/usr/bin/env bash
# creates the isolated python 3.13 venv for the AGT fixture producer.
#
# the venv installs ONLY the hash-locked set in requirements.lock.txt:
# agent-governance-toolkit-core==4.1.0 (exact wheel sha256 verified below
# before anything is installed) plus its locked transitives. no meta-package,
# extras, unpinned range, main branch, or 5.0/ACS contract is ever used. a
# hash mismatch is a hard stop — never fall forward to another artifact.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${HERE}/.venv"
WHEELS="${HERE}/.wheels"
PYTHON="${PYTHON:-python3.13}"

command -v "$PYTHON" >/dev/null || { echo "error: $PYTHON not found (the fixture pins python 3.13)" >&2; exit 1; }

WANT_SHA="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wheel"]["sha256"])' "${HERE}/pins.json")"
WHEEL_URL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wheel"]["url"])' "${HERE}/pins.json")"
WHEEL_FILE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wheel"]["filename"])' "${HERE}/pins.json")"

mkdir -p "$WHEELS"
if [ ! -f "${WHEELS}/${WHEEL_FILE}" ]; then
  echo "downloading pinned core wheel..."
  curl -fsSL -o "${WHEELS}/${WHEEL_FILE}" "$WHEEL_URL"
fi

GOT_SHA="$(shasum -a 256 "${WHEELS}/${WHEEL_FILE}" | awk '{print $1}')"
if [ "$GOT_SHA" != "$WANT_SHA" ]; then
  echo "error: wheel sha256 mismatch (got ${GOT_SHA}, want ${WANT_SHA}) — refusing to install" >&2
  exit 1
fi
echo "verified core wheel sha256: ${GOT_SHA}"

"$PYTHON" -m venv "$VENV"
# --require-hashes pins every transitive; the verified local wheel dir is
# preferred and PyPI supplies any wheel not already cached, still hash-checked
"${VENV}/bin/pip" install --quiet --find-links "$WHEELS" --require-hashes -r "${HERE}/requirements.lock.txt"
"${VENV}/bin/python" -c 'from importlib.metadata import version; print("installed agent-governance-toolkit-core", version("agent-governance-toolkit-core"))'
echo "venv ready: ${VENV}"
