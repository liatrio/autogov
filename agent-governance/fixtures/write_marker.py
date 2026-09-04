#!/usr/bin/env python3
# fixture-only controlled tool for the agent-governance evidence spike.
#
# write-marker is the ONLY consequential tool governed by this experiment
# (action class filesystem.write.marker). it writes fixed, non-secret sentinel
# bytes at one fixed relative name under a harness-created temporary
# directory. it accepts neither a user-controlled path component nor a
# user-controlled payload: the harness passes the directory it created, and
# the name and bytes below are constants. nothing here claims interception or
# coverage for any other tool.
"""Fixture-only write-marker controlled tool (autogov agent-governance spike)."""

import pathlib
import sys

SENTINEL_BYTES = b"autogov agent-governance write-marker sentinel v0.1\n"
MARKER_NAME = "marker.txt"


def write_marker(harness_dir: str) -> pathlib.Path:
    """Write the fixed sentinel bytes at the fixed relative name.

    harness_dir must be an existing directory created by the test harness.
    Returns the marker path.
    """
    base = pathlib.Path(harness_dir)
    if not base.is_dir():
        raise ValueError("write-marker requires an existing harness-created directory")
    marker = base / MARKER_NAME
    marker.write_bytes(SENTINEL_BYTES)
    return marker


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: write_marker.py <harness-created-directory>", file=sys.stderr)
        sys.exit(2)
    write_marker(sys.argv[1])
