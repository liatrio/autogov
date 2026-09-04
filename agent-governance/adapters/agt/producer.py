#!/usr/bin/env python3
# AGT fixture producer for the agent-governance evidence spike.
#
# runs the four mandatory write-marker conformance cases (plus the
# unknown-outcome negative) through the pinned Microsoft AGT core
# (agent-governance-toolkit-core==4.1.0) PolicyEvaluator and serializes the
# same neutral deployment-evidence contract as the non-AGT producer. AGT stays
# behind this replaceable JSON boundary: no AGT object shapes leak into the
# core contract and the Auto Gov binary gains no AGT dependency.
#
# run inside the isolated venv created by setup.sh (python 3.13, hash-locked
# wheel set). the producer reads the version through importlib.metadata; the
# deprecated agent_os namespace's internal version string is not trusted.
#
# determinism: timestamps are pinned by the harness so committed evidence is
# byte-reproducible. records exclude temporary paths, prompts, tool arguments,
# credentials, and AGT audit context snapshots — only bounded redacted
# references and digests are emitted.
"""AGT producer: emits neutral agent-governance deployment evidence."""

import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import pathlib
import sys
import tempfile
import warnings
import zipfile
from base64 import urlsafe_b64encode
from csv import reader as csv_reader
from importlib.metadata import PackageNotFoundError, distribution

HERE = pathlib.Path(__file__).resolve().parent
BASE = HERE.parents[1]  # examples/agent-governance
FIXTURES = BASE / "fixtures"
EVIDENCE_DIR = FIXTURES / "evidence" / "agt"
RECORDS_DIR = EVIDENCE_DIR / "records"


def load_local_source_module(name: str, path: pathlib.Path):
    """load one hashed fixture module from its exact source path."""
    resolved = path.resolve()
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load fixture module from {resolved}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    if pathlib.Path(module.__file__).resolve() != resolved:
        raise SystemExit(f"fixture module origin does not match {resolved}")
    return module


# ignore adjacent timestamp-based bytecode before importing any module whose
# source digest is recorded in evidence. The fresh prefix stays live for the
# isolated producer process so later imports cannot fall back to old pycs.
_IMPORT_PYCACHE = tempfile.TemporaryDirectory(prefix="autogov-fixture-pycache-")
sys.pycache_prefix = _IMPORT_PYCACHE.name
sys.dont_write_bytecode = True

write_marker = load_local_source_module(
    "_autogov_fixture_write_marker", FIXTURES / "write_marker.py"
)

PRODUCER = "agt"
ENGINE = "agent-os-policy-evaluator"
RUNTIME_NAME = "agent-governance-toolkit-core"
RUNTIME_FRAMEWORK = "agent-os"
INTERVENTION_POINT = "tool.pre"
CORRELATION_SALT = "autogov-agent-governance-demo-v0.1"
URN_BASE = "urn:autogov:example:agent-governance"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of_bytes(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def digest_of_file(path: pathlib.Path) -> str:
    return digest_of_bytes(path.read_bytes())


def record_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_record(name: str, obj) -> str:
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    data = record_bytes(obj)
    (RECORDS_DIR / name).write_bytes(data)
    return digest_of_bytes(data)


def ts(second: int) -> str:
    return f"2026-08-26T20:00:{second:02d}Z"


def correlation_id(case_id: str) -> str:
    return "sha256:" + sha256_hex(f"{CORRELATION_SALT}:{PRODUCER}:{case_id}".encode())


def load_pins():
    pins = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
    try:
        installed = distribution(pins["package"])
    except PackageNotFoundError:
        raise SystemExit(
            f"{pins['package']} is not installed in this environment; run {HERE / 'setup.sh'} first"
        )
    if installed.version != pins["version"]:
        raise SystemExit(
            f"installed {pins['package']} {installed.version} does not match the locked {pins['version']}"
        )
    wheel = verify_core_wheel(pins)
    verified_files, core_module_roots = verify_installed_distribution(
        installed, pins["package"], wheel
    )
    return pins, verified_files, core_module_roots


def verify_core_wheel(pins) -> pathlib.Path:
    """verify setup's locally cached wheel and its venv installation receipt."""
    wheel = HERE / ".wheels" / pins["wheel"]["filename"]
    if not wheel.is_file():
        raise SystemExit(f"verified AGT wheel is missing at {wheel}; run {HERE / 'setup.sh'} first")
    got = sha256_hex(wheel.read_bytes())
    if got != pins["wheel"]["sha256"]:
        raise SystemExit(
            f"cached AGT wheel sha256 {got} does not match the locked {pins['wheel']['sha256']}"
        )

    receipt = pathlib.Path(sys.prefix) / ".autogov-agt-core-wheel.json"
    try:
        installed_from = json.loads(receipt.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"AGT installation receipt is missing at {receipt}; rerun {HERE / 'setup.sh'}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"AGT installation receipt is invalid: {exc}")
    expected = {
        "package": pins["package"],
        "version": pins["version"],
        "filename": pins["wheel"]["filename"],
        "sha256": pins["wheel"]["sha256"],
    }
    if installed_from != expected:
        raise SystemExit("AGT installation receipt does not match the locked core wheel; rerun setup.sh")
    return wheel


def verify_installed_distribution(installed, package: str, wheel: pathlib.Path):
    """check installed AGT files against RECORD from the verified wheel."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            record_names = [name for name in archive.namelist() if name.endswith(".dist-info/RECORD")]
            if len(record_names) != 1:
                raise SystemExit(
                    f"verified {package} wheel contains {len(record_names)} RECORD files, expected one"
                )
            record_name = record_names[0]
            record_rows = list(csv_reader(archive.read(record_name).decode("utf-8").splitlines()))
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"verified {package} wheel RECORD cannot be read: {exc}")

    verified_files = set()
    core_module_roots = set()
    for row in record_rows:
        if len(row) != 3:
            raise SystemExit(f"verified {package} wheel has a malformed RECORD row")
        if not row[1]:
            if row[0] != record_name or row[2]:
                raise SystemExit(f"verified {package} wheel has an unexpected unhashed RECORD entry")
            continue
        algorithm, _, expected = row[1].partition("=")
        if algorithm != "sha256" or not expected:
            raise SystemExit(f"verified {package} wheel RECORD has an unsupported hash entry")
        path = pathlib.Path(installed.locate_file(row[0])).resolve()
        if not path.is_file():
            raise SystemExit(f"installed {package} file recorded by wheel RECORD is missing: {row[0]}")
        try:
            expected_size = int(row[2])
        except ValueError:
            raise SystemExit(f"verified {package} wheel RECORD has an invalid file size")
        if path.stat().st_size != expected_size:
            raise SystemExit(f"installed {package} file size does not match wheel RECORD: {row[0]}")
        actual = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode().rstrip("=")
        if actual != expected:
            raise SystemExit(f"installed {package} file does not match verified wheel RECORD: {row[0]}")
        verified_files.add(path)

        top_level = pathlib.PurePosixPath(row[0]).parts[0]
        if not top_level.endswith((".dist-info", ".data")):
            if top_level.endswith(".py"):
                top_level = top_level.removesuffix(".py")
            core_module_roots.add(top_level)

    return frozenset(verified_files), frozenset(core_module_roots)


class VerifiedCoreFinder(importlib.abc.MetaPathFinder):
    """resolve core-wheel modules only from RECORD-verified installed files."""

    def __init__(self, verified_files, core_module_roots):
        self.verified_files = verified_files
        self.core_module_roots = core_module_roots

    def find_spec(self, fullname, path=None, target=None):
        if fullname.partition(".")[0] not in self.core_module_roots:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec is None or spec.origin in (None, "built-in", "frozen"):
            raise ImportError(f"verified AGT core module {fullname} has no source origin")
        if pathlib.Path(spec.origin).resolve() not in self.verified_files:
            raise ImportError(f"AGT core module {fullname} resolved outside the verified wheel")
        return spec


_AGT_IMPORT_GUARD = None


def load_agt_policy_types(verified_files, core_module_roots):
    """import AGT only after its pinned installation has been verified."""
    global _AGT_IMPORT_GUARD
    if _AGT_IMPORT_GUARD is not None:
        raise SystemExit("AGT policy import guard was already installed")
    if any(name.partition(".")[0] in core_module_roots for name in sys.modules):
        raise SystemExit("AGT core modules were loaded before pinned-file verification")

    # the deprecated agent_os namespace warns on import; the warning is
    # expected and the distribution version comes from importlib.metadata.
    # the import guard remains installed for the process lifetime so lazy core
    # imports cannot resolve to a shadow package after the initial import.
    guard = VerifiedCoreFinder(verified_files, core_module_roots)
    sys.meta_path.insert(0, guard)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from agent_os.policies import PolicyDocument, PolicyEvaluator
    except BaseException:
        sys.meta_path.remove(guard)
        raise
    _AGT_IMPORT_GUARD = guard

    return PolicyDocument, PolicyEvaluator


def default_behavior_from(evaluator) -> str:
    """read the pinned evaluator's actual fallback decision, not a literal."""
    decision = evaluator.evaluate({})
    action = getattr(decision, "action", None)
    value = getattr(action, "value", action)
    if isinstance(value, str) and value.lower() in {"allow", "deny"}:
        return value.lower()
    if isinstance(getattr(decision, "allowed", None), bool):
        return "allow" if decision.allowed else "deny"
    raise SystemExit("pinned AGT evaluator produced no recognizable default action")


def run_case(spec, shared):
    """run one conformance case through the pinned AGT PolicyEvaluator."""
    policy_loaded = spec["policy_loaded"]
    policy_document_type = shared["policy_document_type"]
    policy_evaluator_type = shared["policy_evaluator_type"]
    if policy_loaded:
        policy_document = policy_document_type.from_yaml(HERE / "runtime_policy.yaml")
        evaluator = policy_evaluator_type([policy_document])
        default_behavior = default_behavior_from(evaluator)
    else:
        evaluator = policy_evaluator_type([])
        # with zero policies the AGT core evaluator falls back to a global
        # allow; the evidence records that honestly and admission still fails
        # because no policy was loaded
        default_behavior = default_behavior_from(evaluator)

    decision = None
    marker_present = False
    marker_digest = None

    with tempfile.TemporaryDirectory(prefix="autogov-agentgov-") as workdir:
        if spec["bypass"]:
            # consequential action without traversing the tool.pre middleware:
            # no PolicyEvaluator decision is correlated with this write
            write_marker.write_marker(workdir)
        else:
            context = {"tool_name": "write-marker", "purpose": spec["purpose"]}
            decision = evaluator.evaluate(context)  # tool.pre
            if decision.allowed:
                write_marker.write_marker(workdir)

        marker_path = pathlib.Path(workdir) / write_marker.MARKER_NAME
        if marker_path.exists():
            marker_present = True
            marker_digest = digest_of_file(marker_path)
        # cleanup of the known temporary directory is automatic on exit

    case_id = spec["case_id"]
    started, completed = ts(spec["start"]), ts(spec["start"] + 1)

    decision_obj = {"state": "not-observed", "verdict": "unknown"}
    if decision is not None:
        verdict = "allow" if decision.allowed else "deny"
        # redacted decision record: no audit_entry, context snapshot, wall-clock
        # timestamp, or temporary path may leak into evidence
        decision_record = {
            "caseId": case_id,
            "engine": ENGINE,
            "matchedRule": decision.matched_rule,
            "policyArtifactDigest": shared["policy_digest" if policy_loaded else "no_policy_digest"],
            "verdict": verdict,
            "viaDefault": decision.matched_rule is None,
        }
        decision_obj = {
            "state": "observed",
            "verdict": verdict,
            "reference": {
                "id": f"redacted:{case_id}-decision",
                "digest": write_record(f"{case_id}-decision.json", decision_record),
            },
            "observedAt": started,
        }

    if spec["outcome_verified"]:
        outcome_record = {"caseId": case_id, "markerPresent": marker_present}
        if marker_present:
            outcome_record["markerContentDigest"] = marker_digest
        outcome_obj = {
            "state": "verified",
            "result": "occurred" if marker_present else "blocked",
            "reference": {
                "id": f"redacted:{case_id}-outcome",
                "digest": write_record(f"{case_id}-outcome.json", outcome_record),
            },
            "observedAt": completed,
        }
    else:
        outcome_obj = {"state": "unknown", "result": "unknown"}

    if policy_loaded:
        policy = {
            "engine": ENGINE,
            "artifact": {
                "uri": f"{URN_BASE}:{PRODUCER}:runtime-policy:write-marker",
                "digest": shared["policy_digest"],
            },
            "count": 1,
            "loaded": True,
        }
    else:
        policy = {
            "engine": ENGINE,
            "artifact": {
                "uri": f"{URN_BASE}:{PRODUCER}:runtime-policy:none",
                "digest": shared["no_policy_digest"],
            },
            "count": 0,
            "loaded": False,
        }

    return {
        "schemaVersion": "0.1",
        "agent": shared["agent"],
        "runtime": {
            "name": RUNTIME_NAME,
            "version": shared["runtime_version"],
            "framework": RUNTIME_FRAMEWORK,
            "artifact": {
                "uri": shared["wheel_url"],
                "digest": shared["runtime_digest"],
            },
        },
        "adapter": {
            "name": "agt-fixture-adapter",
            "artifact": {
                "uri": f"{URN_BASE}:{PRODUCER}:adapter:0.1",
                "digest": shared["adapter_digest"],
            },
            "contractVersion": "0.1",
            "runtimeDigest": shared["runtime_digest"],
        },
        "runtimePolicy": policy,
        "enforcement": {
            "mode": "enforce",
            "defaultBehavior": default_behavior,
            "requiredInterventionPoints": [INTERVENTION_POINT],
            "observedInterventionPoints": [] if spec["bypass"] else [INTERVENTION_POINT],
        },
        "identity": shared["identity"],
        "audit": shared["audit"],
        "conformance": {
            "fixture": {"id": f"{PRODUCER}-fixture-001", "producer": PRODUCER},
            "controlledTool": {
                "name": "write-marker",
                "actionClass": "filesystem.write.marker",
                "artifact": {
                    "uri": "urn:autogov:fixture:write-marker",
                    "digest": shared["tool_digest"],
                },
            },
            "cases": [
                {
                    "id": case_id,
                    "kind": spec["kind"],
                    "correlationId": correlation_id(case_id),
                    "startedAt": started,
                    "completedAt": completed,
                    "decision": decision_obj,
                    "outcome": outcome_obj,
                    "testResult": {
                        "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
                        "testId": case_id,
                        # statementDigest is bound by the signing helper after it
                        # builds the signed test-result statement bytes
                    },
                }
            ],
        },
    }


def main() -> None:
    pins, verified_files, core_module_roots = load_pins()
    policy_document_type, policy_evaluator_type = load_agt_policy_types(
        verified_files, core_module_roots
    )
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)

    no_policy_digest = write_record("no-policy.json", {"engine": ENGINE, "policies": []})
    identity_digest = write_record(
        "identity.json",
        {"provider": f"{URN_BASE}:identity:local-demo", "workload": f"{PRODUCER}-fixture-workload"},
    )
    sink_digest = write_record(
        "audit-sink.json", {"kind": "file", "sink": f"{PRODUCER}-audit-log"}
    )
    audit_config_digest = write_record(
        "audit-config.json", {"format": "jsonl", "redaction": "digest-only"}
    )

    shared = {
        "policy_document_type": policy_document_type,
        "policy_evaluator_type": policy_evaluator_type,
        "agent": {
            "name": "agent-image",
            "uri": f"{URN_BASE}:agent-image",
            "artifactDigest": digest_of_file(FIXTURES / "agent" / "agent-image.txt"),
        },
        "runtime_version": pins["version"],
        "runtime_digest": "sha256:" + pins["wheel"]["sha256"],
        "wheel_url": pins["wheel"]["url"],
        "adapter_digest": digest_of_file(HERE / "producer.py"),
        "policy_digest": digest_of_file(HERE / "runtime_policy.yaml"),
        "no_policy_digest": no_policy_digest,
        "tool_digest": digest_of_file(FIXTURES / "write_marker.py"),
        "identity": {
            "providerUri": f"{URN_BASE}:identity:local-demo",
            "subjectKind": "workload",
            "subject": {
                "id": f"redacted:{PRODUCER}-fixture-workload",
                "digest": identity_digest,
            },
        },
        "audit": {
            "sinkKind": "file",
            "sink": {"id": f"redacted:{PRODUCER}-audit-sink", "digest": sink_digest},
            "configurationDigest": audit_config_digest,
        },
    }

    specs = [
        {
            "file": "allowed-action.json",
            "case_id": f"{PRODUCER}-allowed-action-001",
            "kind": "allowed-action",
            "purpose": "sanctioned-write",
            "policy_loaded": True,
            "bypass": False,
            "outcome_verified": True,
            "start": 0,
        },
        {
            "file": "denied-action.json",
            "case_id": f"{PRODUCER}-denied-action-001",
            "kind": "denied-action",
            "purpose": "blocked-write",
            "policy_loaded": True,
            "bypass": False,
            "outcome_verified": True,
            "start": 2,
        },
        {
            "file": "adapter-bypass.json",
            "case_id": f"{PRODUCER}-adapter-bypass-001",
            "kind": "adapter-bypass",
            "purpose": None,
            "policy_loaded": True,
            "bypass": True,
            "outcome_verified": True,
            "start": 4,
        },
        {
            "file": "no-policy-loaded.json",
            "case_id": f"{PRODUCER}-no-policy-loaded-001",
            "kind": "no-policy-loaded",
            "purpose": "sanctioned-write",
            "policy_loaded": False,
            "bypass": False,
            "outcome_verified": True,
            "start": 6,
        },
        {
            # negative fixture: not one of the four mandatory cases; admission
            # must fail because an unknown outcome is never promoted to verified
            "file": "unknown-outcome.json",
            "case_id": f"{PRODUCER}-unknown-outcome-001",
            "kind": "allowed-action",
            "purpose": "sanctioned-write",
            "policy_loaded": True,
            "bypass": False,
            "outcome_verified": False,
            "start": 8,
        },
    ]

    for spec in specs:
        evidence = run_case(spec, shared)
        out = EVIDENCE_DIR / spec["file"]
        out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {out.relative_to(BASE)}")


if __name__ == "__main__":
    main()
