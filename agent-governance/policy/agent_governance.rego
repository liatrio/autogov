# local, explicit opt-in admission gate for the agent-governance evidence
# spike. this bundle lives only under examples/agent-governance and is used
# solely when passed via --policy-bundle-path; it is NOT part of the
# production autogov-policy-library and must not be promoted from here.
#
# input shape (offline seam): an array of verified attestation bundles
# [{"dsseEnvelope": {"payload": <base64 statement bytes>, "payloadType":
# "application/vnd.in-toto+json"}}, ...]. signature, certificate, and subject
# digest verification already happened in the offline verifier; this gate
# derives deployment admission from the verified statement facts.
#
# fail-closed structure: `allow` is derived POSITIVELY from required facts
# (never from the absence of violations), so a malformed statement can only
# make allow undefined/false. violations exist for attribution and reporting.
#
# the runtime-policy digest inside the deployment predicate identifies the
# policy governing the agent at runtime; it is distinct from the Auto Gov
# admission-policy digest this bundle gets in the generated VSA. an aggregate
# adapter verdict (`passed`/`compliant`) is rejected, configured controls are
# never treated as exercised, and an unknown outcome never satisfies an
# outcome requirement.
package governance

import rego.v1

deployment_type := "https://autogov.dev/attestation/agent-governance-deployment/v0.1"

test_result_type := "https://in-toto.io/attestation/test-result/v0.1"

statement_type := "https://in-toto.io/Statement/v1"

conformance_descriptor_name := "agent-governance-conformance-v0.1"

conformance_descriptor_uri := sprintf("%s#conformance", [deployment_type])

intoto_payload_type := "application/vnd.in-toto+json"

allowed_root_keys := {
	"schemaVersion", "agent", "runtime", "adapter", "runtimePolicy",
	"enforcement", "identity", "audit", "conformance", "extensions",
}

required_root_keys := {
	"schemaVersion", "agent", "runtime", "adapter", "runtimePolicy",
	"enforcement", "identity", "audit", "conformance",
}

controlled_tool_name := "write-marker"

controlled_tool_action_class := "filesystem.write.marker"

# the fixed fixture implementation is part of this repository-local demo's
# admission contract. a signer cannot substitute an arbitrary same-named tool
# merely by making the test-result descriptor agree with a supplied digest.
controlled_tool_digest := "sha256:9df776a3bb10bd24bb1693b274a49a1a0e3e74b391d24171f35fc88d77e0b8da"

ann_key(suffix) := sprintf("%s#%s", [deployment_type, suffix])

# --- decoded statements -----------------------------------------------------

payloads := [p |
	some i
	b := input[i]
	b.dsseEnvelope.payloadType == intoto_payload_type
	p := base64.decode(b.dsseEnvelope.payload)
]

deployment_statements := [s |
	some i
	p := payloads[i]
	s := json.unmarshal(p)
	s.predicateType == deployment_type
]

# test-result statements keep their exact payload-byte sha256 so linkage can
# bind case.testResult.statementDigest to the signed DSSE payload
test_result_statements := [t |
	some i
	p := payloads[i]
	s := json.unmarshal(p)
	s.predicateType == test_result_type
	t := {"stmt": s, "digest": crypto.sha256(p)}
]

# --- positive admission derivation ------------------------------------------

default allow := false

allow if {
	count(deployment_statements) == 1
	s := deployment_statements[0]
	deployment_envelope_valid(s)
	valid_case_cardinality(s)
	every c in s.predicate.conformance.cases {
		case_admissible(s, c)
	}
	count(agent_governance_violations) == 0
}

# the signed envelope must carry exactly one subject that equals the
# predicate's agent identity, and the predicate may carry only core fields —
# an adapter-supplied aggregate verdict field fails closed here
deployment_envelope_valid(s) if {
	s._type == statement_type
	count(s.subject) == 1
	some sub in s.subject
	sub.name == s.predicate.agent.name
	sprintf("sha256:%s", [sub.digest.sha256]) == s.predicate.agent.artifactDigest
	every k, _ in s.predicate {
		k in allowed_root_keys
	}
	required_root_keys_present(s)
	nested_core_shape_valid(s)
	s.predicate.schemaVersion == "0.1"
	controlled_tool_valid(s)
	adapter_valid(s)
}

required_root_keys_present(s) if {
	keys := object.keys(s.predicate)
	every k in required_root_keys {
		k in keys
	}
}

valid_case_cardinality(s) if {
	cases := s.predicate.conformance.cases
	is_array(cases)
	count(cases) >= 1
	count(cases) <= 4
}

controlled_tool_valid(s) if {
	tool := s.predicate.conformance.controlledTool
	tool.name == controlled_tool_name
	tool.actionClass == controlled_tool_action_class
	tool.artifact.digest == controlled_tool_digest
	canonical_digest(tool.artifact.digest)
}

adapter_valid(s) if {
	s.predicate.adapter.contractVersion == "0.1"
	s.predicate.adapter.runtimeDigest == s.predicate.runtime.artifact.digest
	canonical_digest(s.predicate.adapter.runtimeDigest)
}

canonical_digest(digest) if regex.match("^sha256:[0-9a-f]{64}$", digest)

object_shape(value, required, allowed) if {
	is_object(value)
	keys := object.keys(value)
	every key in required {
		key in keys
	}
	every key in keys {
		key in allowed
	}
}

bounded_text(value, limit) if {
	is_string(value)
	count(value) >= 1
	count(value) <= limit
	not regex.match("\\p{Cc}", value)
}

uri_percent_encoding_valid(value) if {
	decoded := urlquery.decode(value)
	is_string(decoded)
}

authority_uri(value) if {
	regex.match(
		"^(https|oci)://[a-z0-9]([a-z0-9._~-]*[a-z0-9])?(:[0-9]{1,5})?([/?#][^[:space:]]*)?$",
		lower(value),
	)
}

absolute_uri(value) if {
	is_string(value)
	count(value) <= 2048
	regex.match("^[A-Za-z][A-Za-z0-9+.-]*:[^[:space:]]+$", value)
	not regex.match("\\p{Cc}", value)
	uri_percent_encoding_valid(value)
	normalized := lower(value)
	not startswith(normalized, "https:")
	not startswith(normalized, "oci:")
}

absolute_uri(value) if {
	is_string(value)
	count(value) <= 2048
	regex.match("^[A-Za-z][A-Za-z0-9+.-]*:[^[:space:]]+$", value)
	not regex.match("\\p{Cc}", value)
	uri_percent_encoding_valid(value)
	authority_uri(value)
}

artifact_uri(value) if {
	is_string(value)
	count(value) <= 2048
	regex.match("^(https|oci)://", value)
	not regex.match("\\p{Cc}", value)
	uri_percent_encoding_valid(value)
	authority_uri(value)
}

artifact_uri(value) if {
	is_string(value)
	count(value) <= 2048
	regex.match("^urn:[^[:space:]]+$", value)
	not regex.match("\\p{Cc}", value)
	uri_percent_encoding_valid(value)
}

id_value(value) if {
	is_string(value)
	regex.match("^[a-z0-9][a-z0-9._:/-]{0,127}$", value)
}

redacted_id(value) if {
	is_string(value)
	regex.match("^redacted:[A-Za-z0-9._~-]{1,112}$", value)
}

artifact_reference_shape_valid(ref) if {
	object_shape(ref, {"uri", "digest"}, {"uri", "digest"})
	artifact_uri(ref.uri)
	canonical_digest(ref.digest)
}

redacted_reference_shape_valid(ref) if {
	object_shape(ref, {"id", "digest"}, {"id", "digest"})
	redacted_id(ref.id)
	canonical_digest(ref.digest)
}

optional_bounded_text_member(obj, key, _) if not key in object.keys(obj)

optional_bounded_text_member(obj, key, limit) if bounded_text(obj[key], limit)

optional_redacted_reference_member(obj, key) if not key in object.keys(obj)

optional_redacted_reference_member(obj, key) if redacted_reference_shape_valid(obj[key])

optional_timestamp_member(obj, key) if not key in object.keys(obj)

optional_timestamp_member(obj, key) if timestamp_seconds_ns(obj[key])

decision_shape_valid(decision) if {
	object_shape(
		decision,
		{"state", "verdict"},
		{"state", "verdict", "reference", "observedAt"},
	)
	decision.state in {"observed", "not-observed"}
	decision.verdict in {"allow", "deny", "unknown"}
	optional_redacted_reference_member(decision, "reference")
	optional_timestamp_member(decision, "observedAt")
}

outcome_shape_valid(outcome) if {
	object_shape(
		outcome,
		{"state", "result"},
		{"state", "result", "reference", "observedAt"},
	)
	outcome.state in {"verified", "unknown"}
	outcome.result in {"occurred", "blocked", "unknown"}
	optional_redacted_reference_member(outcome, "reference")
	optional_timestamp_member(outcome, "observedAt")
}

case_shape_valid(c) if {
	object_shape(
		c,
		{"id", "kind", "correlationId", "startedAt", "completedAt", "decision", "outcome", "testResult"},
		{"id", "kind", "correlationId", "startedAt", "completedAt", "decision", "outcome", "testResult"},
	)
	id_value(c.id)
	c.kind in {"allowed-action", "denied-action", "adapter-bypass", "no-policy-loaded"}
	canonical_digest(c.correlationId)
	timestamp_seconds_ns(c.startedAt)
	timestamp_seconds_ns(c.completedAt)
	decision_shape_valid(c.decision)
	outcome_shape_valid(c.outcome)
	object_shape(
		c.testResult,
		{"predicateType", "testId", "statementDigest"},
		{"predicateType", "testId", "statementDigest"},
	)
	c.testResult.predicateType == test_result_type
	id_value(c.testResult.testId)
	canonical_digest(c.testResult.statementDigest)
}

nested_core_shape_valid(s) if {
	p := s.predicate

	object_shape(p.agent, {"name", "uri", "artifactDigest"}, {"name", "uri", "artifactDigest"})
	bounded_text(p.agent.name, 256)
	absolute_uri(p.agent.uri)
	canonical_digest(p.agent.artifactDigest)

	object_shape(p.runtime, {"name", "version", "artifact"}, {"name", "version", "framework", "artifact"})
	bounded_text(p.runtime.name, 128)
	bounded_text(p.runtime.version, 128)
	optional_bounded_text_member(p.runtime, "framework", 128)
	artifact_reference_shape_valid(p.runtime.artifact)

	object_shape(
		p.adapter,
		{"name", "artifact", "contractVersion", "runtimeDigest"},
		{"name", "artifact", "contractVersion", "runtimeDigest"},
	)
	bounded_text(p.adapter.name, 128)
	artifact_reference_shape_valid(p.adapter.artifact)
	is_string(p.adapter.contractVersion)
	canonical_digest(p.adapter.runtimeDigest)

	object_shape(
		p.runtimePolicy,
		{"engine", "artifact", "count", "loaded"},
		{"engine", "artifact", "count", "loaded"},
	)
	id_value(p.runtimePolicy.engine)
	artifact_reference_shape_valid(p.runtimePolicy.artifact)
	is_number(p.runtimePolicy.count)
	is_boolean(p.runtimePolicy.loaded)

	object_shape(
		p.enforcement,
		{"mode", "defaultBehavior", "requiredInterventionPoints", "observedInterventionPoints"},
		{"mode", "defaultBehavior", "requiredInterventionPoints", "observedInterventionPoints"},
	)
	p.enforcement.mode in {"enforce", "monitor"}
	p.enforcement.defaultBehavior in {"allow", "deny"}
	is_array(p.enforcement.requiredInterventionPoints)
	is_array(p.enforcement.observedInterventionPoints)
	count(p.enforcement.requiredInterventionPoints) >= 1
	count(p.enforcement.requiredInterventionPoints) <= 32
	count(p.enforcement.observedInterventionPoints) <= 32
	count({point | some point in p.enforcement.requiredInterventionPoints}) == count(p.enforcement.requiredInterventionPoints)
	count({point | some point in p.enforcement.observedInterventionPoints}) == count(p.enforcement.observedInterventionPoints)
	every point in p.enforcement.requiredInterventionPoints {
		id_value(point)
	}
	every point in p.enforcement.observedInterventionPoints {
		id_value(point)
	}

	object_shape(p.identity, {"providerUri", "subjectKind", "subject"}, {"providerUri", "subjectKind", "subject"})
	absolute_uri(p.identity.providerUri)
	p.identity.subjectKind in {"agent", "workload"}
	redacted_reference_shape_valid(p.identity.subject)

	object_shape(p.audit, {"sinkKind", "sink", "configurationDigest"}, {"sinkKind", "sink", "configurationDigest"})
	id_value(p.audit.sinkKind)
	redacted_reference_shape_valid(p.audit.sink)
	canonical_digest(p.audit.configurationDigest)

	object_shape(p.conformance, {"fixture", "controlledTool", "cases"}, {"fixture", "controlledTool", "cases"})
	object_shape(p.conformance.fixture, {"id", "producer"}, {"id", "producer"})
	id_value(p.conformance.fixture.id)
	p.conformance.fixture.producer in {"agt", "non-agt"}
	object_shape(
		p.conformance.controlledTool,
		{"name", "actionClass", "artifact"},
		{"name", "actionClass", "artifact"},
	)
	is_string(p.conformance.controlledTool.name)
	is_string(p.conformance.controlledTool.actionClass)
	artifact_reference_shape_valid(p.conformance.controlledTool.artifact)
	is_array(p.conformance.cases)
	every c in p.conformance.cases {
		case_shape_valid(c)
	}
}

# configured-and-exercised enforcement: policy actually loaded, enforcing
# mode, and every REQUIRED intervention point OBSERVED (never inferred).
#
# `every` over an empty collection is vacuously true, so the required set must
# be non-empty for the check below to assert anything. the embedded schema's
# minItems bound constrains the generator; this gate evaluates already-signed
# statements it did not produce, so it re-establishes the floor itself.
deployment_enforcing(s) if {
	runtime_policy_consistent(s)
	s.predicate.runtimePolicy.loaded == true
	s.predicate.runtimePolicy.count >= 1
	s.predicate.enforcement.mode == "enforce"
	default_behavior_valid(s)
	count(s.predicate.enforcement.requiredInterventionPoints) >= 1
	every p in s.predicate.enforcement.requiredInterventionPoints {
		p in s.predicate.enforcement.observedInterventionPoints
	}
}

runtime_policy_consistent(s) if {
	count := s.predicate.runtimePolicy.count
	is_number(count)
	count == floor(count)
	count >= 1
	count <= 64
	s.predicate.runtimePolicy.loaded == true
}

runtime_policy_consistent(s) if {
	s.predicate.runtimePolicy.count == 0
	s.predicate.runtimePolicy.loaded == false
}

default_behavior_valid(s) if s.predicate.enforcement.defaultBehavior in {"allow", "deny"}

case_admissible(s, c) if {
	c.kind == "allowed-action"
	deployment_enforcing(s)
	case_timestamps_valid(c)
	c.decision.state == "observed"
	c.decision.verdict == "allow"
	c.outcome.state == "verified"
	c.outcome.result == "occurred"
	linkage_valid(s, c)
}

case_admissible(s, c) if {
	c.kind == "denied-action"
	deployment_enforcing(s)
	case_timestamps_valid(c)
	c.decision.state == "observed"
	c.decision.verdict == "deny"
	c.outcome.state == "verified"
	c.outcome.result == "blocked"
	linkage_valid(s, c)
}

# adapter-bypass and no-policy-loaded case kinds are never admissible.

# --- signed test-result linkage ----------------------------------------------

# statements claiming a case id via the conformance descriptor annotation
case_test_results(c) := [t |
	some i
	t := test_result_statements[i]
	tr_descriptor(t.stmt).annotations[ann_key("caseId")] == c.id
]

tr_descriptor(stmt) := d if {
	count(stmt.predicate.configuration) == 1
	d := stmt.predicate.configuration[0]
}

# exactly one matching verified statement per case, cross-bound on payload
# digest, subject, descriptor, annotations, and bounded result profile
linkage_valid(s, c) if {
	trs := case_test_results(c)
	count(trs) == 1
	some t in trs
	tr_statement_valid(s, c, t)
}

tr_statement_valid(s, c, t) if {
	# exact DSSE payload byte digest binds the referenced signed statement
	sprintf("sha256:%s", [t.digest]) == c.testResult.statementDigest
	c.testResult.predicateType == test_result_type
	c.testResult.testId == c.id

	# identical single subject on both signed statements
	t.stmt._type == statement_type
	count(t.stmt.subject) == 1
	some tsub in t.stmt.subject
	some dsub in s.subject
	tsub.name == dsub.name
	tsub.digest.sha256 == dsub.digest.sha256

	# exactly one conformance descriptor bound to the controlled tool artifact
	d := tr_descriptor(t.stmt)
	d.name == conformance_descriptor_name
	d.uri == conformance_descriptor_uri
	sprintf("sha256:%s", [d.digest.sha256]) == s.predicate.conformance.controlledTool.artifact.digest

	tr_annotations_valid(s, c, d)
	tr_result_profile_valid(c, t.stmt.predicate)
	tr_url_valid(t.stmt.predicate)
}

# the descriptor carries exactly the namespaced annotation keys for the case
# state — no more, no less — and each value equals the deployment case fact
tr_annotations_valid(s, c, d) if {
	expected := expected_annotation_keys(c)
	{k | some k, _ in d.annotations} == expected

	d.annotations[ann_key("agentDigest")] == s.predicate.agent.artifactDigest
	# caseId equality already defines case_test_results pairing above; the exact
	# key set here still requires the annotation to be present.
	d.annotations[ann_key("correlationId")] == c.correlationId
	d.annotations[ann_key("decisionState")] == c.decision.state
	d.annotations[ann_key("decisionVerdict")] == c.decision.verdict
	d.annotations[ann_key("outcomeState")] == c.outcome.state
	d.annotations[ann_key("outcomeResult")] == c.outcome.result
	decision_digest_annotation_valid(c, d)
	result_artifact_annotation_valid(c, d)
}

expected_annotation_keys(c) := ((base | dec) | res) if {
	base := {
		ann_key("agentDigest"), ann_key("caseId"), ann_key("correlationId"),
		ann_key("decisionState"), ann_key("decisionVerdict"),
		ann_key("outcomeState"), ann_key("outcomeResult"),
	}
	dec := {k | c.decision.state == "observed"; k := ann_key("decisionDigest")}
	res := {k | c.outcome.state == "verified"; k := ann_key("resultArtifactDigest")}
}

decision_digest_annotation_valid(c, d) if {
	c.decision.state == "observed"
	d.annotations[ann_key("decisionDigest")] == c.decision.reference.digest
}

decision_digest_annotation_valid(c, _) if c.decision.state == "not-observed"

result_artifact_annotation_valid(c, d) if {
	c.outcome.state == "verified"
	d.annotations[ann_key("resultArtifactDigest")] == c.outcome.reference.digest
}

result_artifact_annotation_valid(c, _) if c.outcome.state == "unknown"

# the aggregate test-result records only that the bounded observation harness
# completed — it is NEVER a compliance verdict. a verified outcome pairs with
# PASSED/[case], an unknown outcome with WARNED/[case]
tr_result_profile_valid(c, p) if {
	c.outcome.state == "verified"
	p.result == "PASSED"
	p.passedTests == [c.id]
	p.warnedTests == []
	p.failedTests == []
}

tr_result_profile_valid(c, p) if {
	c.outcome.state == "unknown"
	p.result == "WARNED"
	p.warnedTests == [c.id]
	p.passedTests == []
	p.failedTests == []
}

tr_url_valid(p) if not "url" in object.keys(p)

tr_url_valid(p) if {
	url := p.url
	artifact_uri(url)
}

timestamp_seconds_ns(timestamp) := time.parse_rfc3339_ns(timestamp) if {
	regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", timestamp)
}

case_timestamps_valid(c) if {
	started := timestamp_seconds_ns(c.startedAt)
	completed := timestamp_seconds_ns(c.completedAt)
	decision_observed := timestamp_seconds_ns(c.decision.observedAt)
	outcome_observed := timestamp_seconds_ns(c.outcome.observedAt)
	completed >= started
	completed - started <= 300000000000
	decision_observed >= started
	decision_observed <= completed
	outcome_observed >= started
	outcome_observed <= completed
}

# --- violations (attribution and reporting) ----------------------------------

violations["agent_governance"] := agent_governance_violations

safe_agent_name(s) := name if {
	name := object.get(s, ["predicate", "agent", "name"], "")
	bounded_text(name, 256)
} else := "unknown-agent"

safe_agent_digest(s) := digest if {
	digest := object.get(s, ["predicate", "agent", "artifactDigest"], "")
	canonical_digest(digest)
} else := "unknown-digest"

safe_case_id(c) := id if {
	id := object.get(c, "id", "")
	id_value(id)
} else := "unknown-case"

safe_case_kind(c) := kind if {
	kind := object.get(c, "kind", "")
	kind in {"allowed-action", "denied-action", "adapter-bypass", "no-policy-loaded"}
} else := "unknown-kind"

subject_ref(s) := sprintf("agent %s (%s)", [
	safe_agent_name(s),
	safe_agent_digest(s),
])

case_ref(s, c) := sprintf("%s case %s (%s)", [
	subject_ref(s),
	safe_case_id(c),
	safe_case_kind(c),
])

agent_governance_violations contains msg if {
	count(deployment_statements) != 1
	msg := sprintf("expected exactly one verified agent-governance deployment statement, found %d", [count(deployment_statements)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not s._type == statement_type
	msg := sprintf("%s: deployment statement _type must be %q", [subject_ref(s), statement_type])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not s.predicate.schemaVersion == "0.1"
	msg := sprintf("%s: predicate schemaVersion must be 0.1", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not required_root_keys_present(s)
	msg := sprintf("%s: predicate is missing required core fields", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not nested_core_shape_valid(s)
	msg := sprintf("%s: predicate nested core shape is incomplete, malformed, or carries unexpected claims", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not valid_case_cardinality(s)
	msg := sprintf("%s: conformance cases must contain 1-4 entries", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not controlled_tool_valid(s)
	msg := sprintf("%s: controlled tool must bind the fixed write-marker fixture and canonical digest", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not adapter_valid(s)
	msg := sprintf("%s: adapter contract version or runtime digest linkage is invalid", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not default_behavior_valid(s)
	msg := sprintf("%s: enforcement default behavior must be allow or deny", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	not runtime_policy_consistent(s)
	msg := sprintf("%s: runtime policy loaded/count facts are contradictory or out of bounds", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	count(s.subject) != 1
	msg := sprintf("%s: deployment statement must have exactly one subject", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some sub in s.subject
	sub.name != s.predicate.agent.name
	msg := sprintf("%s: signed subject name does not match the predicate agent name", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some sub in s.subject
	sprintf("sha256:%s", [sub.digest.sha256]) != s.predicate.agent.artifactDigest
	msg := sprintf("%s: signed subject digest does not match the predicate agent digest", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some k, _ in s.predicate
	not k in allowed_root_keys
	msg := sprintf("%s: unexpected predicate field (aggregate or unknown claims are rejected)", [subject_ref(s)])
}

# defense in depth: the generator refuses duplicate case ids/kinds, but a
# trusted signer could still sign a hand-built predicate — reject it here too
agent_governance_violations contains msg if {
	some s in deployment_statements
	cases := s.predicate.conformance.cases
	count({c.id | some c in cases}) != count(cases)
	msg := sprintf("%s: duplicate conformance case ids are rejected", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	cases := s.predicate.conformance.cases
	count({c.kind | some c in cases}) != count(cases)
	msg := sprintf("%s: duplicate conformance case kinds are rejected", [subject_ref(s)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "adapter-bypass"
	msg := sprintf("%s: consequential write-marker action without a correlated policy decision or exercised required intervention point — deployment not admissible", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "no-policy-loaded"
	msg := sprintf("%s: middleware present with no runtime policy loaded — deployment not admissible", [case_ref(s, c)])
}

positive_kind(kind) if kind in {"allowed-action", "denied-action"}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	positive_kind(c.kind)
	not case_timestamps_valid(c)
	msg := sprintf("%s: case timestamps must be UTC seconds, ordered, within five minutes, and include in-interval observations", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	positive_kind(c.kind)
	not deployment_enforcing(s)
	msg := sprintf("%s: runtime policy/enforcement facts do not prove a loaded, enforcing, exercised control", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	positive_kind(c.kind)
	c.decision.state != "observed"
	msg := sprintf("%s: no observed policy decision", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "allowed-action"
	c.decision.state == "observed"
	c.decision.verdict != "allow"
	msg := sprintf("%s: observed decision verdict does not prove the allowed control", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "denied-action"
	c.decision.state == "observed"
	c.decision.verdict != "deny"
	msg := sprintf("%s: observed decision verdict does not prove the denied control", [case_ref(s, c)])
}

# an unverified/unknown outcome can never satisfy an outcome requirement
agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	positive_kind(c.kind)
	c.outcome.state != "verified"
	msg := sprintf("%s: required outcome is not verified — unknown is never promoted", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "allowed-action"
	c.outcome.state == "verified"
	c.outcome.result != "occurred"
	msg := sprintf("%s: verified outcome does not prove the allowed action occurred", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "denied-action"
	c.outcome.state == "verified"
	c.outcome.result != "blocked"
	msg := sprintf("%s: verified outcome does not prove the denied action was blocked", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	count(case_test_results(c)) == 0
	msg := sprintf("%s: no verified test-result statement is paired with this case", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	count(case_test_results(c)) > 1
	msg := sprintf("%s: multiple test-result statements claim this case — ambiguous pairing is rejected", [case_ref(s, c)])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	trs := case_test_results(c)
	count(trs) == 1
	some t in trs
	not tr_statement_valid(s, c, t)
	msg := sprintf("%s: paired test-result statement fails cross-binding (payload digest, subject, descriptor, annotations, or result profile)", [case_ref(s, c)])
}
