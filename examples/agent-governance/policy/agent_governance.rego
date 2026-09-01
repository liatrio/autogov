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

ann_key(suffix) := sprintf("%s#%s", [deployment_type, suffix])

# --- decoded statements -----------------------------------------------------

payloads contains p if {
	some b in input
	b.dsseEnvelope.payloadType == intoto_payload_type
	p := base64.decode(b.dsseEnvelope.payload)
}

deployment_statements contains s if {
	some p in payloads
	s := json.unmarshal(p)
	s.predicateType == deployment_type
}

# test-result statements keep their exact payload-byte sha256 so linkage can
# bind case.testResult.statementDigest to the signed DSSE payload
test_result_statements contains t if {
	some p in payloads
	s := json.unmarshal(p)
	s.predicateType == test_result_type
	t := {"stmt": s, "digest": crypto.sha256(p)}
}

# --- positive admission derivation ------------------------------------------

default allow := false

allow if {
	count(deployment_statements) == 1
	some s in deployment_statements
	deployment_envelope_valid(s)
	count(s.predicate.conformance.cases) >= 1
	count(s.predicate.conformance.cases) <= 4
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
	s.predicate.schemaVersion == "0.1"
}

# configured-and-exercised enforcement: policy actually loaded, enforcing
# mode, and every REQUIRED intervention point OBSERVED (never inferred).
#
# `every` over an empty collection is vacuously true, so the required set must
# be non-empty for the check below to assert anything. the embedded schema's
# minItems bound constrains the generator; this gate evaluates already-signed
# statements it did not produce, so it re-establishes the floor itself.
deployment_enforcing(s) if {
	s.predicate.runtimePolicy.loaded == true
	s.predicate.runtimePolicy.count >= 1
	s.predicate.enforcement.mode == "enforce"
	count(s.predicate.enforcement.requiredInterventionPoints) >= 1
	every p in s.predicate.enforcement.requiredInterventionPoints {
		p in s.predicate.enforcement.observedInterventionPoints
	}
}

case_admissible(s, c) if {
	c.kind == "allowed-action"
	deployment_enforcing(s)
	c.decision.state == "observed"
	c.decision.verdict == "allow"
	c.outcome.state == "verified"
	c.outcome.result == "occurred"
	linkage_valid(s, c)
}

case_admissible(s, c) if {
	c.kind == "denied-action"
	deployment_enforcing(s)
	c.decision.state == "observed"
	c.decision.verdict == "deny"
	c.outcome.state == "verified"
	c.outcome.result == "blocked"
	linkage_valid(s, c)
}

# adapter-bypass and no-policy-loaded case kinds are never admissible.

# --- signed test-result linkage ----------------------------------------------

# statements claiming a case id via the conformance descriptor annotation
case_test_results(c) := {t |
	some t in test_result_statements
	tr_descriptor(t.stmt).annotations[ann_key("caseId")] == c.id
}

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
	d.annotations[ann_key("caseId")] == c.id
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

tr_url_valid(p) if not p.url

tr_url_valid(p) if {
	some prefix in ["https:", "oci:", "urn:"]
	startswith(p.url, prefix)
}

# --- violations (attribution and reporting) ----------------------------------

violations["agent_governance"] := agent_governance_violations

subject_ref(s) := sprintf("agent %s (%s)", [
	object.get(s, ["predicate", "agent", "name"], "unknown-agent"),
	object.get(s, ["predicate", "agent", "artifactDigest"], "unknown-digest"),
])

case_ref(s, c) := sprintf("%s case %s (%s)", [
	subject_ref(s),
	object.get(c, "id", "unknown-case"),
	object.get(c, "kind", "unknown-kind"),
])

agent_governance_violations contains msg if {
	count(deployment_statements) != 1
	msg := sprintf("expected exactly one verified agent-governance deployment statement, found %d", [count(deployment_statements)])
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
	msg := sprintf("%s: signed subject name %q does not match the predicate agent name", [subject_ref(s), sub.name])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some sub in s.subject
	sprintf("sha256:%s", [sub.digest.sha256]) != s.predicate.agent.artifactDigest
	msg := sprintf("%s: signed subject digest sha256:%s does not match the predicate agent digest", [subject_ref(s), sub.digest.sha256])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some k, _ in s.predicate
	not k in allowed_root_keys
	msg := sprintf("%s: unexpected predicate field %q (aggregate or unknown claims are rejected)", [subject_ref(s), k])
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
	msg := sprintf("%s: observed decision verdict %q does not prove the allowed control", [case_ref(s, c), c.decision.verdict])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "denied-action"
	c.decision.state == "observed"
	c.decision.verdict != "deny"
	msg := sprintf("%s: observed decision verdict %q does not prove the denied control", [case_ref(s, c), c.decision.verdict])
}

# an unverified/unknown outcome can never satisfy an outcome requirement
agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	positive_kind(c.kind)
	c.outcome.state != "verified"
	msg := sprintf("%s: required outcome is not verified (state %q) — unknown is never promoted", [case_ref(s, c), object.get(c, ["outcome", "state"], "missing")])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "allowed-action"
	c.outcome.state == "verified"
	c.outcome.result != "occurred"
	msg := sprintf("%s: verified outcome %q does not prove the allowed action occurred", [case_ref(s, c), c.outcome.result])
}

agent_governance_violations contains msg if {
	some s in deployment_statements
	some c in s.predicate.conformance.cases
	c.kind == "denied-action"
	c.outcome.state == "verified"
	c.outcome.result != "blocked"
	msg := sprintf("%s: verified outcome %q does not prove the denied action was blocked", [case_ref(s, c), c.outcome.result])
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
