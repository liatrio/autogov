#!/usr/bin/env python3
# minimal non-AGT agent runtime for the agent-governance evidence spike.
#
# this toy runtime is the contract oracle for the neutral evidence boundary:
# it loads declarative JSON policy documents, intercepts tool invocations at
# exactly one intervention point (tool.pre), and returns a pre-action decision.
# it never calls Auto Gov and is never on any production action path.
"""Toy agent runtime with a tool.pre policy middleware (fixture only)."""

import json
import pathlib

RUNTIME_NAME = "toy-runtime"
RUNTIME_VERSION = "1.0.0"
INTERVENTION_POINT = "tool.pre"

# with zero policy documents loaded the engine falls back to a global allow,
# mirroring the pinned AGT core PolicyEvaluator's default. the demonstration's
# no-policy-loaded case records this honestly (defaultBehavior=allow) and Auto
# Gov admission still fails the deployment because no policy was loaded.
GLOBAL_DEFAULT_NO_POLICY = "allow"


class ToyRuntime:
    """Evaluates JSON policy documents and dispatches governed tool calls."""

    def __init__(self, policy_docs):
        self.policy_docs = list(policy_docs)

    @classmethod
    def from_policy_file(cls, path):
        doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        return cls([doc])

    @property
    def policy_count(self):
        return len(self.policy_docs)

    @property
    def default_behavior(self):
        if not self.policy_docs:
            return GLOBAL_DEFAULT_NO_POLICY
        return self.policy_docs[0].get("default_action", "deny")

    def decide(self, context):
        """tool.pre decision: first matching rule by priority, else default."""
        rules = []
        for doc in self.policy_docs:
            rules.extend(doc.get("rules", []))
        rules.sort(key=lambda r: r.get("priority", 0), reverse=True)
        for rule in rules:
            if context.get("tool_name") != rule.get("tool_name", "write-marker"):
                continue
            field = rule.get("field")
            if field is not None and context.get(field) != rule.get("equals"):
                continue
            return {
                "verdict": rule["action"],
                "matched_rule": rule["name"],
                "via_default": False,
            }
        return {
            "verdict": self.default_behavior,
            "matched_rule": None,
            "via_default": True,
        }

    def invoke_tool(self, tool_fn, context):
        """Intercept a governed tool call at tool.pre and enforce the decision.

        Returns (decision, executed). The tool runs only on an allow verdict.
        """
        decision = self.decide(context)
        executed = False
        if decision["verdict"] == "allow":
            tool_fn()
            executed = True
        return decision, executed
