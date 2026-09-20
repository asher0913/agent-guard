from __future__ import annotations

import json
import re
from collections.abc import Iterable

from .models import Action, Decision, ToolCall, TrajectoryDecision

DESTRUCTIVE_PATTERNS = (
    re.compile(r"\brm\s+-[^\n]*r[^\n]*f\b", re.IGNORECASE),
    re.compile(r"\b(mkfs|dd\s+if=|shutdown|reboot)\b", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b", re.IGNORECASE),
)
INJECTION_PATTERNS = (
    re.compile(r"ignore (all|any|the) previous instructions", re.IGNORECASE),
    re.compile(r"reveal (the )?(system prompt|credentials|secrets)", re.IGNORECASE),
)
DANGEROUS_TARGETS = {"/", "~", "$HOME", "/home", "/users", "c:\\"}
EXTERNAL_TOOLS = {"send_email", "http_post", "upload_file", "publish_message"}
MUTATING_TOOLS = {
    "delete_file",
    "execute_shell",
    "send_email",
    "transfer_funds",
    "change_permissions",
    "publish_message",
}
SENSITIVE_KEYS = {"password", "secret", "token", "api_key", "private_key", "ssn"}


def _flatten(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} {_flatten(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(item) for item in value)
    return str(value)


class PolicyEngine:
    """Deterministic, explainable policy checks before an agent tool call executes."""

    def evaluate(self, call: ToolCall) -> Decision:
        reasons: list[str] = []
        rules: list[str] = []
        risk = 0
        serialized = json.dumps(call.arguments, sort_keys=True, default=str)
        flattened = _flatten(call.arguments)

        if any(pattern.search(flattened) for pattern in DESTRUCTIVE_PATTERNS):
            risk += 100
            reasons.append("destructive shell pattern detected")
            rules.append("shell.destructive")

        if any(pattern.search(flattened) for pattern in INJECTION_PATTERNS):
            risk += 80
            reasons.append("prompt-injection pattern detected in tool arguments")
            rules.append("content.prompt_injection")

        target = str(call.arguments.get("path", call.arguments.get("target", ""))).strip().lower()
        if target in DANGEROUS_TARGETS or target.endswith("/*"):
            risk += 100
            reasons.append("operation targets a broad or protected filesystem path")
            rules.append("filesystem.protected_target")

        lowered_keys = {str(key).lower() for key in call.arguments}
        contains_sensitive_data = bool(lowered_keys & SENSITIVE_KEYS) or any(
            key in serialized.lower() for key in SENSITIVE_KEYS
        )
        if call.tool in EXTERNAL_TOOLS and contains_sensitive_data:
            risk += 100
            reasons.append("external tool call contains credential or personal-data fields")
            rules.append("data.exfiltration")

        required_scope = f"tool:{call.tool}"
        if call.tool in MUTATING_TOOLS and required_scope not in call.granted_scopes:
            risk += 45
            reasons.append(f"missing required scope: {required_scope}")
            rules.append("authorization.missing_scope")

        if risk >= 80:
            action = Action.DENY
        elif risk > 0 or call.tool in MUTATING_TOOLS:
            action = Action.REQUIRE_APPROVAL
            if not reasons:
                reasons.append("mutating action requires human approval")
                rules.append("action.human_approval")
        else:
            action = Action.ALLOW
            reasons.append("no policy violations detected")

        return Decision(action, min(risk, 100), tuple(reasons), tuple(rules))

    def evaluate_trajectory(self, calls: Iterable[ToolCall]) -> TrajectoryDecision:
        decisions: list[Decision] = []
        blocked_step: int | None = None
        overall = Action.ALLOW
        for index, call in enumerate(calls):
            decision = self.evaluate(call)
            decisions.append(decision)
            if decision.action is Action.DENY:
                overall = Action.DENY
                blocked_step = index
                break
            if decision.action is Action.REQUIRE_APPROVAL:
                overall = Action.REQUIRE_APPROVAL
        return TrajectoryDecision(overall, len(decisions), blocked_step, tuple(decisions))

