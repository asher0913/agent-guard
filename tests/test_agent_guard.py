from fastapi.testclient import TestClient

from agent_guard.api import create_app
from agent_guard.benchmark import run_benchmark
from agent_guard.engine import PolicyEngine
from agent_guard.models import Action, ToolCall


def test_allows_read_only_tool() -> None:
    decision = PolicyEngine().evaluate(ToolCall("read_file", {"path": "README.md"}))
    assert decision.action is Action.ALLOW
    assert decision.risk_score == 0


def test_denies_destructive_root_command() -> None:
    decision = PolicyEngine().evaluate(ToolCall("execute_shell", {"command": "rm -rf /"}))
    assert decision.action is Action.DENY
    assert "shell.destructive" in decision.matched_rules


def test_requires_approval_for_unscoped_mutation() -> None:
    decision = PolicyEngine().evaluate(ToolCall("send_email", {"to": "ops@example.com"}))
    assert decision.action is Action.REQUIRE_APPROVAL
    assert decision.risk_score == 45


def test_stops_trajectory_on_first_denial() -> None:
    calls = [
        ToolCall("search_docs", {"query": "incident guide"}),
        ToolCall("delete_file", {"path": "/"}),
        ToolCall("read_file", {"path": "never-reached"}),
    ]
    result = PolicyEngine().evaluate_trajectory(calls)
    assert result.action is Action.DENY
    assert result.blocked_step == 1
    assert result.steps_evaluated == 2


def test_benchmark_detects_fixture_attacks_without_false_positives() -> None:
    result = run_benchmark()
    assert result.recall == 1.0
    assert result.false_positive_rate == 0.0


def test_api_returns_explainable_decision() -> None:
    response = TestClient(create_app()).post(
        "/v1/evaluate", json={"tool": "http_post", "arguments": {"token": "secret"}}
    )
    assert response.status_code == 200
    assert response.json()["action"] == "deny"
    assert "data.exfiltration" in response.json()["matched_rules"]

