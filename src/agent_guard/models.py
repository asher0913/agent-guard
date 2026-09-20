from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Action(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class ToolCall:
    tool: str
    arguments: dict[str, Any]
    actor: str = "agent"
    granted_scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    action: Action
    risk_score: int
    reasons: tuple[str, ...]
    matched_rules: tuple[str, ...]
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrajectoryDecision:
    action: Action
    steps_evaluated: int
    blocked_step: int | None
    decisions: tuple[Decision, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

