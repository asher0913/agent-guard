from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .engine import PolicyEngine
from .models import ToolCall


class ToolCallBody(BaseModel):
    tool: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    actor: str = "agent"
    granted_scopes: list[str] = Field(default_factory=list)

    def domain(self) -> ToolCall:
        return ToolCall(self.tool, self.arguments, self.actor, tuple(self.granted_scopes))


class TrajectoryBody(BaseModel):
    calls: list[ToolCallBody] = Field(min_length=1, max_length=100)


def create_app(engine: PolicyEngine | None = None) -> FastAPI:
    engine = engine or PolicyEngine()
    app = FastAPI(title="AgentGuard", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/evaluate")
    def evaluate(body: ToolCallBody) -> dict[str, object]:
        return engine.evaluate(body.domain()).to_dict()

    @app.post("/v1/trajectory")
    def trajectory(body: TrajectoryBody) -> dict[str, object]:
        return engine.evaluate_trajectory(call.domain() for call in body.calls).to_dict()

    return app


app = create_app()

