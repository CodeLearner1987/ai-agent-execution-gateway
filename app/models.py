"""
models.py

Pydantic schemas shared across the API layer, policy engine, executor,
and database layer. Keeping these in one place ensures the shape of a
"request" is consistent everywhere it's passed around.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class ActionType(str, Enum):
    """Known action types. Anything outside this enum is still accepted
    (action_type is a free-form string at the API boundary) but these
    are the values the policy engine treats as first-class."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    TRANSFER = "transfer"
    SEND = "send"
    UPDATE = "update"
    EXECUTE = "execute"
    OTHER = "other"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


# ---------------------------------------------------------------------------
# /request
# ---------------------------------------------------------------------------

class AgentRequest(BaseModel):
    """Inbound payload from an AI agent asking permission to act."""

    agent_id: str = Field(..., min_length=1, max_length=128)
    prompt: str = Field(..., min_length=1, max_length=8000)
    tool_name: str = Field(..., min_length=1, max_length=128)
    action_type: str = Field(..., min_length=1, max_length=64)
    metadata: Optional[dict[str, Any]] = None

    @field_validator("agent_id", "tool_name", "action_type")
    @classmethod
    def _strip_and_require_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("field cannot be blank")
        return v


class PolicyDecision(BaseModel):
    """Result of running an AgentRequest through the policy engine."""

    decision: Decision
    risk_score: int = Field(..., ge=0, le=100)
    reason: str
    flags: list[str] = Field(default_factory=list)
    is_security_event: bool = False


class RequestResponse(BaseModel):
    """What POST /request returns to the caller."""

    request_id: str
    decision: Decision
    risk_score: int
    reason: str


# ---------------------------------------------------------------------------
# /logs
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    id: int
    request_id: str
    timestamp: datetime
    agent_id: str
    prompt: str
    tool_name: str
    action_type: str
    decision: Decision
    risk_score: int
    reason: str
    is_security_event: bool = False

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# /simulate-execution
# ---------------------------------------------------------------------------

class ExecutionRequest(BaseModel):
    """A client supplies the request_id of a previously evaluated request.
    The executor looks up that decision and only runs if it was ALLOW."""

    request_id: str


class ExecutionResult(BaseModel):
    request_id: str
    executed: bool
    output: Optional[dict[str, Any]] = None
    message: str


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
