"""
main.py

FastAPI application entrypoint. Wires together:

    Agent -> /request -> PolicyEngine -> log_decision -> RequestResponse
    Agent -> /simulate-execution -> look up logged decision -> executor (only if ALLOW)
    Operator -> /logs -> read-only view of stored decisions

No route calls the executor directly from a freshly-computed decision —
execution always goes through a stored, looked-up log entry, so the
gateway's own audit trail is the single source of truth for "was this
actually allowed".
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app import database
from app.executor import ExecutionBlockedError, simulate_execution
from app.models import (
    AgentRequest,
    Decision,
    ExecutionRequest,
    ExecutionResult,
    LogEntry,
    RequestResponse,
)
from app.policy_engine import policy_engine

logger = logging.getLogger("gateway")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="AI Agent Execution Gateway",
    description=(
        "Middleware that sits between AI agents and real-world tool "
        "execution, enforcing policy, scoring risk, and logging every "
        "decision before anything is allowed to run."
    ),
    version="0.1.0",
)

# CORS left permissive for local MVP/demo use. Lock this down to known
# origins before any production deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/request", response_model=RequestResponse, tags=["gateway"])
def submit_request(payload: AgentRequest) -> RequestResponse:
    """Primary gateway endpoint. An agent submits an intended action;
    the policy engine evaluates it; the decision is logged and returned.
    No execution happens here — this endpoint only decides."""

    decision = policy_engine.evaluate(payload)

    if decision.is_security_event:
        logger.warning(
            "SECURITY_EVENT agent_id=%s tool_name=%s flags=%s",
            payload.agent_id,
            payload.tool_name,
            decision.flags,
        )

    log_entry = database.log_decision(
        agent_id=payload.agent_id,
        prompt=payload.prompt,
        tool_name=payload.tool_name,
        action_type=payload.action_type,
        decision=decision,
    )

    return RequestResponse(
        request_id=log_entry.request_id,
        decision=decision.decision,
        risk_score=decision.risk_score,
        reason=decision.reason,
    )


@app.get("/logs", response_model=list[LogEntry], tags=["gateway"])
def get_logs(
    limit: int = Query(default=200, ge=1, le=1000),
    agent_id: str | None = Query(default=None),
    security_events_only: bool = Query(default=False),
) -> list[LogEntry]:
    """Returns stored request logs, most recent first. Supports basic
    filtering by agent_id and by security-event status."""

    return database.get_logs(
        limit=limit, agent_id=agent_id, security_events_only=security_events_only
    )


@app.post("/simulate-execution", response_model=ExecutionResult, tags=["gateway"])
def simulate(payload: ExecutionRequest) -> ExecutionResult:
    """Executes (in simulation) a previously evaluated request, looked
    up by request_id. Execution only proceeds if the stored decision
    for that request_id was ALLOW."""

    log_entry = database.get_log_by_request_id(payload.request_id)
    if log_entry is None:
        raise HTTPException(status_code=404, detail="request_id not found")

    if log_entry.decision != Decision.ALLOW:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Execution refused: request_id {payload.request_id} has "
                f"decision '{log_entry.decision.value}', not ALLOW."
            ),
        )

    try:
        return simulate_execution(log_entry)
    except ExecutionBlockedError as exc:
        # Defense in depth: should be unreachable given the check above.
        raise HTTPException(status_code=403, detail=str(exc)) from exc
