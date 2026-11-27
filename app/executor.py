"""
executor.py

Simulated tool execution layer. This module is deliberately the ONLY
place in the codebase that "executes" anything — and it refuses to run
unless it is handed a log entry whose decision is ALLOW.

In a real deployment, this is where you'd plug in actual tool adapters
(HTTP calls to internal services, DB writes, third-party APIs, etc.).
The MVP simulates execution so the gateway's control flow can be
demonstrated and tested without real side effects.
"""

from __future__ import annotations

from app.models import Decision, ExecutionResult, LogEntry


class ExecutionBlockedError(Exception):
    """Raised if something tries to execute a non-ALLOW request. This
    should be unreachable via the API layer, but the executor enforces
    it independently as defense in depth — never trust a single layer
    to be the only thing standing between a request and execution."""


def simulate_execution(log_entry: LogEntry) -> ExecutionResult:
    if log_entry.decision != Decision.ALLOW:
        raise ExecutionBlockedError(
            f"Refusing to execute request {log_entry.request_id}: "
            f"decision was {log_entry.decision.value}, not ALLOW."
        )

    # --- simulated tool dispatch ---
    # A real implementation would branch on log_entry.tool_name and call
    # the corresponding adapter. Here we fabricate a deterministic,
    # clearly-labeled simulated result.
    output = {
        "tool_name": log_entry.tool_name,
        "action_type": log_entry.action_type,
        "agent_id": log_entry.agent_id,
        "simulated": True,
        "detail": (
            f"Simulated execution of '{log_entry.tool_name}' "
            f"({log_entry.action_type}) on behalf of agent "
            f"'{log_entry.agent_id}'. No real side effects occurred."
        ),
    }

    return ExecutionResult(
        request_id=log_entry.request_id,
        executed=True,
        output=output,
        message="Execution simulated successfully.",
    )
