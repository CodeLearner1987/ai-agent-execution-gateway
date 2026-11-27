"""
database.py

Storage layer for the gateway.

Default backend: SQLite (file-based, zero-config, ships working out of
the box). Optional backend: Supabase (Postgres) — enabled automatically
when SUPABASE_URL and SUPABASE_KEY are present in the environment.

Both backends implement the same small interface (insert_log,
fetch_logs) so the API layer never needs to know which one is active.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from app.models import Decision, LogEntry, PolicyDecision, utcnow

DB_PATH = Path(os.getenv("GATEWAY_DB_PATH", "data/gateway.db"))

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_TABLE = os.getenv("SUPABASE_TABLE", "gateway_logs")

USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    prompt TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    action_type TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    is_security_event INTEGER NOT NULL DEFAULT 0
);
"""


class SQLiteBackend:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(CREATE_TABLE_SQL)
            conn.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def insert_log(
        self,
        *,
        request_id: str,
        agent_id: str,
        prompt: str,
        tool_name: str,
        action_type: str,
        decision: Decision,
        risk_score: int,
        reason: str,
        is_security_event: bool,
    ) -> LogEntry:
        timestamp = utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO logs (
                    request_id, timestamp, agent_id, prompt, tool_name,
                    action_type, decision, risk_score, reason, is_security_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    timestamp,
                    agent_id,
                    prompt,
                    tool_name,
                    action_type,
                    decision.value,
                    risk_score,
                    reason,
                    int(is_security_event),
                ),
            )
            conn.commit()
            row_id = cur.lastrowid

        return LogEntry(
            id=row_id,
            request_id=request_id,
            timestamp=timestamp,
            agent_id=agent_id,
            prompt=prompt,
            tool_name=tool_name,
            action_type=action_type,
            decision=decision,
            risk_score=risk_score,
            reason=reason,
            is_security_event=is_security_event,
        )

    def fetch_logs(
        self,
        *,
        limit: int = 200,
        agent_id: Optional[str] = None,
        security_events_only: bool = False,
    ) -> list[LogEntry]:
        query = "SELECT * FROM logs"
        clauses = []
        params: list[Any] = []

        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if security_events_only:
            clauses.append("is_security_event = 1")

        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            LogEntry(
                id=row["id"],
                request_id=row["request_id"],
                timestamp=row["timestamp"],
                agent_id=row["agent_id"],
                prompt=row["prompt"],
                tool_name=row["tool_name"],
                action_type=row["action_type"],
                decision=Decision(row["decision"]),
                risk_score=row["risk_score"],
                reason=row["reason"],
                is_security_event=bool(row["is_security_event"]),
            )
            for row in rows
        ]

    def get_by_request_id(self, request_id: str) -> Optional[LogEntry]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM logs WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            return None
        return LogEntry(
            id=row["id"],
            request_id=row["request_id"],
            timestamp=row["timestamp"],
            agent_id=row["agent_id"],
            prompt=row["prompt"],
            tool_name=row["tool_name"],
            action_type=row["action_type"],
            decision=Decision(row["decision"]),
            risk_score=row["risk_score"],
            reason=row["reason"],
            is_security_event=bool(row["is_security_event"]),
        )


# ---------------------------------------------------------------------------
# Supabase backend
# ---------------------------------------------------------------------------

class SupabaseBackend:
    """Thin wrapper around the supabase-py client. Activated only when
    SUPABASE_URL / SUPABASE_KEY are configured.

    Expected table schema (create via Supabase SQL editor):

        create table gateway_logs (
            id bigint generated always as identity primary key,
            request_id text not null unique,
            timestamp timestamptz not null,
            agent_id text not null,
            prompt text not null,
            tool_name text not null,
            action_type text not null,
            decision text not null,
            risk_score int not null,
            reason text not null,
            is_security_event boolean not null default false
        );
    """

    def __init__(self, url: str, key: str, table: str) -> None:
        from supabase import create_client  # imported lazily; optional dep

        self.client = create_client(url, key)
        self.table = table

    def insert_log(
        self,
        *,
        request_id: str,
        agent_id: str,
        prompt: str,
        tool_name: str,
        action_type: str,
        decision: Decision,
        risk_score: int,
        reason: str,
        is_security_event: bool,
    ) -> LogEntry:
        timestamp = utcnow().isoformat()
        payload = {
            "request_id": request_id,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "prompt": prompt,
            "tool_name": tool_name,
            "action_type": action_type,
            "decision": decision.value,
            "risk_score": risk_score,
            "reason": reason,
            "is_security_event": is_security_event,
        }
        result = self.client.table(self.table).insert(payload).execute()
        row = result.data[0]
        return LogEntry(
            id=row.get("id", 0),
            request_id=row["request_id"],
            timestamp=row["timestamp"],
            agent_id=row["agent_id"],
            prompt=row["prompt"],
            tool_name=row["tool_name"],
            action_type=row["action_type"],
            decision=Decision(row["decision"]),
            risk_score=row["risk_score"],
            reason=row["reason"],
            is_security_event=bool(row["is_security_event"]),
        )

    def fetch_logs(
        self,
        *,
        limit: int = 200,
        agent_id: Optional[str] = None,
        security_events_only: bool = False,
    ) -> list[LogEntry]:
        query = self.client.table(self.table).select("*").order("id", desc=True).limit(limit)
        if agent_id:
            query = query.eq("agent_id", agent_id)
        if security_events_only:
            query = query.eq("is_security_event", True)
        result = query.execute()
        return [
            LogEntry(
                id=row.get("id", 0),
                request_id=row["request_id"],
                timestamp=row["timestamp"],
                agent_id=row["agent_id"],
                prompt=row["prompt"],
                tool_name=row["tool_name"],
                action_type=row["action_type"],
                decision=Decision(row["decision"]),
                risk_score=row["risk_score"],
                reason=row["reason"],
                is_security_event=bool(row["is_security_event"]),
            )
            for row in result.data
        ]

    def get_by_request_id(self, request_id: str) -> Optional[LogEntry]:
        result = (
            self.client.table(self.table)
            .select("*")
            .eq("request_id", request_id)
            .limit(1)
            .execute()
        )
        if not result.data:
            return None
        row = result.data[0]
        return LogEntry(
            id=row.get("id", 0),
            request_id=row["request_id"],
            timestamp=row["timestamp"],
            agent_id=row["agent_id"],
            prompt=row["prompt"],
            tool_name=row["tool_name"],
            action_type=row["action_type"],
            decision=Decision(row["decision"]),
            risk_score=row["risk_score"],
            reason=row["reason"],
            is_security_event=bool(row["is_security_event"]),
        )


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def _build_backend():
    if USE_SUPABASE:
        return SupabaseBackend(SUPABASE_URL, SUPABASE_KEY, SUPABASE_TABLE)
    return SQLiteBackend(DB_PATH)


backend = _build_backend()


def new_request_id() -> str:
    return str(uuid.uuid4())


def log_decision(
    *,
    agent_id: str,
    prompt: str,
    tool_name: str,
    action_type: str,
    decision: PolicyDecision,
) -> LogEntry:
    request_id = new_request_id()
    return backend.insert_log(
        request_id=request_id,
        agent_id=agent_id,
        prompt=prompt,
        tool_name=tool_name,
        action_type=action_type,
        decision=decision.decision,
        risk_score=decision.risk_score,
        reason=decision.reason,
        is_security_event=decision.is_security_event,
    )


def get_logs(
    limit: int = 200,
    agent_id: Optional[str] = None,
    security_events_only: bool = False,
) -> list[LogEntry]:
    return backend.fetch_logs(
        limit=limit, agent_id=agent_id, security_events_only=security_events_only
    )


def get_log_by_request_id(request_id: str) -> Optional[LogEntry]:
    return backend.get_by_request_id(request_id)
