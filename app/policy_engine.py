"""
policy_engine.py

The brain of the gateway. Every inbound AgentRequest is scored and
classified into ALLOW / BLOCK / REVIEW before it is allowed anywhere
near the (simulated) execution layer.

Design notes:
- Rules and scoring are intentionally kept in plain, readable Python
  (no rule-engine DSL) so the logic is auditable at a glance — this is
  a security-relevant module and "auditable" beats "clever".
- The engine is stateless except for an in-memory request-rate tracker
  used for the "repeated agent behavior" signal. In a multi-process
  deployment this should be backed by Redis; see README for notes.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from app.models import AgentRequest, Decision, PolicyDecision

# ---------------------------------------------------------------------------
# Static rule definitions
# ---------------------------------------------------------------------------

# Sensitive keywords that should never appear in a prompt being forwarded
# toward tool execution. Matched as whole-word-ish substrings, case-insensitive.
SENSITIVE_KEYWORDS = [
    "api_key",
    "api key",
    "password",
    "secret",
    "token",
    "seed",
    "wallet",
    "private_key",
    "private key",
]

# Tool name fragments that indicate a destructive / irreversible action.
DESTRUCTIVE_TOOL_FRAGMENTS = [
    "delete",
    "withdraw",
    "transfer",
    "overwrite",
    "drop",
    "purge",
    "wipe",
]

# Action types considered inherently high risk.
HIGH_RISK_ACTION_TYPES = {"delete", "transfer"}

# Known/expected tool catalog. Anything not in here is "unknown" and
# picks up a small risk bump. In production this would be loaded from
# a tool registry / config rather than hardcoded.
KNOWN_TOOLS = {
    "send_email",
    "read_database",
    "update_record",
    "create_ticket",
    "read_file",
    "write_file",
    "search_web",
    "post_message",
    "get_weather",
    "calendar_create",
}

# Phrases indicative of a prompt-injection / jailbreak attempt directed
# at the agent or the gateway itself.
PROMPT_INJECTION_PATTERNS = [
    r"ignore (all|any|the)?\s*previous instructions",
    r"ignore (all|any|the)?\s*prior instructions",
    r"disregard (all|any|the)?\s*(previous|prior) instructions",
    r"\bbypass\b",
    r"\boverride\b",
    r"system prompt",
    r"reveal (your|the) (system|instructions|prompt)",
    r"act as (if|though) you (have no|have not any) restrictions",
    r"jailbreak",
    r"do anything now",
    r"\bDAN\b",
]

_INJECTION_REGEXES = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS]

# Rate-limit window for the "repeated agent behavior" signal.
RATE_WINDOW_SECONDS = 60
RATE_THRESHOLD = 10  # >10 requests/min triggers the signal

# Risk score thresholds for the final decision.
BLOCK_SCORE_THRESHOLD = 80
REVIEW_SCORE_THRESHOLD = 40


class _RateTracker:
    """Tracks recent request timestamps per agent_id to approximate
    'repeated agent behavior' (>10 requests/min).

    In-memory and process-local by design for the MVP. Swap for a
    Redis sorted-set (ZADD/ZRANGEBYSCORE) implementation behind the
    same interface for multi-worker / multi-instance deployments.
    """

    def __init__(self, window_seconds: int = RATE_WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def record_and_count(self, agent_id: str) -> int:
        now = time.monotonic()
        bucket = self._hits[agent_id]
        bucket.append(now)
        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket)


class PolicyEngine:
    """Stateful (rate-tracking) policy engine. Instantiate once and
    reuse across requests (it's cheap and thread-safe enough for the
    MVP's in-memory counters via the GIL)."""

    def __init__(self) -> None:
        self._rate_tracker = _RateTracker()

    # -- public API ---------------------------------------------------

    def evaluate(self, request: AgentRequest) -> PolicyDecision:
        flags: list[str] = []
        score = 0

        prompt_lower = request.prompt.lower()
        tool_lower = request.tool_name.lower()
        action_lower = request.action_type.lower()

        # --- signal: sensitive keyword in prompt ---
        sensitive_hit = self._find_sensitive_keyword(prompt_lower)
        if sensitive_hit:
            score += 40
            flags.append(f"sensitive_keyword:{sensitive_hit}")

        # --- signal: destructive tool name ---
        destructive_hit = self._find_destructive_fragment(tool_lower)
        if destructive_hit:
            score += 30
            flags.append(f"destructive_tool:{destructive_hit}")

        # --- signal: repeated agent behavior (rate) ---
        request_count = self._rate_tracker.record_and_count(request.agent_id)
        if request_count > RATE_THRESHOLD:
            score += 20
            flags.append(f"rate_limit_exceeded:{request_count}_req_per_min")

        # --- signal: unknown tool ---
        if tool_lower not in KNOWN_TOOLS:
            score += 10
            flags.append(f"unknown_tool:{request.tool_name}")

        score = min(score, 100)

        # --- prompt injection / security event detection (separate axis) ---
        injection_hit = self._find_prompt_injection(request.prompt)
        is_security_event = injection_hit is not None
        if injection_hit:
            flags.append(f"prompt_injection_detected:{injection_hit}")
            # Injection attempts are always treated as maximally risky,
            # regardless of what the keyword/destructive scoring produced.
            score = max(score, 90)

        # --- hard BLOCK rules (override score-based decision) ---
        hard_block_reason = self._hard_block_reason(
            sensitive_hit=sensitive_hit,
            destructive_hit=destructive_hit,
            action_lower=action_lower,
            score=score,
            injection_hit=injection_hit,
        )

        if hard_block_reason:
            return PolicyDecision(
                decision=Decision.BLOCK,
                risk_score=score,
                reason=hard_block_reason,
                flags=flags,
                is_security_event=is_security_event,
            )

        # --- score-based decision for everything else ---
        decision, reason = self._decide_from_score(score, flags)

        return PolicyDecision(
            decision=decision,
            risk_score=score,
            reason=reason,
            flags=flags,
            is_security_event=is_security_event,
        )

    # -- internal helpers ----------------------------------------------

    @staticmethod
    def _find_sensitive_keyword(prompt_lower: str) -> str | None:
        for kw in SENSITIVE_KEYWORDS:
            if kw in prompt_lower:
                return kw
        return None

    @staticmethod
    def _find_destructive_fragment(tool_lower: str) -> str | None:
        for fragment in DESTRUCTIVE_TOOL_FRAGMENTS:
            if fragment in tool_lower:
                return fragment
        return None

    @staticmethod
    def _find_prompt_injection(prompt: str) -> str | None:
        for regex in _INJECTION_REGEXES:
            match = regex.search(prompt)
            if match:
                return match.group(0)
        return None

    @staticmethod
    def _hard_block_reason(
        *,
        sensitive_hit: str | None,
        destructive_hit: str | None,
        action_lower: str,
        score: int,
        injection_hit: str | None,
    ) -> str | None:
        """Hard rules that BLOCK regardless of overall score. Returns a
        human-readable reason string, or None if no hard rule fired."""

        if injection_hit:
            return (
                "Blocked: prompt injection / instruction-override attempt "
                f"detected ('{injection_hit}')."
            )

        if sensitive_hit:
            return (
                "Blocked: prompt contains a sensitive keyword "
                f"('{sensitive_hit}') that must never reach a tool call."
            )

        if destructive_hit:
            return (
                "Blocked: tool name indicates a destructive action "
                f"('{destructive_hit}')."
            )

        if action_lower in HIGH_RISK_ACTION_TYPES and score > 60:
            return (
                f"Blocked: action_type '{action_lower}' is high risk and "
                f"risk_score {score} exceeds the 60 threshold for that "
                "action class."
            )

        return None

    @staticmethod
    def _decide_from_score(score: int, flags: list[str]) -> tuple[Decision, str]:
        if score >= BLOCK_SCORE_THRESHOLD:
            return (
                Decision.BLOCK,
                f"Blocked: aggregate risk_score {score} meets/exceeds the "
                f"block threshold ({BLOCK_SCORE_THRESHOLD}).",
            )
        if score >= REVIEW_SCORE_THRESHOLD:
            return (
                Decision.REVIEW,
                f"Flagged for human review: risk_score {score} is elevated "
                f"(>= {REVIEW_SCORE_THRESHOLD}). Flags: {', '.join(flags) or 'none'}.",
            )
        return (
            Decision.ALLOW,
            f"Allowed: risk_score {score} is within acceptable bounds.",
        )


# Module-level singleton used by the API layer. A single process-wide
# instance is what makes the in-memory rate tracker meaningful within
# one running server.
policy_engine = PolicyEngine()
