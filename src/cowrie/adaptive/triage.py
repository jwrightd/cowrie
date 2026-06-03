# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from cowrie.adaptive.linux_commands import invalid_linux_command_reason

_SCANNER_COMMANDS = {
    "cat",
    "cd",
    "echo",
    "id",
    "ls",
    "pwd",
    "uname",
    "uptime",
    "whoami",
}


def miss_signature(payload: dict[str, Any]) -> str:
    command = payload.get("command", "")
    argv = " ".join(payload.get("argv", []))
    return hashlib.sha256(f"{command}\0{argv}".encode("utf-8")).hexdigest()


@dataclass
class RateLimiter:
    max_events: int = 20
    window_seconds: int = 3600
    _events: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        now = time.time()
        events = [
            ts
            for ts in self._events.get(key, [])
            if now - ts <= self.window_seconds
        ]
        if len(events) >= self.max_events:
            self._events[key] = events
            return False
        events.append(now)
        self._events[key] = events
        return True


@dataclass
class TriageDecision:
    enqueue: bool
    reason: str
    novelty_score: float


class DeterministicTriage:
    """Cheap gate before any LLM work."""

    def __init__(self) -> None:
        self._seen_signatures: set[str] = set()
        self._rate_limiter = RateLimiter()

    def decide(self, event: dict[str, Any]) -> TriageDecision:
        payload = event.get("payload", {})
        command = payload.get("command", "")
        invalid_reason = invalid_linux_command_reason(command)
        if invalid_reason:
            return TriageDecision(False, invalid_reason, 0.0)

        signature = miss_signature(payload)
        if signature in self._seen_signatures:
            return TriageDecision(False, "duplicate_miss", 0.1)
        self._seen_signatures.add(signature)

        source = payload.get("src_ip") or event.get("session_id", "unknown")
        if not self._rate_limiter.allow(str(source)):
            return TriageDecision(False, "rate_limited", 0.0)

        prior_sequence = payload.get("prior_sequence", [])
        if command in _SCANNER_COMMANDS and len(prior_sequence) <= 3:
            return TriageDecision(False, "likely_scanner_recon", 0.2)

        score = min(1.0, 0.35 + (len(prior_sequence) * 0.08))
        return TriageDecision(True, "worth_triage", score)
