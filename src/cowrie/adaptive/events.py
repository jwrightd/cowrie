# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import hashlib
import json
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from cowrie.adaptive import ADAPTIVE_EVENT_TYPES
from cowrie.core.config import CowrieConfig


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sequence_hash(commands: list[dict[str, Any]]) -> str:
    """Return a stable hash for a cumulative command sequence."""
    return hashlib.sha256(_stable_json(commands).encode("utf-8")).hexdigest()


def sanitized_env(environ: dict[str, str] | None) -> dict[str, str]:
    """Keep only low-risk environment context for downstream triage."""
    if not environ:
        return {}
    allowed = ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER")
    return {key: environ[key] for key in allowed if key in environ}


def session_id_from_protocol(protocol: Any) -> str:
    """Best-effort stable session identifier across Cowrie test and runtime paths."""
    terminal = getattr(protocol, "terminal", None)
    transport = getattr(terminal, "transport", None)
    session = getattr(transport, "session", None)
    if session is not None:
        sid = getattr(session, "id", None)
        if sid:
            return str(sid)

    try:
        proto_transport = protocol.getProtoTransport()
    except Exception:
        proto_transport = None

    for candidate in (
        getattr(proto_transport, "transportId", None),
        getattr(proto_transport, "id", None),
        getattr(getattr(proto_transport, "transport", None), "sessionno", None),
        getattr(protocol, "sessionno", None),
    ):
        if candidate is not None:
            return str(candidate)

    return "unknown"


def protocol_name(protocol: Any) -> str:
    name = protocol.__class__.__name__.lower()
    if "telnet" in name:
        return "telnet"
    return "ssh"


@dataclass
class AdaptiveEvent:
    event_type: str
    session_id: str
    sequence_index: int
    sequence_hash: str
    payload: dict[str, Any]
    sensor_id: str = field(
        default_factory=lambda: CowrieConfig.get(
            "honeypot", "sensor_name", fallback=socket.gethostname()
        )
    )
    honeypot: str = "cowrie"
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.event_type not in ADAPTIVE_EVENT_TYPES:
            raise ValueError(f"unsupported adaptive event type: {self.event_type}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SessionTracker:
    """In-memory cumulative command tracking for one honeypot process."""

    def __init__(self) -> None:
        self._commands_by_session: dict[str, list[dict[str, Any]]] = {}

    def reset(self, session_id: str) -> None:
        self._commands_by_session[session_id] = []

    def drop(self, session_id: str) -> None:
        self._commands_by_session.pop(session_id, None)

    def commands(self, session_id: str) -> list[dict[str, Any]]:
        return list(self._commands_by_session.get(session_id, []))

    def append_command(
        self, session_id: str, command: str, argv: list[str], cwd: str
    ) -> tuple[int, str, list[dict[str, Any]]]:
        commands = self._commands_by_session.setdefault(session_id, [])
        commands.append(
            {
                "command": command,
                "argv": list(argv),
                "cwd": cwd,
                "index": len(commands) + 1,
            }
        )
        return len(commands), sequence_hash(commands), list(commands)

    def snapshot(self, session_id: str) -> tuple[int, str, list[dict[str, Any]]]:
        commands = self._commands_by_session.setdefault(session_id, [])
        return len(commands), sequence_hash(commands), list(commands)
