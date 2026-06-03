# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from typing import Any

from twisted.python import log

from cowrie.adaptive import (
    EVENT_COMMAND_HANDLED,
    EVENT_COMMAND_MISSED,
    EVENT_COMMAND_OBSERVED,
    EVENT_SESSION_ENDED,
    EVENT_SESSION_STARTED,
)
from cowrie.adaptive.client import SidecarClient
from cowrie.adaptive.events import (
    AdaptiveEvent,
    SessionTracker,
    protocol_name,
    sanitized_env,
    session_id_from_protocol,
)


class CowrieAdaptiveAdapter:
    """Translate Cowrie runtime activity into adapter-neutral events."""

    def __init__(self, client: SidecarClient | None = None) -> None:
        self.client = client or SidecarClient()
        self.tracker = SessionTracker()

    def session_started(self, protocol: Any) -> None:
        session_id = session_id_from_protocol(protocol)
        self.tracker.reset(session_id)
        self._emit(
            protocol,
            EVENT_SESSION_STARTED,
            {
                "protocol": protocol_name(protocol),
                "src_ip": getattr(protocol, "realClientIP", ""),
                "src_port": getattr(protocol, "realClientPort", None),
                "username": getattr(getattr(protocol, "user", None), "username", ""),
                "hostname": getattr(protocol, "hostname", ""),
            },
        )

    def session_ended(self, protocol: Any) -> None:
        session_id = session_id_from_protocol(protocol)
        _, _, commands = self.tracker.snapshot(session_id)
        self._emit(
            protocol,
            EVENT_SESSION_ENDED,
            {
                "protocol": protocol_name(protocol),
                "command_count": len(commands),
                "commands": commands,
            },
        )
        self.tracker.drop(session_id)

    def command_observed(
        self, protocol: Any, command: str, argv: list[str]
    ) -> tuple[int, str, list[dict[str, Any]]]:
        session_id = session_id_from_protocol(protocol)
        index, seq_hash, commands = self.tracker.append_command(
            session_id, command, argv, getattr(protocol, "cwd", "/")
        )
        self._emit(
            protocol,
            EVENT_COMMAND_OBSERVED,
            {
                "command": command,
                "argv": list(argv),
                "cwd": getattr(protocol, "cwd", "/"),
                "env": sanitized_env(getattr(protocol, "environ", None)),
                "commands": commands,
            },
            sequence_index=index,
            seq_hash=seq_hash,
        )
        return index, seq_hash, commands

    def command_handled(
        self,
        protocol: Any,
        command: str,
        argv: list[str],
        handler: str,
    ) -> None:
        self._emit(
            protocol,
            EVENT_COMMAND_HANDLED,
            {
                "command": command,
                "argv": list(argv),
                "cwd": getattr(protocol, "cwd", "/"),
                "handler": handler,
            },
        )

    def command_missed(
        self,
        protocol: Any,
        command: str,
        argv: list[str],
        commands: list[dict[str, Any]] | None = None,
    ) -> None:
        payload = {
            "command": command,
            "argv": list(argv),
            "cwd": getattr(protocol, "cwd", "/"),
            "env": sanitized_env(getattr(protocol, "environ", None)),
            "prior_sequence": commands
            if commands is not None
            else self.tracker.commands(session_id_from_protocol(protocol)),
        }
        self._emit(protocol, EVENT_COMMAND_MISSED, payload)

    def _emit(
        self,
        protocol: Any,
        event_type: str,
        payload: dict[str, Any],
        sequence_index: int | None = None,
        seq_hash: str | None = None,
    ) -> None:
        session_id = session_id_from_protocol(protocol)
        if sequence_index is None or seq_hash is None:
            sequence_index, seq_hash, _commands = self.tracker.snapshot(session_id)
        event = AdaptiveEvent(
            event_type=event_type,
            session_id=session_id,
            sequence_index=sequence_index,
            sequence_hash=seq_hash,
            payload=payload,
        )
        event_dict = event.to_dict()
        log.msg(
            eventid=f"cowrie.adaptive.{event_type}",
            adaptive_event_type=event_type,
            adaptive_session=event.session_id,
            adaptive_sequence_hash=event.sequence_hash,
            adaptive_payload=payload,
            format="Adaptive event: %(adaptive_event_type)s %(adaptive_session)s",
        )
        self.client.send_event(event_dict)


_adapter = CowrieAdaptiveAdapter()


def get_adapter() -> CowrieAdaptiveAdapter:
    return _adapter


def set_adapter_for_tests(adapter: CowrieAdaptiveAdapter) -> None:
    global _adapter
    _adapter = adapter
