# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""Adapter-neutral adaptive honeypot support."""

from __future__ import annotations

EVENT_ARTIFACT_OBSERVED = "artifact_observed"
EVENT_COMMAND_HANDLED = "command_handled"
EVENT_COMMAND_MISSED = "command_missed"
EVENT_COMMAND_OBSERVED = "command_observed"
EVENT_SESSION_ENDED = "session_ended"
EVENT_SESSION_STARTED = "session_started"

ADAPTIVE_EVENT_TYPES = {
    EVENT_ARTIFACT_OBSERVED,
    EVENT_COMMAND_HANDLED,
    EVENT_COMMAND_MISSED,
    EVENT_COMMAND_OBSERVED,
    EVENT_SESSION_ENDED,
    EVENT_SESSION_STARTED,
}
