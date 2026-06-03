# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from twisted.internet import reactor
from twisted.python import log

from cowrie.core.config import CowrieConfig


class SidecarClient:
    """Small non-blocking HTTP client for the adaptive sidecar."""

    def __init__(self) -> None:
        self.enabled = CowrieConfig.getboolean("adaptive", "enabled", fallback=False)
        self.base_url = CowrieConfig.get(
            "adaptive", "sidecar_url", fallback="http://127.0.0.1:8088"
        ).rstrip("/")
        self.timeout = CowrieConfig.getfloat("adaptive", "timeout", fallback=2.0)

    def send_event(self, event: dict[str, Any]) -> None:
        if not self.enabled:
            return
        reactor.callInThread(self._post_json, "/events", event)

    def report_reload_result(self, result: dict[str, Any]) -> None:
        if not self.enabled:
            return
        reactor.callInThread(self._post_json, "/behavior/reload-result", result)

    def _post_json(self, path: str, body: dict[str, Any]) -> None:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (OSError, urllib.error.URLError) as e:
            log.msg(f"adaptive sidecar request failed: {e!r}")
