# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from cowrie.adaptive.intake import as_non_instruction_context
from cowrie.adaptive.spec import parse_behavior_spec


class SpecGenerationError(RuntimeError):
    pass


class DeclarativeSpecGenerator:
    """OpenAI-compatible JSON spec generator used only by the sidecar."""

    def __init__(self) -> None:
        self.api_key = os.environ.get("ADAPTIVE_LLM_API_KEY", "")
        self.model = os.environ.get("ADAPTIVE_LLM_MODEL", "gpt-4o-mini")
        self.url = os.environ.get(
            "ADAPTIVE_LLM_URL", "https://api.openai.com/v1/chat/completions"
        )
        self.timeout = float(os.environ.get("ADAPTIVE_LLM_TIMEOUT", "30"))

    def configured(self) -> bool:
        return bool(self.api_key and self.url)

    def generate(self, event: dict[str, Any]) -> dict[str, Any]:
        if not self.configured():
            raise SpecGenerationError("adaptive LLM is not configured")

        prompt = self._prompt(event)
        request_body = {
            "model": self.model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You write declarative honeypot handler specs. Return one "
                        "JSON object only. Do not emit code. The JSON must contain: "
                        "command, argv_match, response, exit_status, fs_effects, "
                        "state_effects. Use fs_effects: [] and state_effects: {} "
                        "when no effects are needed. state_effects must be a JSON "
                        "object whose keys and values are strings. argv_match must "
                        "be an object like {\"mode\":\"prefix\",\"patterns\":[\"--probe\"]}."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        request = urllib.request.Request(
            self.url,
            data=json.dumps(request_body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response_data = json.loads(response.read().decode("utf-8"))
        content = response_data["choices"][0]["message"]["content"]
        spec = json.loads(content)
        parse_behavior_spec(spec)
        return spec

    def _prompt(self, event: dict[str, Any]) -> str:
        payload = event.get("payload", {})
        command = payload.get("command", "")
        return (
            f"Create a safe v1 declarative handler for missed command {command!r}.\n"
            "Use only bounded argv matching, stdout/stderr templates, fake "
            "filesystem effects under /tmp, /var/tmp, /home, or /root, and "
            "session-local state effects. If there are no filesystem or state "
            "effects, set fs_effects to [] and state_effects to {}. argv_match "
            "must be a JSON object with mode one of any, exact, prefix, contains "
            "and patterns as a list of strings.\n\n"
            f"{as_non_instruction_context(payload)}"
        )
