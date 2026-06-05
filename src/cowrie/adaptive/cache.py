# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import hashlib
import json
from typing import Any

from cowrie.adaptive.linux_commands import normalize_command_name

_MAX_CACHE_ARGS = 8
_MAX_CACHE_ARG_LENGTH = 128


def argv_fingerprint(argv: list[str]) -> str:
    bounded = [str(arg)[:_MAX_CACHE_ARG_LENGTH] for arg in argv[:_MAX_CACHE_ARGS]]
    return json.dumps(bounded, separators=(",", ":"), sort_keys=True)


def handler_cache_key(command: str, argv: list[str]) -> str:
    payload = {
        "command": normalize_command_name(command),
        "argv": json.loads(argv_fingerprint(argv)),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
