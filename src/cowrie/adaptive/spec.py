# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

_COMMAND_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SAFE_FS_PREFIXES = ("/tmp/", "/var/tmp/", "/home/", "/root/")
_MAX_ARG_PATTERNS = 16
_MAX_ARG_LENGTH = 256
_MAX_RESPONSE_LENGTH = 16384
_MAX_FS_CONTENT_LENGTH = 65536


class SpecValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ResponseSpec:
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class FileEffect:
    path: str
    content: str = ""
    mode: int = 0o644


@dataclass(frozen=True)
class BehaviorSpec:
    command: str
    response: ResponseSpec
    argv_match: dict[str, Any] = field(default_factory=dict)
    exit_status: int = 0
    fs_effects: list[FileEffect] = field(default_factory=list)
    state_effects: dict[str, str] = field(default_factory=dict)
    spec_id: str | None = None
    version: int = 1


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SpecValidationError(f"{name} must be an object")
    return value


def _validate_template(template: str, name: str) -> str:
    if not isinstance(template, str):
        raise SpecValidationError(f"{name} must be a string")
    if len(template) > _MAX_RESPONSE_LENGTH:
        raise SpecValidationError(f"{name} is too long")
    allowed = {"command", "args", "cwd", "username", "hostname"}
    unknown = set(_PLACEHOLDER_RE.findall(template)) - allowed
    if unknown:
        raise SpecValidationError(f"{name} has unsupported placeholders: {unknown}")
    return template


def _validate_argv_match(value: Any) -> dict[str, Any]:
    if value in (None, {}, []):
        return {}
    if isinstance(value, list):
        if len(value) > _MAX_ARG_PATTERNS:
            raise SpecValidationError("argv_match patterns is too large")
        clean_patterns = []
        for pattern in value:
            if not isinstance(pattern, str):
                raise SpecValidationError("argv_match patterns must be strings")
            if len(pattern) > _MAX_ARG_LENGTH:
                raise SpecValidationError("argv_match pattern is too long")
            clean_patterns.append(pattern)
        return {"mode": "prefix", "patterns": clean_patterns}
    argv_match = _require_dict(value, "argv_match")
    mode = argv_match.get("mode", "any")
    if mode not in {"any", "exact", "prefix", "contains"}:
        raise SpecValidationError("argv_match.mode is unsupported")
    patterns = argv_match.get("patterns", [])
    if not isinstance(patterns, list):
        raise SpecValidationError("argv_match.patterns must be a list")
    if len(patterns) > _MAX_ARG_PATTERNS:
        raise SpecValidationError("argv_match.patterns is too large")
    clean_patterns = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise SpecValidationError("argv_match patterns must be strings")
        if len(pattern) > _MAX_ARG_LENGTH:
            raise SpecValidationError("argv_match pattern is too long")
        clean_patterns.append(pattern)
    return {"mode": mode, "patterns": clean_patterns}


def _validate_fs_effects(value: Any) -> list[FileEffect]:
    if value in (None, []):
        return []
    if not isinstance(value, list):
        raise SpecValidationError("fs_effects must be a list")
    effects = []
    for effect in value:
        item = _require_dict(effect, "fs_effect")
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise SpecValidationError("fs_effect.path must be absolute")
        if path in {"/tmp", "/var/tmp", "/home", "/root"}:
            raise SpecValidationError("fs_effect.path must name a file")
        if not path.startswith(_SAFE_FS_PREFIXES):
            raise SpecValidationError("fs_effect.path is outside fake writable paths")
        content = item.get("content", "")
        if not isinstance(content, str):
            raise SpecValidationError("fs_effect.content must be a string")
        if len(content.encode("utf-8")) > _MAX_FS_CONTENT_LENGTH:
            raise SpecValidationError("fs_effect.content is too large")
        mode = item.get("mode", 0o644)
        if not isinstance(mode, int) or mode < 0 or mode > 0o777:
            raise SpecValidationError("fs_effect.mode must be a file mode")
        effects.append(FileEffect(path=path, content=content, mode=mode))
    return effects


def parse_behavior_spec(raw: dict[str, Any]) -> BehaviorSpec:
    data = _require_dict(raw, "behavior spec")
    command = data.get("command")
    if not isinstance(command, str) or not _COMMAND_RE.fullmatch(command):
        raise SpecValidationError("command must be a bounded command name")
    response_value = data.get("response", {})
    if isinstance(response_value, str):
        response = {"stdout": response_value, "stderr": ""}
    else:
        response = _require_dict(response_value, "response")
    exit_status = data.get("exit_status", 0)
    if not isinstance(exit_status, int) or exit_status < 0 or exit_status > 255:
        raise SpecValidationError("exit_status must be between 0 and 255")
    state_effects = data.get("state_effects", {})
    if state_effects in (None, []):
        state_effects = {}
    if not isinstance(state_effects, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in state_effects.items()
    ):
        raise SpecValidationError("state_effects must be a string map")
    return BehaviorSpec(
        command=command,
        argv_match=_validate_argv_match(data.get("argv_match", {})),
        response=ResponseSpec(
            stdout=_validate_template(response.get("stdout", ""), "response.stdout"),
            stderr=_validate_template(response.get("stderr", ""), "response.stderr"),
        ),
        exit_status=exit_status,
        fs_effects=_validate_fs_effects(data.get("fs_effects", [])),
        state_effects=state_effects,
        spec_id=data.get("spec_id"),
        version=int(data.get("version", 1)),
    )


def load_behavior_specs(path: str) -> list[BehaviorSpec]:
    if not path:
        return []
    spec_path = Path(path)
    if not spec_path.exists():
        return []
    data = json.loads(spec_path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if "handlers" in data:
            raw_specs = data["handlers"]
        else:
            raw_specs = [data]
    elif isinstance(data, list):
        raw_specs = data
    else:
        raise SpecValidationError("behavior spec file must contain an object or list")
    if not isinstance(raw_specs, list):
        raise SpecValidationError("handlers must be a list")
    return [parse_behavior_spec(item) for item in raw_specs]


def argv_matches(spec: BehaviorSpec, argv: list[str]) -> bool:
    matcher = spec.argv_match
    mode = matcher.get("mode", "any")
    patterns = matcher.get("patterns", [])
    if mode == "any":
        return True
    if mode == "exact":
        return argv == patterns
    if mode == "prefix":
        return argv[: len(patterns)] == patterns
    if mode == "contains":
        return all(pattern in argv for pattern in patterns)
    return False


def render_template(template: str, command: "AdaptiveCommand") -> str:
    values = {
        "command": command.spec.command,
        "args": " ".join(command.args),
        "cwd": command.protocol.cwd,
        "username": command.protocol.user.username,
        "hostname": command.protocol.hostname,
    }
    return template.format_map(values)


class AdaptiveCommand(HoneyPotCommand):
    """Deterministic command generated from a validated declarative spec."""

    spec: BehaviorSpec

    def call(self) -> None:
        self._apply_fs_effects()
        if self.spec.response.stdout:
            self.write(render_template(self.spec.response.stdout, self))
        if self.spec.response.stderr:
            self.errorWrite(render_template(self.spec.response.stderr, self))
        state = getattr(self.protocol, "adaptive_state", None)
        if state is None:
            state = {}
            self.protocol.adaptive_state = state
        state.update(self.spec.state_effects)

    def _apply_fs_effects(self) -> None:
        for effect in self.spec.fs_effects:
            try:
                virtual_path = self.fs.resolve_path(effect.path, self.protocol.cwd)
                content = effect.content.encode("utf-8")
                self.fs.mkfile(
                    virtual_path,
                    self.protocol.user.uid,
                    self.protocol.user.gid,
                    len(content),
                    stat.S_IFREG | effect.mode,
                )
                file_obj = self.fs.getfile(virtual_path)
                if file_obj is not None:
                    file_obj[fs.A_CONTENTS] = content
            except (fs.FileNotFound, fs.PermissionDenied, OSError) as e:
                log.msg(f"adaptive fs_effect failed for {effect.path}: {e!r}")


def command_class_for_spec(spec: BehaviorSpec) -> type[AdaptiveCommand]:
    class Command_adaptive(AdaptiveCommand):
        pass

    Command_adaptive.spec = spec
    Command_adaptive.__name__ = f"Command_adaptive_{spec.command}"
    return Command_adaptive


class BehaviorRegistry:
    """Reloadable collection of validated adaptive behavior specs."""

    def __init__(self) -> None:
        self._mtime: float | None = None
        self._path = ""
        self._file_specs: list[BehaviorSpec] = []
        self._remote_specs: list[BehaviorSpec] = []
        self._remote_version = -1
        self._last_remote_check = 0.0
        self._last_remote_error = ""
        self._specs: list[BehaviorSpec] = []

    def reload_if_needed(self) -> None:
        self._reload_file_if_needed()
        self._reload_remote_if_needed()

    def _reload_file_if_needed(self) -> None:
        path = CowrieConfig.get("adaptive", "behavior_file", fallback="")
        if not path:
            self._path = ""
            self._mtime = None
            self._file_specs = []
            self._merge_specs()
            return
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            if self._path != path:
                self._path = path
                self._mtime = None
                self._file_specs = []
                self._merge_specs()
            return
        if self._path == path and self._mtime == mtime:
            return
        specs = load_behavior_specs(path)
        self._path = path
        self._mtime = mtime
        self._file_specs = specs
        self._merge_specs()
        log.msg(f"adaptive loaded {len(specs)} behavior specs from {path}")

    def _reload_remote_if_needed(self) -> None:
        if not CowrieConfig.getboolean("adaptive", "enabled", fallback=False):
            return
        now = time.monotonic()
        interval = CowrieConfig.getfloat(
            "adaptive", "behavior_poll_interval", fallback=1.0
        )
        if now - self._last_remote_check < interval:
            return
        self._last_remote_check = now
        base_url = CowrieConfig.get(
            "adaptive", "sidecar_url", fallback="http://127.0.0.1:8088"
        ).rstrip("/")
        timeout = CowrieConfig.getfloat("adaptive", "timeout", fallback=2.0)
        try:
            with urllib.request.urlopen(
                f"{base_url}/behavior/latest", timeout=timeout
            ) as response:
                data = json.loads(response.read().decode("utf-8"))
            raw_specs = data.get("handlers", [])
            if not isinstance(raw_specs, list):
                raise SpecValidationError("handlers must be a list")
            version = int(data.get("version", 0))
            if version == self._remote_version:
                return
            specs = [parse_behavior_spec(item) for item in raw_specs]
            self._remote_version = version
            self._remote_specs = specs
            self._last_remote_error = ""
            self._merge_specs()
            log.msg(
                f"adaptive loaded {len(specs)} behavior specs "
                f"from {base_url}/behavior/latest version {version}"
            )
        except (
            OSError,
            urllib.error.URLError,
            json.JSONDecodeError,
            KeyError,
            ValueError,
            SpecValidationError,
        ) as e:
            message = repr(e)
            if message != self._last_remote_error:
                self._last_remote_error = message
                log.msg(f"adaptive behavior fetch failed: {message}")

    def _merge_specs(self) -> None:
        self._specs = [*self._remote_specs, *self._file_specs]

    def command_class(self, command: str, argv: list[str]) -> type[AdaptiveCommand] | None:
        self.reload_if_needed()
        for spec in self._specs:
            if spec.command == command and argv_matches(spec, argv):
                return command_class_for_spec(spec)
        return None

    def load_for_tests(self, specs: list[dict[str, Any]]) -> None:
        fd, path = tempfile.mkstemp(prefix="cowrie-adaptive-test-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"handlers": specs}, handle)
        self._path = path
        self._mtime = None
        self._specs = []
        if not CowrieConfig.has_section("adaptive"):
            CowrieConfig.add_section("adaptive")
        CowrieConfig.set("adaptive", "behavior_file", path)
        self.reload_if_needed()

    def clear_for_tests(self) -> None:
        self._path = ""
        self._mtime = None
        self._file_specs = []
        self._remote_specs = []
        self._remote_version = -1
        self._last_remote_check = 0.0
        self._last_remote_error = ""
        self._specs = []
        if not CowrieConfig.has_section("adaptive"):
            CowrieConfig.add_section("adaptive")
        CowrieConfig.set("adaptive", "behavior_file", "")


registry = BehaviorRegistry()
