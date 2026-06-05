# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import os
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from cowrie.adaptive import EVENT_COMMAND_MISSED
from cowrie.adaptive.cache import argv_fingerprint, handler_cache_key
from cowrie.adaptive.intake import sanitized_hash
from cowrie.adaptive.llm_specs import DeclarativeSpecGenerator, SpecGenerationError
from cowrie.adaptive.rag import RagRetriever
from cowrie.adaptive.spec import SpecValidationError, normalize_matching_behavior_spec
from cowrie.adaptive.store import MemoryStore, PostgresStore, dumps_json
from cowrie.adaptive.triage import DeterministicTriage


class AdaptiveSidecar:
    def __init__(
        self,
        store: Any,
        generator: DeclarativeSpecGenerator | None = None,
        rag_retriever: RagRetriever | None = None,
    ):
        self.store = store
        self.triage = DeterministicTriage()
        self.generator = generator or DeclarativeSpecGenerator()
        self.rag_retriever = rag_retriever or RagRetriever(store)
        self.recent_results: list[dict[str, Any]] = []

    def receive_event(self, event: dict[str, Any]) -> dict[str, Any]:
        self.store.store_event(event)
        response = {"stored": True, "queued": False}
        if event.get("event_type") != EVENT_COMMAND_MISSED or self.store.frozen:
            self._remember({**response, "event_type": event.get("event_type")})
            return response

        decision = self.triage.decide(event)
        response.update(
            {
                "triage_reason": decision.reason,
                "novelty_score": decision.novelty_score,
            }
        )
        if not decision.enqueue:
            self._remember({**response, "status": "skipped"})
            return response

        payload = event.get("payload", {})
        command = payload.get("command", "")
        argv = payload.get("argv", [])
        cache_key = handler_cache_key(command, argv)
        argv_fp = argv_fingerprint(argv)
        cache_entry = self.store.claim_handler_cache(cache_key, command, argv_fp)
        cache_status = cache_entry.get("cache_status", "miss")
        response.update({"cache_key": cache_key, "cache_status": cache_status})
        if cache_status == "hit":
            response["status"] = "cache_hit"
            self._remember(
                {
                    **response,
                    "command": command,
                    "session_id": event.get("session_id"),
                }
            )
            return response
        if cache_status == "pending":
            response["status"] = "cache_pending"
            self._remember(
                {
                    **response,
                    "command": command,
                    "session_id": event.get("session_id"),
                }
            )
            return response

        attempt = {
            "session_id": event.get("session_id"),
            "sanitized_input_hash": sanitized_hash(event.get("payload", {})),
            "cache_key": cache_key,
            "cache_status": cache_status,
            "rag_status": "not_requested",
            "prompt_metadata": {
                "event_type": event.get("event_type"),
                "sequence_hash": event.get("sequence_hash"),
                "model": self.generator.model,
                "provider": getattr(self.generator, "provider", ""),
                "cache_key": cache_key,
                "cache_status": cache_status,
                "rag_status": "not_requested",
            },
            "generated_spec": None,
            "validator_failures": [],
            "retry_count": 0,
            "status": "queued",
        }
        self.store.record_patch_attempt(attempt)
        response.update({"queued": True, "status": "generation_started"})
        self._remember(
            {
                **response,
                "command": command,
                "session_id": event.get("session_id"),
            }
        )
        threading.Thread(
            target=self._generate_and_publish,
            args=(event, attempt, cache_key),
            daemon=True,
        ).start()
        return response

    def _generate_and_publish(
        self, event: dict[str, Any], attempt: dict[str, Any], cache_key: str
    ) -> None:
        try:
            rag_result = self.rag_retriever.retrieve(event)
            attempt["rag_status"] = rag_result.status
            attempt["prompt_metadata"].update(rag_result.metadata())
            spec = self.generator.generate(event, rag_result.prompt_context())
            payload = event.get("payload", {})
            spec = normalize_matching_behavior_spec(
                spec,
                payload.get("command", ""),
                payload.get("argv", []),
            )
        except SpecGenerationError:
            attempt["status"] = "queued_no_llm"
            self.store.record_patch_attempt(attempt)
            self.store.mark_handler_cache_failed(cache_key, "queued_no_llm")
            self._remember(
                {
                    "stored": True,
                    "queued": True,
                    "status": "queued_no_llm",
                    "command": event.get("payload", {}).get("command", ""),
                    "session_id": event.get("session_id"),
                }
            )
            return
        except (OSError, json.JSONDecodeError, KeyError, SpecValidationError) as e:
            attempt["validator_failures"] = [repr(e)]
            attempt["status"] = "rejected"
            self.store.record_patch_attempt(attempt)
            self.store.mark_handler_cache_failed(cache_key, repr(e))
            self._remember(
                {
                    "stored": True,
                    "queued": True,
                    "status": "rejected",
                    "error": repr(e),
                    "command": event.get("payload", {}).get("command", ""),
                    "session_id": event.get("session_id"),
                }
            )
            return
        except Exception as e:
            attempt["validator_failures"] = [traceback.format_exc()]
            attempt["status"] = "error"
            self.store.record_patch_attempt(attempt)
            self.store.mark_handler_cache_failed(cache_key, repr(e))
            self._remember(
                {
                    "stored": True,
                    "queued": True,
                    "status": "error",
                    "error": repr(e),
                    "command": event.get("payload", {}).get("command", ""),
                    "session_id": event.get("session_id"),
                }
            )
            return

        attempt["generated_spec"] = spec
        attempt["status"] = "accepted"
        self.store.record_patch_attempt(attempt)
        version = self.store.publish_behavior_spec(spec, cache_key=cache_key)
        self._remember(
            {
                "stored": True,
                "queued": True,
                "status": "accepted",
                "version": version,
                "command": spec.get("command", ""),
                "session_id": event.get("session_id"),
            }
        )

    def latest_behavior(self, since_version: int = 0) -> dict[str, Any]:
        return self.store.latest_behavior(since_version=since_version)

    def reload_result(self, result: dict[str, Any]) -> dict[str, Any]:
        self.store.store_event(
            {
                "event_type": "behavior_reload_result",
                "session_id": result.get("session_id", "control-plane"),
                "sequence_index": 0,
                "sequence_hash": "",
                "payload": result,
            }
        )
        return {"stored": True}

    def freeze(self) -> dict[str, Any]:
        self.store.freeze()
        return {"frozen": True}

    def debug_recent(self) -> dict[str, Any]:
        return {"recent_results": list(self.recent_results)}

    def debug_rag(self) -> dict[str, Any]:
        return self.store.rag_stats()

    def _remember(self, result: dict[str, Any]) -> None:
        result = {**result, "time": time.time()}
        self.recent_results.append(result)
        self.recent_results = self.recent_results[-50:]
        print(  # noqa: T201
            f"adaptive sidecar event result: {json.dumps(result, sort_keys=True)}",
            flush=True,
        )


def make_store() -> Any:
    dsn = os.environ.get("ADAPTIVE_POSTGRES_DSN", "")
    if dsn:
        return PostgresStore(dsn)
    return MemoryStore()


def make_handler(sidecar: AdaptiveSidecar) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self._read_json()
            path = urlparse(self.path).path
            if path == "/events":
                self._write_json(sidecar.receive_event(body))
            elif path == "/behavior/reload-result":
                self._write_json(sidecar.reload_result(body))
            elif path == "/control/freeze":
                self._write_json(sidecar.freeze())
            else:
                self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/behavior/latest":
                query = parse_qs(parsed.query)
                since_version = int(query.get("since_version", ["0"])[0] or "0")
                self._write_json(sidecar.latest_behavior(since_version))
            elif path == "/debug/recent":
                self._write_json(sidecar.debug_recent())
            elif path == "/debug/rag":
                self._write_json(sidecar.debug_rag())
            else:
                self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def _write_json(
            self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK
        ) -> None:
            body = dumps_json(data)
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> None:
    host = os.environ.get("ADAPTIVE_SIDECAR_HOST", "127.0.0.1")
    port = int(os.environ.get("ADAPTIVE_SIDECAR_PORT", "8088"))
    sidecar = AdaptiveSidecar(make_store())
    server = ThreadingHTTPServer((host, port), make_handler(sidecar))
    print(f"adaptive sidecar listening on http://{host}:{port}")  # noqa: T201
    server.serve_forever()


if __name__ == "__main__":
    main()
