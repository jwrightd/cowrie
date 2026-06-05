# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import os
import time
import unittest
from unittest import mock

from cowrie.adaptive import (
    EVENT_COMMAND_HANDLED,
    EVENT_COMMAND_MISSED,
    EVENT_COMMAND_OBSERVED,
    EVENT_SESSION_STARTED,
)
from cowrie.adaptive.cowrie_adapter import (
    CowrieAdaptiveAdapter,
    set_adapter_for_tests,
)
from cowrie.adaptive.llm_specs import (
    DeclarativeSpecGenerator,
    LLMClient,
    SpecGenerationError,
    loads_llm_json,
)
from cowrie.adaptive.rag import EmbeddingClient, RagRetriever
from cowrie.adaptive.sidecar import AdaptiveSidecar
from cowrie.adaptive.spec import SpecValidationError, parse_behavior_spec, registry
from cowrie.adaptive.store import MemoryStore
from cowrie.core.config import CowrieConfig
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class MemoryClient:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.sync_response: dict | None = None

    def send_event(self, event: dict) -> None:
        self.events.append(event)

    def send_event_sync(self, event: dict) -> dict | None:
        self.events.append(event)
        return self.sync_response

    def report_reload_result(self, result: dict) -> None:
        pass


class AdaptiveCowrieTests(unittest.TestCase):
    def setUp(self) -> None:
        if not CowrieConfig.has_section("adaptive"):
            CowrieConfig.add_section("adaptive")
        CowrieConfig.set("adaptive", "enabled", "false")
        CowrieConfig.set("adaptive", "behavior_file", "")
        registry.clear_for_tests()
        self.client = MemoryClient()
        set_adapter_for_tests(CowrieAdaptiveAdapter(self.client))
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()
        registry.clear_for_tests()

    def event_types(self) -> list[str]:
        return [event["event_type"] for event in self.client.events]

    def test_known_command_output_is_unchanged_and_observed(self) -> None:
        self.proto.lineReceived(b"whoami\n")
        self.assertEqual(self.tr.value(), b"root\n" + PROMPT)
        self.assertIn(EVENT_SESSION_STARTED, self.event_types())
        self.assertIn(EVENT_COMMAND_OBSERVED, self.event_types())
        self.assertIn(EVENT_COMMAND_HANDLED, self.event_types())
        self.assertNotIn(EVENT_COMMAND_MISSED, self.event_types())

    def test_unknown_command_emits_command_miss(self) -> None:
        self.proto.lineReceived(b"unknownadaptive -x\n")
        self.assertEqual(
            self.tr.value(), b"-bash: unknownadaptive: command not found\n" + PROMPT
        )
        miss_events = [
            event
            for event in self.client.events
            if event["event_type"] == EVENT_COMMAND_MISSED
        ]
        self.assertEqual(len(miss_events), 1)
        self.assertEqual(miss_events[0]["payload"]["command"], "unknownadaptive")
        self.assertEqual(miss_events[0]["payload"]["argv"], ["-x"])
        self.assertEqual(
            miss_events[0]["payload"]["prior_sequence"][-1]["command"],
            "unknownadaptive",
        )

    def test_unknown_command_can_use_immediate_adaptive_response(self) -> None:
        self.client.sync_response = {
            "status": "accepted",
            "spec": {
                "command": "unknownadaptive",
                "argv_match": {"mode": "exact", "patterns": ["--probe"]},
                "response": {"stdout": "generated now\n", "stderr": ""},
                "exit_status": 0,
                "fs_effects": [],
                "state_effects": {},
            },
        }
        self.proto.lineReceived(b"unknownadaptive --probe\n")
        self.assertEqual(self.tr.value(), b"generated now\n" + PROMPT)
        self.assertIn(EVENT_COMMAND_MISSED, self.event_types())
        self.assertIn(EVENT_COMMAND_HANDLED, self.event_types())

    def test_adaptive_spec_handles_unknown_command(self) -> None:
        registry.load_for_tests(
            [
                {
                    "command": "unknownadaptive",
                    "argv_match": {"mode": "prefix", "patterns": ["-x"]},
                    "response": {
                        "stdout": "adaptive {command} {args} in {cwd}\n",
                        "stderr": "",
                    },
                    "exit_status": 0,
                    "fs_effects": [],
                    "state_effects": {"last_adaptive": "unknownadaptive"},
                }
            ]
        )
        self.proto.lineReceived(b"unknownadaptive -x 1\n")
        self.assertEqual(
            self.tr.value(), b"adaptive unknownadaptive -x 1 in /root\n" + PROMPT
        )
        self.assertNotIn(EVENT_COMMAND_MISSED, self.event_types())
        self.assertEqual(self.proto.adaptive_state["last_adaptive"], "unknownadaptive")

    def test_adaptive_spec_adds_missing_response_newline(self) -> None:
        registry.load_for_tests(
            [
                {
                    "command": "unknownadaptive",
                    "argv_match": {"mode": "prefix", "patterns": ["--bad"]},
                    "response": {
                        "stdout": "",
                        "stderr": "unknownadaptive: option --bad requires an argument",
                    },
                    "exit_status": 1,
                    "fs_effects": [],
                    "state_effects": {},
                }
            ]
        )
        self.proto.lineReceived(b"unknownadaptive --bad\n")
        self.assertEqual(
            self.tr.value(),
            b"unknownadaptive: option --bad requires an argument\n" + PROMPT,
        )

    def test_adaptive_spec_can_create_fake_file(self) -> None:
        registry.load_for_tests(
            [
                {
                    "command": "dropper",
                    "argv_match": {"mode": "any", "patterns": []},
                    "response": {"stdout": "saved\n", "stderr": ""},
                    "exit_status": 0,
                    "fs_effects": [
                        {"path": "/tmp/payload.sh", "content": "echo owned\n"}
                    ],
                    "state_effects": {},
                }
            ]
        )
        self.proto.lineReceived(b"dropper\n")
        self.assertEqual(self.tr.value(), b"saved\n" + PROMPT)
        self.tr.clear()
        self.proto.lineReceived(b"cat /tmp/payload.sh\n")
        self.assertEqual(self.tr.value(), b"echo owned\n" + PROMPT)


class AdaptiveSpecTests(unittest.TestCase):
    def test_rejects_host_filesystem_effects(self) -> None:
        with self.assertRaises(SpecValidationError):
            parse_behavior_spec(
                {
                    "command": "evil",
                    "response": {"stdout": "", "stderr": ""},
                    "fs_effects": [
                        {"path": "/etc/passwd", "content": "bad"}
                    ],
                }
            )

    def test_accepts_empty_state_effect_list_as_no_effects(self) -> None:
        spec = parse_behavior_spec(
            {
                "command": "raretool",
                "response": {"stdout": "ok\n", "stderr": ""},
                "state_effects": [],
            }
        )
        self.assertEqual(spec.state_effects, {})

    def test_coerces_scalar_state_effect_values_to_strings(self) -> None:
        spec = parse_behavior_spec(
            {
                "command": "ss",
                "response": {"stdout": "ok\n", "stderr": ""},
                "state_effects": {
                    "last_exit_status": 0,
                    "has_socket_snapshot": True,
                    "last_error": None,
                },
            }
        )
        self.assertEqual(
            spec.state_effects,
            {
                "last_exit_status": "0",
                "has_socket_snapshot": "True",
                "last_error": "",
            },
        )

    def test_rejects_nested_state_effect_values(self) -> None:
        with self.assertRaises(SpecValidationError):
            parse_behavior_spec(
                {
                    "command": "ss",
                    "response": {"stdout": "ok\n", "stderr": ""},
                    "state_effects": {"snapshot": {"ports": [22]}},
                }
            )

    def test_accepts_argv_match_list_as_prefix_matcher(self) -> None:
        spec = parse_behavior_spec(
            {
                "command": "raretool",
                "argv_match": ["--probe"],
                "response": {"stdout": "ok\n", "stderr": ""},
            }
        )
        self.assertEqual(
            spec.argv_match, {"mode": "prefix", "patterns": ["--probe"]}
        )

    def test_accepts_response_string_as_stdout_template(self) -> None:
        spec = parse_behavior_spec(
            {
                "command": "raretool",
                "response": "raretool probe ok\n",
            }
        )
        self.assertEqual(spec.response.stdout, "raretool probe ok\n")
        self.assertEqual(spec.response.stderr, "")


class FakeHTTPResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class StaticGenerator:
    model = "hf-cyber-test"
    provider = "huggingface"

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.calls = 0
        self.rag_contexts: list[str] = []

    def configured(self) -> bool:
        return True

    def generate(self, event: dict, rag_context: str = "") -> dict:
        self.calls += 1
        self.rag_contexts.append(rag_context)
        if self.delay:
            time.sleep(self.delay)
        payload = event["payload"]
        return {
            "command": payload["command"],
            "argv_match": {"mode": "prefix", "patterns": payload.get("argv", [])},
            "response": {"stdout": "handled by shared cache\n", "stderr": ""},
            "exit_status": 0,
            "fs_effects": [],
            "state_effects": {},
        }


class ScalarStateGenerator(StaticGenerator):
    def generate(self, event: dict, rag_context: str = "") -> dict:
        spec = super().generate(event, rag_context)
        spec["state_effects"] = {"query_count": 2, "has_snapshot": True}
        return spec


class BadMatcherGenerator(StaticGenerator):
    def generate(self, event: dict, rag_context: str = "") -> dict:
        spec = super().generate(event, rag_context)
        spec["argv_match"] = {"mode": "exact", "patterns": ["ss", "ss -a"]}
        return spec


class FakeEmbeddingClient:
    model = "fake-embedding"

    def __init__(self, embedding: list[float]) -> None:
        self.embedding = embedding

    def configured(self) -> bool:
        return True

    def embed(self, text: str) -> list[float]:
        return self.embedding


class AdaptiveLLMTests(unittest.TestCase):
    def test_huggingface_provider_request_shape_and_response_parsing(self) -> None:
        captured: dict[str, object] = {}
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"command":"systemctl",'
                            '"argv_match":{"mode":"prefix","patterns":["status"]},'
                            '"response":{"stdout":"active\\n","stderr":""},'
                            '"exit_status":0,"fs_effects":[],"state_effects":{}}'
                        )
                    }
                }
            ]
        }

        def fake_urlopen(request, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeHTTPResponse(json.dumps(response_body).encode("utf-8"))

        with mock.patch.dict(
            os.environ,
            {
                "ADAPTIVE_LLM_PROVIDER": "huggingface",
                "ADAPTIVE_LLM_API_KEY": "test-key",
                "ADAPTIVE_LLM_MODEL": "org/cyber-model",
            },
            clear=True,
        ), mock.patch(
            "cowrie.adaptive.llm_specs.urllib.request.urlopen",
            side_effect=fake_urlopen,
        ):
            spec = DeclarativeSpecGenerator(LLMClient()).generate(
                {
                    "payload": {
                        "command": "systemctl",
                        "argv": ["status"],
                        "prior_sequence": [],
                    }
                }
            )

        self.assertEqual(spec["command"], "systemctl")
        self.assertEqual(
            captured["url"], "https://router.huggingface.co/v1/chat/completions"
        )
        body = captured["body"]
        self.assertEqual(body["model"], "org/cyber-model")
        self.assertEqual(body["response_format"], {"type": "json_object"})

    def test_missing_model_or_key_is_not_configured(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            generator = DeclarativeSpecGenerator(LLMClient())
            self.assertFalse(generator.configured())
            with self.assertRaises(SpecGenerationError):
                generator.generate({"payload": {"command": "systemctl"}})

    def test_can_omit_response_format_for_local_openai_servers(self) -> None:
        captured: dict[str, object] = {}
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"command":"systemctl",'
                            '"argv_match":{"mode":"prefix","patterns":["status"]},'
                            '"response":{"stdout":"active\\n","stderr":""},'
                            '"exit_status":0,"fs_effects":[],"state_effects":{}}'
                        )
                    }
                }
            ]
        }

        def fake_urlopen(request, timeout):  # type: ignore[no-untyped-def]
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeHTTPResponse(json.dumps(response_body).encode("utf-8"))

        with mock.patch.dict(
            os.environ,
            {
                "ADAPTIVE_LLM_API_KEY": "local-not-needed",
                "ADAPTIVE_LLM_MODEL": "baron-local",
                "ADAPTIVE_LLM_URL": "http://127.0.0.1:8080/v1/chat/completions",
                "ADAPTIVE_LLM_RESPONSE_FORMAT": "",
            },
            clear=True,
        ), mock.patch(
            "cowrie.adaptive.llm_specs.urllib.request.urlopen",
            side_effect=fake_urlopen,
        ):
            DeclarativeSpecGenerator(LLMClient()).generate(
                {"payload": {"command": "systemctl", "argv": ["status"]}}
            )

        self.assertNotIn("response_format", captured["body"])

    def test_prompt_guides_empty_argv_matcher(self) -> None:
        prompt = DeclarativeSpecGenerator(LLMClient())._prompt(
            {"payload": {"command": "ss", "argv": [], "prior_sequence": []}}
        )
        self.assertIn("The triggering argv is exactly []", prompt)
        self.assertIn(
            'prefer argv_match: {"mode":"exact","patterns":[]}',
            prompt,
        )
        self.assertIn("escaped newlines like \\n", prompt)

    def test_llm_json_loader_extracts_object_from_extra_text(self) -> None:
        spec = loads_llm_json(
            'Here is the JSON:\n{"command":"lsof","response":{"stdout":"ok\\n"}}\nDone.'
        )
        self.assertEqual(spec["command"], "lsof")

    def test_llm_json_loader_escapes_raw_newlines_inside_strings(self) -> None:
        spec = loads_llm_json(
            '{"command":"lsof","response":{"stdout":"COMMAND PID\nsshd 713\n"}}'
        )
        self.assertEqual(spec["response"]["stdout"], "COMMAND PID\nsshd 713\n")

    def test_local_embedding_client_works_without_api_key(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"ADAPTIVE_EMBEDDING_PROVIDER": "local"},
            clear=True,
        ):
            client = EmbeddingClient()
            self.assertTrue(client.configured())
            embedding = client.embed("ss -tulpn lists listening sockets")
        self.assertEqual(len(embedding), 384)
        self.assertTrue(any(value != 0 for value in embedding))


class AdaptiveRegistryTests(unittest.TestCase):
    def tearDown(self) -> None:
        registry.clear_for_tests()

    def test_fetches_latest_behavior_from_sidecar(self) -> None:
        if not CowrieConfig.has_section("adaptive"):
            CowrieConfig.add_section("adaptive")
        CowrieConfig.set("adaptive", "enabled", "true")
        CowrieConfig.set("adaptive", "sidecar_url", "http://127.0.0.1:8088")
        CowrieConfig.set("adaptive", "timeout", "1.0")
        CowrieConfig.set("adaptive", "behavior_poll_interval", "0.0")
        CowrieConfig.set("adaptive", "behavior_file", "")
        body = (
            b'{"frozen": false, "version": 7, "handlers": ['
            b'{"command": "remoteadaptive", '
            b'"argv_match": {"mode": "prefix", "patterns": ["--probe"]}, '
            b'"response": {"stdout": "remote ok\\n", "stderr": ""}, '
            b'"exit_status": 0, "fs_effects": [], "state_effects": {}}'
            b"]}"
        )
        with mock.patch(
            "cowrie.adaptive.spec.urllib.request.urlopen",
            return_value=FakeHTTPResponse(body),
        ):
            command_class = registry.command_class("remoteadaptive", ["--probe"])
        self.assertIsNotNone(command_class)


class AdaptiveSidecarTests(unittest.TestCase):
    def test_sidecar_stores_and_queues_miss_without_configured_llm(self) -> None:
        store = MemoryStore()
        sidecar = AdaptiveSidecar(store)
        result = sidecar.receive_event(
            {
                "event_type": EVENT_COMMAND_MISSED,
                "session_id": "session-1",
                "sequence_index": 1,
                "sequence_hash": "abc",
                "payload": {
                    "command": "systemctl",
                    "argv": ["--probe"],
                    "prior_sequence": [
                        {"command": "id", "argv": [], "cwd": "/root", "index": 1}
                    ],
                },
            }
        )
        self.assertTrue(result["stored"])
        self.assertTrue(result["queued"])
        self.assertEqual(result["status"], "generation_started")
        for _attempt in range(20):
            if any(
                item.get("status") == "queued_no_llm"
                for item in sidecar.debug_recent()["recent_results"]
            ):
                break
            time.sleep(0.01)
        self.assertTrue(
            any(
                item.get("status") == "queued_no_llm"
                for item in sidecar.debug_recent()["recent_results"]
            )
        )
        self.assertEqual(len(store.events), 1)
        self.assertGreaterEqual(len(store.patch_attempts), 1)

    def test_sidecar_skips_unknown_linux_command_names(self) -> None:
        store = MemoryStore()
        sidecar = AdaptiveSidecar(store)
        result = sidecar.receive_event(
            {
                "event_type": EVENT_COMMAND_MISSED,
                "session_id": "session-2",
                "sequence_index": 1,
                "sequence_hash": "def",
                "payload": {
                    "command": "raretool",
                    "argv": ["--probe"],
                    "prior_sequence": [
                        {"command": "id", "argv": [], "cwd": "/root", "index": 1}
                    ],
                },
            }
        )
        self.assertTrue(result["stored"])
        self.assertFalse(result["queued"])
        self.assertEqual(result["triage_reason"], "unknown_linux_command")
        self.assertEqual(store.patch_attempts, [])
        self.assertEqual(store.latest_behavior()["handlers"], [])

    def test_shared_cache_pending_suppresses_duplicate_generation(self) -> None:
        store = MemoryStore()
        generator = StaticGenerator(delay=0.05)
        first = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(store, enabled=False),
        )
        second = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(store, enabled=False),
        )
        event = {
            "event_type": EVENT_COMMAND_MISSED,
            "session_id": "session-cache-1",
            "sequence_index": 1,
            "sequence_hash": "cache",
            "payload": {
                "command": "systemctl",
                "argv": ["status", "ssh"],
                "prior_sequence": [
                    {"command": "id", "argv": [], "cwd": "/root", "index": 1}
                ],
            },
        }
        first_result = first.receive_event(event)
        second_result = second.receive_event({**event, "session_id": "session-cache-2"})
        self.assertEqual(first_result["cache_status"], "miss")
        self.assertEqual(second_result["cache_status"], "pending")
        self.assertFalse(second_result["queued"])
        for _attempt in range(50):
            if generator.calls == 1 and store.latest_behavior()["handlers"]:
                break
            time.sleep(0.01)
        self.assertEqual(generator.calls, 1)

    def test_repeated_valid_miss_uses_cache_pending_not_duplicate_skip(self) -> None:
        store = MemoryStore()
        generator = StaticGenerator(delay=0.05)
        sidecar = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(store, enabled=False),
        )
        event = {
            "event_type": EVENT_COMMAND_MISSED,
            "session_id": "session-repeat-1",
            "sequence_index": 1,
            "sequence_hash": "repeat",
            "payload": {
                "command": "ss",
                "argv": ["-tupln"],
                "prior_sequence": [],
            },
        }
        first_result = sidecar.receive_event(event)
        second_result = sidecar.receive_event({**event, "session_id": "session-repeat-2"})
        self.assertEqual(first_result["cache_status"], "miss")
        self.assertEqual(second_result["cache_status"], "pending")
        self.assertEqual(second_result["status"], "cache_pending")

    def test_published_spec_is_normalized_after_validation(self) -> None:
        store = MemoryStore()
        sidecar = AdaptiveSidecar(
            store,
            generator=ScalarStateGenerator(),
            rag_retriever=RagRetriever(store, enabled=False),
        )
        sidecar.receive_event(
            {
                "event_type": EVENT_COMMAND_MISSED,
                "session_id": "session-normalize-1",
                "sequence_index": 1,
                "sequence_hash": "normalize",
                "payload": {
                    "command": "ss",
                    "argv": ["-tulpn"],
                    "prior_sequence": [],
                },
            }
        )
        for _attempt in range(50):
            if store.latest_behavior()["handlers"]:
                break
            time.sleep(0.01)
        handler = store.latest_behavior()["handlers"][0]
        self.assertEqual(
            handler["state_effects"],
            {"query_count": "2", "has_snapshot": "True"},
        )

    def test_narrows_generated_spec_that_does_not_match_triggering_argv(self) -> None:
        store = MemoryStore()
        sidecar = AdaptiveSidecar(
            store,
            generator=BadMatcherGenerator(),
            rag_retriever=RagRetriever(store, enabled=False),
        )
        sidecar.receive_event(
            {
                "event_type": EVENT_COMMAND_MISSED,
                "session_id": "session-bad-match-1",
                "sequence_index": 1,
                "sequence_hash": "bad-match",
                "payload": {
                    "command": "ss",
                    "argv": [],
                    "prior_sequence": [],
                },
            }
        )
        for _attempt in range(50):
            if store.latest_behavior()["handlers"]:
                break
            time.sleep(0.01)
        handlers = store.latest_behavior()["handlers"]
        self.assertEqual(len(handlers), 1)
        self.assertEqual(handlers[0]["argv_match"], {"mode": "exact", "patterns": []})
        self.assertEqual(store.patch_attempts[-1]["status"], "accepted")

    def test_cache_hit_avoids_llm_call_for_new_sidecar_instance(self) -> None:
        store = MemoryStore()
        generator = StaticGenerator()
        sidecar = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(store, enabled=False),
        )
        event = {
            "event_type": EVENT_COMMAND_MISSED,
            "session_id": "session-cache-hit-1",
            "sequence_index": 1,
            "sequence_hash": "cache-hit",
            "payload": {
                "command": "systemctl",
                "argv": ["status", "ssh"],
                "prior_sequence": [],
            },
        }
        sidecar.receive_event(event)
        for _attempt in range(50):
            if store.latest_behavior()["handlers"]:
                break
            time.sleep(0.01)
        second = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(store, enabled=False),
        )
        result = second.receive_event({**event, "session_id": "session-cache-hit-2"})
        self.assertEqual(result["cache_status"], "hit")
        self.assertEqual(generator.calls, 1)

    def test_waiting_miss_returns_generated_spec(self) -> None:
        store = MemoryStore()
        generator = StaticGenerator()
        sidecar = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(store, enabled=False),
        )
        result = sidecar.receive_event(
            {
                "event_type": EVENT_COMMAND_MISSED,
                "session_id": "session-wait-1",
                "sequence_index": 1,
                "sequence_hash": "wait",
                "payload": {
                    "command": "lsof",
                    "argv": ["-i"],
                    "prior_sequence": [],
                },
            },
            wait=True,
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["spec"]["command"], "lsof")
        self.assertEqual(generator.calls, 1)

    def test_rag_context_is_injected_into_generation_prompt(self) -> None:
        store = MemoryStore()
        source_id = store.add_rag_source("unit", "test")
        store.add_rag_chunk(
            source_id,
            "systemctl status ssh shows Loaded and Active fields.",
            [1.0, 0.0],
            {"command": "systemctl"},
        )
        generator = StaticGenerator()
        sidecar = AdaptiveSidecar(
            store,
            generator=generator,
            rag_retriever=RagRetriever(
                store,
                embedding_client=FakeEmbeddingClient([1.0, 0.0]),
            ),
        )
        sidecar.receive_event(
            {
                "event_type": EVENT_COMMAND_MISSED,
                "session_id": "session-rag-1",
                "sequence_index": 1,
                "sequence_hash": "rag",
                "payload": {
                    "command": "systemctl",
                    "argv": ["status", "ssh"],
                    "prior_sequence": [],
                },
            }
        )
        for _attempt in range(50):
            if generator.rag_contexts:
                break
            time.sleep(0.01)
        self.assertIn("systemctl status ssh", generator.rag_contexts[0])
        self.assertEqual(store.rag_queries[0]["chunk_ids"], [1])

    def test_debug_rag_returns_store_stats(self) -> None:
        store = MemoryStore()
        source_id = store.add_rag_source("unit", "test")
        store.add_rag_chunk(source_id, "ss lists sockets", [1.0], {"command": "ss"})
        sidecar = AdaptiveSidecar(
            store,
            generator=StaticGenerator(),
            rag_retriever=RagRetriever(store, enabled=False),
        )
        stats = sidecar.debug_rag()
        self.assertEqual(stats["sources"], 1)
        self.assertEqual(stats["chunks"], 1)
        self.assertEqual(stats["queries"], 0)


if __name__ == "__main__":
    unittest.main()
