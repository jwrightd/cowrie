# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

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

    def send_event(self, event: dict) -> None:
        self.events.append(event)

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


if __name__ == "__main__":
    unittest.main()
