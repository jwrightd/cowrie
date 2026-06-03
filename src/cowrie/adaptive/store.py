# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
from typing import Any


class MemoryStore:
    """Small local store for tests and sidecar dry runs."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.patch_attempts: list[dict[str, Any]] = []
        self.behavior_specs: list[dict[str, Any]] = []
        self.frozen = False

    def store_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def record_patch_attempt(self, attempt: dict[str, Any]) -> None:
        self.patch_attempts.append(attempt)

    def publish_behavior_spec(self, spec: dict[str, Any]) -> int:
        version = len(self.behavior_specs) + 1
        spec = {**spec, "version": version, "status": "active"}
        self.behavior_specs.append(spec)
        return version

    def latest_behavior(self) -> dict[str, Any]:
        return {
            "version": len(self.behavior_specs),
            "frozen": self.frozen,
            "handlers": list(self.behavior_specs),
        }

    def freeze(self) -> None:
        self.frozen = True


class PostgresStore:
    """Postgres-backed adaptive store.

    psycopg2 is imported lazily so Cowrie can run without the optional output
    dependency installed.
    """

    def __init__(self, dsn: str) -> None:
        import psycopg2
        import psycopg2.extras

        self._extras = psycopg2.extras
        self.conn = psycopg2.connect(dsn)
        self.conn.autocommit = True
        self.frozen = False

    def store_event(self, event: dict[str, Any]) -> None:
        with self.conn.cursor() as cur:
            sensor_id = self._ensure_sensor(cur, event.get("sensor_id", "unknown"))
            self._ensure_session(cur, event, sensor_id)
            cur.execute(
                """
                INSERT INTO adaptive.attack_events
                    (session_id, event_type, sequence_index, sequence_hash, payload)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    event["session_id"],
                    event["event_type"],
                    event.get("sequence_index", 0),
                    event.get("sequence_hash", ""),
                    self._extras.Json(event.get("payload", {})),
                ),
            )
            if event["event_type"] == "command_missed":
                payload = event.get("payload", {})
                cur.execute(
                    """
                    INSERT INTO adaptive.command_misses
                        (session_id, command, argv, cwd, env, prior_sequence_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event["session_id"],
                        payload.get("command", ""),
                        self._extras.Json(payload.get("argv", [])),
                        payload.get("cwd", ""),
                        self._extras.Json(payload.get("env", {})),
                        event.get("sequence_hash", ""),
                    ),
                )
            self._upsert_sequence(cur, event)

    def record_patch_attempt(self, attempt: dict[str, Any]) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO adaptive.patch_attempts
                    (session_id, sanitized_input_hash, prompt_metadata,
                     generated_spec, validator_failures, retry_count, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    attempt.get("session_id"),
                    attempt.get("sanitized_input_hash"),
                    self._extras.Json(attempt.get("prompt_metadata", {})),
                    self._extras.Json(attempt.get("generated_spec")),
                    self._extras.Json(attempt.get("validator_failures", [])),
                    attempt.get("retry_count", 0),
                    attempt.get("status", "queued"),
                ),
            )

    def publish_behavior_spec(self, spec: dict[str, Any]) -> int:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM adaptive.behavior_specs")
            version = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO adaptive.behavior_specs
                    (version, command, spec, status, validation_result)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    version,
                    spec.get("command", ""),
                    self._extras.Json(spec),
                    "active",
                    self._extras.Json({"result": "accepted"}),
                ),
            )
            return version

    def latest_behavior(self) -> dict[str, Any]:
        with self.conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT version, spec
                FROM adaptive.behavior_specs
                WHERE status = 'active'
                ORDER BY version ASC
                """
            )
            rows = cur.fetchall()
        handlers = [dict(row["spec"], version=row["version"]) for row in rows]
        version = max([row["version"] for row in rows], default=0)
        return {"version": version, "frozen": self.frozen, "handlers": handlers}

    def freeze(self) -> None:
        self.frozen = True

    def _ensure_sensor(self, cur: Any, sensor_name: str) -> int:
        cur.execute("SELECT id FROM adaptive.sensors WHERE name = %s", (sensor_name,))
        row = cur.fetchone()
        if row:
            return int(row[0])
        cur.execute(
            "INSERT INTO adaptive.sensors (name, honeypot) VALUES (%s, %s) RETURNING id",
            (sensor_name, "cowrie"),
        )
        return int(cur.fetchone()[0])

    def _ensure_session(self, cur: Any, event: dict[str, Any], sensor_id: int) -> None:
        payload = event.get("payload", {})
        cur.execute(
            """
            INSERT INTO adaptive.sessions
                (id, sensor_id, protocol, src_ip, started_at)
            VALUES (%s, %s, %s, %s, to_timestamp(%s))
            ON CONFLICT (id) DO NOTHING
            """,
            (
                event["session_id"],
                sensor_id,
                payload.get("protocol", "unknown"),
                payload.get("src_ip", ""),
                event.get("timestamp", 0),
            ),
        )
        if event["event_type"] == "session_ended":
            cur.execute(
                "UPDATE adaptive.sessions SET ended_at = to_timestamp(%s) WHERE id = %s",
                (event.get("timestamp", 0), event["session_id"]),
            )

    def _upsert_sequence(self, cur: Any, event: dict[str, Any]) -> None:
        payload = event.get("payload", {})
        commands = payload.get("commands") or payload.get("prior_sequence") or []
        miss_count = 1 if event["event_type"] == "command_missed" else 0
        cur.execute(
            """
            INSERT INTO adaptive.attack_sequences
                (session_id, sequence_hash, commands, miss_count, triage_status)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (session_id) DO UPDATE SET
                sequence_hash = EXCLUDED.sequence_hash,
                commands = EXCLUDED.commands,
                miss_count = attack_sequences.miss_count + EXCLUDED.miss_count,
                updated_at = now()
            """,
            (
                event["session_id"],
                event.get("sequence_hash", ""),
                self._extras.Json(commands),
                miss_count,
                "observed",
            ),
        )


def dumps_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True).encode("utf-8")
