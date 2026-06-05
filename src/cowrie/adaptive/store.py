# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import math
import threading
from typing import Any

from cowrie.adaptive.rag import RagChunk


class MemoryStore:
    """Small local store for tests and sidecar dry runs."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.patch_attempts: list[dict[str, Any]] = []
        self.behavior_specs: list[dict[str, Any]] = []
        self.handler_cache: dict[str, dict[str, Any]] = {}
        self.rag_sources: list[dict[str, Any]] = []
        self.rag_chunks: list[dict[str, Any]] = []
        self.rag_queries: list[dict[str, Any]] = []
        self.frozen = False
        self._lock = threading.Lock()

    def store_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def record_patch_attempt(self, attempt: dict[str, Any]) -> None:
        self.patch_attempts.append(attempt)

    def publish_behavior_spec(
        self, spec: dict[str, Any], cache_key: str | None = None
    ) -> int:
        version = len(self.behavior_specs) + 1
        spec = {**spec, "id": version, "version": version, "status": "active"}
        self.behavior_specs.append(spec)
        if cache_key:
            with self._lock:
                cache_entry = self.handler_cache.get(cache_key, {})
                cache_entry.update(
                    {
                        "cache_key": cache_key,
                        "status": "active",
                        "behavior_spec_id": version,
                        "failure_reason": None,
                    }
                )
                self.handler_cache[cache_key] = cache_entry
        return version

    def latest_behavior(self, since_version: int = 0) -> dict[str, Any]:
        handlers = [
            spec
            for spec in self.behavior_specs
            if spec.get("status") == "active"
            and int(spec.get("version", 0)) > since_version
        ]
        return {
            "version": len(self.behavior_specs),
            "frozen": self.frozen,
            "handlers": handlers,
            "retired_handler_ids": [],
        }

    def freeze(self) -> None:
        self.frozen = True

    def claim_handler_cache(
        self, cache_key: str, command: str, argv_fingerprint: str
    ) -> dict[str, Any]:
        with self._lock:
            entry = self.handler_cache.get(cache_key)
            if entry:
                if entry.get("status") == "active":
                    entry["hit_count"] = int(entry.get("hit_count", 0)) + 1
                    return {**entry, "cache_status": "hit"}
                if entry.get("status") == "pending":
                    return {**entry, "cache_status": "pending"}
            entry = {
                "cache_key": cache_key,
                "command": command,
                "argv_fingerprint": argv_fingerprint,
                "status": "pending",
                "behavior_spec_id": None,
                "hit_count": 0,
            }
            self.handler_cache[cache_key] = entry
            return {**entry, "cache_status": "miss"}

    def mark_handler_cache_failed(self, cache_key: str, reason: str) -> None:
        with self._lock:
            entry = self.handler_cache.get(cache_key)
            if not entry:
                return
            entry["status"] = "failed"
            entry["failure_reason"] = reason

    def add_rag_source(
        self, name: str, source_type: str, version: str = "", uri: str = ""
    ) -> int:
        for source in self.rag_sources:
            if (
                source["name"] == name
                and source["source_type"] == source_type
                and source["version"] == version
                and source["uri"] == uri
            ):
                return int(source["id"])
        source_id = len(self.rag_sources) + 1
        self.rag_sources.append(
            {
                "id": source_id,
                "name": name,
                "source_type": source_type,
                "version": version,
                "uri": uri,
            }
        )
        return source_id

    def add_rag_chunk(
        self,
        source_id: int,
        chunk_text: str,
        embedding: list[float],
        metadata: dict[str, Any] | None = None,
    ) -> int:
        metadata = metadata or {}
        for chunk in self.rag_chunks:
            if (
                chunk["source_id"] == source_id
                and chunk["chunk_text"] == chunk_text
                and chunk["metadata"] == metadata
            ):
                return int(chunk["id"])
        chunk_id = len(self.rag_chunks) + 1
        self.rag_chunks.append(
            {
                "id": chunk_id,
                "source_id": source_id,
                "chunk_text": chunk_text,
                "embedding": embedding,
                "metadata": metadata,
            }
        )
        return chunk_id

    def search_rag_chunks(self, embedding: list[float], limit: int) -> list[RagChunk]:
        scored = []
        for chunk in self.rag_chunks:
            score = _cosine_similarity(embedding, chunk["embedding"])
            scored.append((score, chunk))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            RagChunk(
                chunk_id=chunk["id"],
                text=chunk["chunk_text"],
                metadata=chunk["metadata"],
                score=score,
            )
            for score, chunk in scored[:limit]
        ]

    def record_rag_query(
        self,
        session_id: str | None,
        query_text: str,
        chunk_ids: list[int],
        scores: list[float],
        metadata: dict[str, Any],
    ) -> None:
        self.rag_queries.append(
            {
                "session_id": session_id,
                "query_text": query_text,
                "chunk_ids": chunk_ids,
                "scores": scores,
                "metadata": metadata,
            }
        )

    def rag_stats(self) -> dict[str, Any]:
        return {
            "sources": len(self.rag_sources),
            "chunks": len(self.rag_chunks),
            "queries": len(self.rag_queries),
            "recent_queries": self.rag_queries[-5:],
        }


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
                     generated_spec, validator_failures, retry_count, status,
                     cache_key, cache_status, rag_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    attempt.get("session_id"),
                    attempt.get("sanitized_input_hash"),
                    self._extras.Json(attempt.get("prompt_metadata", {})),
                    self._extras.Json(attempt.get("generated_spec")),
                    self._extras.Json(attempt.get("validator_failures", [])),
                    attempt.get("retry_count", 0),
                    attempt.get("status", "queued"),
                    attempt.get("cache_key"),
                    attempt.get("cache_status"),
                    attempt.get("rag_status", "not_requested"),
                ),
            )

    def publish_behavior_spec(
        self, spec: dict[str, Any], cache_key: str | None = None
    ) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM adaptive.behavior_specs"
            )
            version = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO adaptive.behavior_specs
                    (version, command, spec, status, validation_result)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    version,
                    spec.get("command", ""),
                    self._extras.Json(spec),
                    "active",
                    self._extras.Json({"result": "accepted"}),
                ),
            )
            row_id = cur.fetchone()[0]
            if cache_key:
                cur.execute(
                    """
                    UPDATE adaptive.handler_cache
                    SET status = 'active',
                        behavior_spec_id = %s,
                        failure_reason = NULL,
                        updated_at = now()
                    WHERE cache_key = %s
                    """,
                    (row_id, cache_key),
                )
            return version

    def latest_behavior(self, since_version: int = 0) -> dict[str, Any]:
        with self.conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, version, spec
                FROM adaptive.behavior_specs
                WHERE status = 'active'
                  AND version > %s
                ORDER BY version ASC
                """,
                (since_version,),
            )
            rows = cur.fetchall()
            cur.execute(
                """
                SELECT id
                FROM adaptive.behavior_specs
                WHERE status = 'retired'
                  AND version > %s
                ORDER BY version ASC
                """,
                (since_version,),
            )
            retired_rows = cur.fetchall()
        handlers = [
            dict(row["spec"], id=row["id"], version=row["version"]) for row in rows
        ]
        version = self._latest_behavior_version()
        return {
            "version": version,
            "frozen": self.frozen,
            "handlers": handlers,
            "retired_handler_ids": [int(row["id"]) for row in retired_rows],
        }

    def freeze(self) -> None:
        self.frozen = True

    def claim_handler_cache(
        self, cache_key: str, command: str, argv_fingerprint: str
    ) -> dict[str, Any]:
        with self.conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO adaptive.handler_cache
                    (cache_key, command, argv_fingerprint, status)
                VALUES (%s, %s, %s, 'pending')
                ON CONFLICT (cache_key) DO NOTHING
                """,
                (cache_key, command, argv_fingerprint),
            )
            inserted = cur.rowcount == 1
            cur.execute(
                """
                SELECT cache_key, command, argv_fingerprint, status,
                       behavior_spec_id, hit_count
                FROM adaptive.handler_cache
                WHERE cache_key = %s
                """,
                (cache_key,),
            )
            entry = dict(cur.fetchone())
            if inserted:
                entry["cache_status"] = "miss"
                return entry
            if entry.get("status") == "active":
                cur.execute(
                    """
                    UPDATE adaptive.handler_cache
                    SET hit_count = hit_count + 1,
                        last_hit_at = now(),
                        updated_at = now()
                    WHERE cache_key = %s
                    """,
                    (cache_key,),
                )
                entry["hit_count"] = int(entry.get("hit_count", 0)) + 1
                entry["cache_status"] = "hit"
                return entry
            if entry.get("status") == "pending":
                entry["cache_status"] = "pending"
                return entry
            cur.execute(
                """
                UPDATE adaptive.handler_cache
                SET status = 'pending',
                    behavior_spec_id = NULL,
                    failure_reason = NULL,
                    updated_at = now()
                WHERE cache_key = %s
                """,
                (cache_key,),
            )
            entry["status"] = "pending"
            entry["cache_status"] = "miss"
            return entry

    def mark_handler_cache_failed(self, cache_key: str, reason: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                UPDATE adaptive.handler_cache
                SET status = 'failed',
                    failure_reason = %s,
                    updated_at = now()
                WHERE cache_key = %s
                """,
                (reason, cache_key),
            )

    def add_rag_source(
        self, name: str, source_type: str, version: str = "", uri: str = ""
    ) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM adaptive.rag_sources
                WHERE name = %s
                  AND source_type = %s
                  AND version = %s
                  AND uri = %s
                """,
                (name, source_type, version, uri),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
            cur.execute(
                """
                INSERT INTO adaptive.rag_sources (name, source_type, version, uri)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (name, source_type, version, uri),
            )
            return int(cur.fetchone()[0])

    def add_rag_chunk(
        self,
        source_id: int,
        chunk_text: str,
        embedding: list[float],
        metadata: dict[str, Any] | None = None,
    ) -> int:
        metadata = metadata or {}
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM adaptive.rag_chunks
                WHERE source_id = %s
                  AND chunk_text = %s
                  AND metadata = %s::jsonb
                """,
                (source_id, chunk_text, self._extras.Json(metadata)),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
            cur.execute(
                """
                INSERT INTO adaptive.rag_chunks
                    (source_id, chunk_text, metadata, embedding)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (
                    source_id,
                    chunk_text,
                    self._extras.Json(metadata),
                    self._extras.Json([float(value) for value in embedding]),
                ),
            )
            return int(cur.fetchone()[0])

    def search_rag_chunks(self, embedding: list[float], limit: int) -> list[RagChunk]:
        with self.conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, chunk_text, metadata, embedding
                FROM adaptive.rag_chunks
                """
            )
            rows = cur.fetchall()
        scored = []
        for row in rows:
            row_embedding = row["embedding"]
            if not isinstance(row_embedding, list):
                continue
            score = _cosine_similarity(embedding, [float(v) for v in row_embedding])
            scored.append(
                RagChunk(
                    chunk_id=int(row["id"]),
                    text=row["chunk_text"],
                    metadata=dict(row["metadata"]),
                    score=score,
                )
            )
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:limit]

    def record_rag_query(
        self,
        session_id: str | None,
        query_text: str,
        chunk_ids: list[int],
        scores: list[float],
        metadata: dict[str, Any],
    ) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO adaptive.rag_queries
                    (session_id, query_text, retrieved_chunk_ids,
                     similarity_scores, metadata)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    session_id,
                    query_text,
                    self._extras.Json(chunk_ids),
                    self._extras.Json(scores),
                    self._extras.Json(metadata),
                ),
            )

    def rag_stats(self) -> dict[str, Any]:
        with self.conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                  (SELECT count(*) FROM adaptive.rag_sources) AS sources,
                  (SELECT count(*) FROM adaptive.rag_chunks) AS chunks,
                  (SELECT count(*) FROM adaptive.rag_queries) AS queries
                """
            )
            counts = dict(cur.fetchone())
            cur.execute(
                """
                SELECT id, session_id, query_text, retrieved_chunk_ids,
                       similarity_scores, metadata, created_at
                FROM adaptive.rag_queries
                ORDER BY created_at DESC
                LIMIT 5
                """
            )
            recent = []
            for row in cur.fetchall():
                item = dict(row)
                created_at = item.get("created_at")
                if hasattr(created_at, "isoformat"):
                    item["created_at"] = created_at.isoformat()
                recent.append(item)
        return {
            "sources": int(counts["sources"]),
            "chunks": int(counts["chunks"]),
            "queries": int(counts["queries"]),
            "recent_queries": recent,
        }

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

    def _latest_behavior_version(self) -> int:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM adaptive.behavior_specs")
            return int(cur.fetchone()[0])


def dumps_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True).encode("utf-8")


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)
