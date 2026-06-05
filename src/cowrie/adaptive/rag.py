# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import os
import hashlib
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
_DEFAULT_EMBEDDING_DIMENSION = 384
_DEFAULT_TOP_K = 5
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:/+-]+")


class EmbeddingError(RuntimeError):
    pass


class EmbeddingClient:
    def __init__(self) -> None:
        env_provider = os.environ.get("ADAPTIVE_EMBEDDING_PROVIDER", "").lower()
        has_key = bool(
            os.environ.get("ADAPTIVE_EMBEDDING_API_KEY") or os.environ.get("HF_TOKEN")
        )
        self.provider = env_provider or ("huggingface" if has_key else "local")
        default_model = (
            "local-hash-384"
            if self.provider == "local"
            else _DEFAULT_EMBEDDING_MODEL
        )
        self.model = os.environ.get("ADAPTIVE_EMBEDDING_MODEL", default_model)
        self.api_key = os.environ.get("ADAPTIVE_EMBEDDING_API_KEY") or os.environ.get(
            "HF_TOKEN", ""
        )
        self.url = os.environ.get(
            "ADAPTIVE_EMBEDDING_URL",
            "https://router.huggingface.co/hf-inference/models/"
            f"{self.model}/pipeline/feature-extraction",
        )
        self.timeout = float(os.environ.get("ADAPTIVE_EMBEDDING_TIMEOUT", "30"))
        self.dimension = int(
            os.environ.get("ADAPTIVE_EMBEDDING_DIMENSION", str(_DEFAULT_EMBEDDING_DIMENSION))
        )

    def configured(self) -> bool:
        if self.provider == "local":
            return True
        return bool(self.api_key and self.url and self.model)

    def embed(self, text: str) -> list[float]:
        if self.provider == "local":
            return _local_embedding(text, self.dimension)
        if not self.configured():
            raise EmbeddingError("adaptive embedding model is not configured")
        request = urllib.request.Request(
            self.url,
            data=json.dumps({"inputs": text, "options": {"wait_for_model": True}}).encode(
                "utf-8"
            ),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        embedding = _coerce_embedding(payload)
        if len(embedding) != self.dimension:
            raise EmbeddingError(
                f"embedding dimension {len(embedding)} did not match {self.dimension}"
            )
        return embedding


@dataclass(frozen=True)
class RagChunk:
    chunk_id: int
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0


@dataclass(frozen=True)
class RagResult:
    status: str
    query: str
    chunks: list[RagChunk] = field(default_factory=list)
    error: str = ""
    model: str = ""

    def prompt_context(self) -> str:
        if not self.chunks:
            return ""
        parts = []
        for index, chunk in enumerate(self.chunks, start=1):
            metadata = json.dumps(chunk.metadata, sort_keys=True)
            parts.append(
                f"[RAG {index} score={chunk.score:.3f} metadata={metadata}]\n"
                f"{chunk.text}"
            )
        return "\n\n".join(parts)

    def metadata(self) -> dict[str, Any]:
        return {
            "rag_status": self.status,
            "rag_model": self.model,
            "rag_query": self.query,
            "rag_chunk_ids": [chunk.chunk_id for chunk in self.chunks],
            "rag_scores": [chunk.score for chunk in self.chunks],
            "rag_error": self.error,
        }


class RagRetriever:
    def __init__(
        self,
        store: Any,
        embedding_client: EmbeddingClient | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.store = store
        self.embedding_client = embedding_client or EmbeddingClient()
        if enabled is None:
            enabled = os.environ.get("ADAPTIVE_RAG_ENABLED", "true").lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
        self.enabled = enabled
        self.top_k = int(os.environ.get("ADAPTIVE_RAG_TOP_K", str(_DEFAULT_TOP_K)))

    def retrieve(self, event: dict[str, Any]) -> RagResult:
        query = build_rag_query(event.get("payload", {}))
        if not self.enabled:
            return RagResult("disabled", query, model=self.embedding_client.model)
        if not self.embedding_client.configured():
            return RagResult("not_configured", query, model=self.embedding_client.model)
        try:
            embedding = self.embedding_client.embed(query)
            chunks = self.store.search_rag_chunks(embedding, self.top_k)
            self.store.record_rag_query(
                event.get("session_id"),
                query,
                [chunk.chunk_id for chunk in chunks],
                [chunk.score for chunk in chunks],
                {"model": self.embedding_client.model},
            )
            return RagResult(
                "ok" if chunks else "empty",
                query,
                chunks,
                model=self.embedding_client.model,
            )
        except Exception as e:
            return RagResult("failed", query, error=repr(e), model=self.embedding_client.model)


def build_rag_query(payload: dict[str, Any]) -> str:
    prior_sequence = payload.get("prior_sequence", [])
    commands = []
    for item in prior_sequence[-10:]:
        command = item.get("command", "")
        argv = " ".join(item.get("argv", []))
        commands.append(f"{command} {argv}".strip())
    return "\n".join(
        [
            f"missed command: {payload.get('command', '')}",
            f"argv: {' '.join(payload.get('argv', []))}",
            f"cwd: {payload.get('cwd', '')}",
            f"env summary: {json.dumps(payload.get('env', {}), sort_keys=True)}",
            "prior sequence:",
            *commands,
        ]
    )


def _coerce_embedding(payload: Any) -> list[float]:
    if isinstance(payload, dict) and "embedding" in payload:
        payload = payload["embedding"]
    if isinstance(payload, dict) and "data" in payload:
        data = payload["data"]
        if isinstance(data, list) and data and isinstance(data[0], dict):
            payload = data[0].get("embedding")
    if (
        isinstance(payload, list)
        and payload
        and isinstance(payload[0], list)
        and payload[0]
        and isinstance(payload[0][0], list)
    ):
        payload = payload[0]
    if isinstance(payload, list) and payload and isinstance(payload[0], list):
        rows = payload
        width = len(rows[0])
        return [
            float(sum(float(row[col]) for row in rows) / len(rows))
            for col in range(width)
        ]
    if isinstance(payload, list) and all(isinstance(item, (int, float)) for item in payload):
        return [float(item) for item in payload]
    raise EmbeddingError("unexpected embedding response shape")


def _local_embedding(text: str, dimension: int) -> list[float]:
    vector = [0.0] * dimension
    tokens = _TOKEN_RE.findall(text.lower())
    if not tokens:
        return vector
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dimension
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[index] += sign
    norm = sum(value * value for value in vector) ** 0.5
    if norm == 0:
        return vector
    return [value / norm for value in vector]
