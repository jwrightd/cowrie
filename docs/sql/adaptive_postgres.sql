-- SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

CREATE SCHEMA IF NOT EXISTS adaptive;

CREATE TABLE IF NOT EXISTS adaptive.sensors (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  honeypot TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS adaptive.sessions (
  id TEXT PRIMARY KEY,
  sensor_id INTEGER NOT NULL REFERENCES adaptive.sensors(id),
  protocol TEXT NOT NULL,
  src_ip TEXT,
  client_fingerprint TEXT,
  started_at TIMESTAMPTZ NOT NULL,
  ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS adaptive.attack_events (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES adaptive.sessions(id),
  event_type TEXT NOT NULL,
  sequence_index INTEGER NOT NULL,
  sequence_hash TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS attack_events_session_index
  ON adaptive.attack_events(session_id, sequence_index);
CREATE INDEX IF NOT EXISTS attack_events_payload_gin
  ON adaptive.attack_events USING GIN(payload);

CREATE TABLE IF NOT EXISTS adaptive.attack_sequences (
  session_id TEXT PRIMARY KEY REFERENCES adaptive.sessions(id),
  sequence_hash TEXT NOT NULL,
  commands JSONB NOT NULL,
  miss_count INTEGER NOT NULL DEFAULT 0,
  novelty_score REAL NOT NULL DEFAULT 0,
  triage_status TEXT NOT NULL DEFAULT 'observed',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS adaptive.command_misses (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES adaptive.sessions(id),
  command TEXT NOT NULL,
  argv JSONB NOT NULL,
  cwd TEXT NOT NULL,
  env JSONB NOT NULL,
  prior_sequence_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS command_misses_command_index
  ON adaptive.command_misses(command, created_at);

CREATE TABLE IF NOT EXISTS adaptive.behavior_specs (
  id BIGSERIAL PRIMARY KEY,
  version INTEGER NOT NULL,
  command TEXT NOT NULL,
  spec JSONB NOT NULL,
  status TEXT NOT NULL,
  source_miss_id BIGINT REFERENCES adaptive.command_misses(id),
  validation_result JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS behavior_specs_active_index
  ON adaptive.behavior_specs(status, version);

CREATE TABLE IF NOT EXISTS adaptive.patch_attempts (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT REFERENCES adaptive.sessions(id),
  sanitized_input_hash TEXT NOT NULL,
  prompt_metadata JSONB NOT NULL,
  generated_spec JSONB,
  validator_failures JSONB NOT NULL DEFAULT '[]'::jsonb,
  retry_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
