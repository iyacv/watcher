-- Postgres schema for the hosted/cloud variant.
-- Mirrors schema.sql but uses Postgres types and constraints.

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          BIGSERIAL PRIMARY KEY,
  host        TEXT NOT NULL,
  url         TEXT,
  name        TEXT NOT NULL,
  attack_type TEXT,
  cookie      TEXT,
  severity    TEXT NOT NULL DEFAULT 'low'
              CHECK (severity IN ('critical','high','medium','low','info')),
  cvss        REAL,
  status      TEXT NOT NULL DEFAULT 'open'
              CHECK (status IN ('open','resolved')),
  detected_at TIMESTAMPTZ NOT NULL,
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  raw_hash    TEXT NOT NULL UNIQUE,
  aged        BOOLEAN NOT NULL DEFAULT FALSE,
  source_file TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vulnerability_changes (
  id           BIGSERIAL PRIMARY KEY,
  vuln_hash    TEXT NOT NULL,
  host         TEXT NOT NULL,
  name         TEXT NOT NULL,
  old_severity TEXT NOT NULL,
  new_severity TEXT NOT NULL,
  changed_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vuln_changes_hash       ON vulnerability_changes(vuln_hash);
CREATE INDEX IF NOT EXISTS idx_vuln_changes_changed_at ON vulnerability_changes(changed_at);
CREATE INDEX IF NOT EXISTS idx_vuln_host_severity ON vulnerabilities(host, severity);
CREATE INDEX IF NOT EXISTS idx_vuln_detected_at   ON vulnerabilities(detected_at);
CREATE INDEX IF NOT EXISTS idx_vuln_host_url      ON vulnerabilities(host, url);

CREATE TABLE IF NOT EXISTS events (
  id          BIGSERIAL PRIMARY KEY,
  host        TEXT NOT NULL,
  event_id    TEXT,
  event_type  TEXT,
  severity    TEXT NOT NULL DEFAULT 'information'
              CHECK (severity IN ('error','failure','warning','information','success')),
  "user"       TEXT,
  display_name TEXT,
  detected_at TIMESTAMPTZ NOT NULL,
  raw_hash    TEXT NOT NULL UNIQUE,
  source_file TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_event_host        ON events(host);
CREATE INDEX IF NOT EXISTS idx_event_event_type  ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_event_detected_at ON events(detected_at);

CREATE TABLE IF NOT EXISTS correlations (
  id          BIGSERIAL PRIMARY KEY,
  host        TEXT NOT NULL,
  vuln_id     TEXT,
  event_id    TEXT,
  event_type  TEXT,
  vuln_time   TIMESTAMPTZ,
  event_time  TIMESTAMPTZ,
  severity    TEXT NOT NULL DEFAULT 'high'
              CHECK (severity IN ('critical','high','medium','low','info')),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (host, vuln_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_corr_host     ON correlations(host);
CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlations(severity);
