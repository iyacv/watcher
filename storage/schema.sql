-- SQLite schema. Auto-created by setup.bat, or run manually:
--   sqlite3 capstone.db < storage/schema.sql

-- ── F5 vulnerabilities ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host        TEXT NOT NULL,
  port        INTEGER,
  vuln_id     TEXT NOT NULL,
  name        TEXT,
  severity    TEXT NOT NULL DEFAULT 'low'
              CHECK(severity IN ('critical','high','medium','low','info')),
  cvss        REAL,
  description TEXT,
  remediation TEXT,
  detected_at TEXT NOT NULL,
  raw_hash    TEXT NOT NULL UNIQUE,
  status      TEXT NOT NULL DEFAULT 'open'
              CHECK(status IN ('open','resolved')),
  aged        INTEGER NOT NULL DEFAULT 0,
  source_file TEXT,
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vuln_host_severity ON vulnerabilities(host, severity);
CREATE INDEX IF NOT EXISTS idx_vuln_detected_at   ON vulnerabilities(detected_at);
CREATE INDEX IF NOT EXISTS idx_vuln_vuln_id       ON vulnerabilities(vuln_id);

-- ── Log360 events ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host        TEXT NOT NULL,
  event_id    TEXT,
  event_type  TEXT,
  severity    TEXT NOT NULL DEFAULT 'low'
              CHECK(severity IN ('critical','high','medium','low','info')),
  user        TEXT,
  description TEXT,
  detected_at TEXT NOT NULL,
  raw_hash    TEXT NOT NULL UNIQUE,
  source_file TEXT,
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_event_host        ON events(host);
CREATE INDEX IF NOT EXISTS idx_event_event_type  ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_event_detected_at ON events(detected_at);

-- ── Correlations (F5 vuln + Log360 event on same host) ───────────────────────
CREATE TABLE IF NOT EXISTS correlations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host        TEXT NOT NULL,
  vuln_id     TEXT,
  event_id    TEXT,
  event_type  TEXT,
  vuln_time   TEXT,
  event_time  TEXT,
  severity    TEXT NOT NULL DEFAULT 'high'
              CHECK(severity IN ('critical','high','medium','low','info')),
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(host, vuln_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_corr_host     ON correlations(host);
CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlations(severity);
