-- SQLite schema. Auto-created by setup.bat, or run manually:
--   sqlite3 capstone.db < storage/schema.sql

-- ── F5 vulnerabilities (matches real scanner XML <scanner_vulnerabilities>) ──
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host        TEXT NOT NULL,
  url         TEXT,
  name        TEXT NOT NULL,
  attack_type TEXT,
  cookie      TEXT,
  severity    TEXT NOT NULL DEFAULT 'low'
              CHECK(severity IN ('critical','high','medium','low','info')),
  cvss        REAL,
  status      TEXT NOT NULL DEFAULT 'open'
              CHECK(status IN ('open','resolved')),
  detected_at TEXT NOT NULL,
  last_seen   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  raw_hash    TEXT NOT NULL UNIQUE,
  aged        INTEGER NOT NULL DEFAULT 0,
  source_file TEXT,
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vulnerability_changes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_hash    TEXT NOT NULL,
  host         TEXT NOT NULL,
  name         TEXT NOT NULL,
  old_severity TEXT NOT NULL,
  new_severity TEXT NOT NULL,
  changed_at   TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vuln_changes_hash       ON vulnerability_changes(vuln_hash);
CREATE INDEX IF NOT EXISTS idx_vuln_changes_changed_at ON vulnerability_changes(changed_at);
CREATE INDEX IF NOT EXISTS idx_vuln_host_severity ON vulnerabilities(host, severity);
CREATE INDEX IF NOT EXISTS idx_vuln_detected_at   ON vulnerabilities(detected_at);
CREATE INDEX IF NOT EXISTS idx_vuln_host_url      ON vulnerabilities(host, url);

-- ── Log360 events — keeps Log360's native Windows event vocabulary ──────────
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host        TEXT NOT NULL,
  event_id    TEXT,
  event_type  TEXT,
  severity    TEXT NOT NULL DEFAULT 'information'
              CHECK(severity IN ('error','failure','warning','information','success')),
  user         TEXT,
  display_name TEXT,
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
