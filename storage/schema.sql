-- Run this once to set up the database
-- mysql -u root -p < storage/schema.sql

CREATE DATABASE IF NOT EXISTS capstone_security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE capstone_security;

-- ── F5 vulnerabilities ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  host        VARCHAR(255) NOT NULL,
  port        SMALLINT UNSIGNED,
  vuln_id     VARCHAR(100) NOT NULL,      
  name        VARCHAR(500),
  severity    ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'low',
  cvss        DECIMAL(4,1),
  description TEXT,
  remediation TEXT,
  detected_at DATETIME NOT NULL,
  raw_hash    CHAR(64) NOT NULL UNIQUE,   
  status      ENUM('open','resolved') NOT NULL DEFAULT 'open',
  aged        TINYINT(1) NOT NULL DEFAULT 0,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_host_severity (host, severity),
  INDEX idx_detected_at   (detected_at),
  INDEX idx_vuln_id       (vuln_id)
);

-- ── Log360 events ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  host        VARCHAR(255) NOT NULL,
  event_id    VARCHAR(100),
  event_type  VARCHAR(255),
  severity    ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'low',
  user        VARCHAR(255),
  description TEXT,
  detected_at DATETIME NOT NULL,
  raw_hash    CHAR(64) NOT NULL UNIQUE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_host       (host),
  INDEX idx_event_type (event_type),
  INDEX idx_detected_at(detected_at)
);

-- ── Correlations (F5 vuln + Log360 event on same host) ───────────────────────
CREATE TABLE IF NOT EXISTS correlations (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  host        VARCHAR(255) NOT NULL,
  vuln_id     VARCHAR(100),
  event_id    VARCHAR(100),
  event_type  VARCHAR(255),
  vuln_time   DATETIME,
  event_time  DATETIME,
  severity    ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'high',
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_correlation (host, vuln_id, event_id),
  INDEX idx_host     (host),
  INDEX idx_severity (severity)
);
