"""SQLite backend (local mode). Same interface as storage/_postgres.py."""
import sqlite3
import config


def get_connection():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def insert_vulnerability(conn, r: dict) -> int:
    sql = """
        INSERT INTO vulnerabilities
          (host, url, name, attack_type, cookie, severity, cvss,
           status, detected_at, raw_hash, aged, source_file)
        VALUES
          (:host, :url, :name, :attack_type, :cookie, :severity, :cvss,
           :status, :detected_at, :raw_hash, :aged, :source_file)
    """
    r.setdefault("aged", False)
    r.setdefault("status", "open")
    r.setdefault("source_file", None)
    r.setdefault("url", None)
    r.setdefault("attack_type", None)
    r.setdefault("cookie", None)
    r.setdefault("cvss", None)
    cursor = conn.cursor()
    cursor.execute(sql, r)
    conn.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id


def insert_event(conn, r: dict) -> int:
    sql = """
        INSERT INTO events
          (host, event_id, event_type, severity, user,
           description, detected_at, raw_hash, source_file)
        VALUES
          (:host, :event_id, :event_type, :severity, :user,
           :description, :detected_at, :raw_hash, :source_file)
    """
    r.setdefault("source_file", None)
    cursor = conn.cursor()
    cursor.execute(sql, r)
    conn.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id


def flag_correlation(conn, c: dict):
    sql = """
        INSERT INTO correlations
          (host, vuln_id, event_id, event_type, vuln_time, event_time, severity)
        VALUES
          (:host, :vuln_id, :event_id, :event_type,
           :vuln_time, :event_time, :severity)
        ON CONFLICT(host, vuln_id, event_id) DO UPDATE SET severity = excluded.severity
    """
    cursor = conn.cursor()
    cursor.execute(sql, c)
    conn.commit()
    cursor.close()
