"""
Postgres backend (cloud mode). Activated when DATABASE_URL is set.

DATABASE_URL examples:
  postgres://user:pass@host/db
  postgresql://user:pass@host:5432/db?sslmode=require
"""
import os
import psycopg2
import psycopg2.extras


def get_connection():
    url = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


def insert_vulnerability(conn, r: dict) -> int:
    sql = """
        INSERT INTO vulnerabilities
          (host, url, name, attack_type, cookie, severity, cvss,
           status, detected_at, raw_hash, aged, source_file)
        VALUES
          (%(host)s, %(url)s, %(name)s, %(attack_type)s, %(cookie)s,
           %(severity)s, %(cvss)s, %(status)s, %(detected_at)s, %(raw_hash)s,
           %(aged)s, %(source_file)s)
        ON CONFLICT (raw_hash) DO NOTHING
        RETURNING id
    """
    r.setdefault("aged", False)
    r.setdefault("status", "open")
    r.setdefault("source_file", None)
    r.setdefault("url", None)
    r.setdefault("attack_type", None)
    r.setdefault("cookie", None)
    r.setdefault("cvss", None)
    cur = conn.cursor()
    cur.execute(sql, r)
    row = cur.fetchone()
    conn.commit()
    cur.close()
    return row["id"] if row else 0


def insert_event(conn, r: dict) -> int:
    sql = """
        INSERT INTO events
          (host, event_id, event_type, severity, "user",
           description, detected_at, raw_hash, source_file)
        VALUES
          (%(host)s, %(event_id)s, %(event_type)s, %(severity)s, %(user)s,
           %(description)s, %(detected_at)s, %(raw_hash)s, %(source_file)s)
        ON CONFLICT (raw_hash) DO NOTHING
        RETURNING id
    """
    r.setdefault("source_file", None)
    cur = conn.cursor()
    cur.execute(sql, r)
    row = cur.fetchone()
    conn.commit()
    cur.close()
    return row["id"] if row else 0


def flag_correlation(conn, c: dict):
    sql = """
        INSERT INTO correlations
          (host, vuln_id, event_id, event_type, vuln_time, event_time, severity)
        VALUES
          (%(host)s, %(vuln_id)s, %(event_id)s, %(event_type)s,
           %(vuln_time)s, %(event_time)s, %(severity)s)
        ON CONFLICT (host, vuln_id, event_id) DO UPDATE
          SET severity = EXCLUDED.severity
    """
    cur = conn.cursor()
    cur.execute(sql, c)
    conn.commit()
    cur.close()
