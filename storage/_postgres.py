
import os
import psycopg
from psycopg.rows import dict_row


def get_connection():
    url = os.environ["DATABASE_URL"]
  
    if "sslmode=" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"
   
    conn = psycopg.connect(url, row_factory=dict_row, prepare_threshold=None)
    return conn


def insert_vulnerability(conn, r: dict) -> int:
    """Insert a vulnerability. If the same raw_hash already exists,
    update severity/status/cvss/last_seen, and log a row to
    vulnerability_changes when severity changed."""
    r.setdefault("aged", False)
    r.setdefault("status", "open")
    r.setdefault("source_file", None)
    r.setdefault("url", None)
    r.setdefault("attack_type", None)
    r.setdefault("cookie", None)
    r.setdefault("cvss", None)

    cur = conn.cursor()

    # Check if this vulnerability already exists (look up old severity)
    cur.execute(
        "SELECT id, severity FROM vulnerabilities WHERE raw_hash = %(raw_hash)s",
        {"raw_hash": r["raw_hash"]},
    )
    existing = cur.fetchone()

    if existing is None:
        # New vulnerability — straight INSERT
        cur.execute("""
            INSERT INTO vulnerabilities
              (host, url, name, attack_type, cookie, severity, cvss,
               status, detected_at, last_seen, raw_hash, aged, source_file)
            VALUES
              (%(host)s, %(url)s, %(name)s, %(attack_type)s, %(cookie)s,
               %(severity)s, %(cvss)s, %(status)s, %(detected_at)s, NOW(),
               %(raw_hash)s, %(aged)s, %(source_file)s)
            RETURNING id
        """, r)
        row = cur.fetchone()
        conn.commit()
        cur.close()
        return row["id"] if row else 0

    # Existing vulnerability — log severity change (if any), then UPDATE
    old_sev = existing["severity"]
    new_sev = r["severity"]
    if old_sev != new_sev:
        cur.execute("""
            INSERT INTO vulnerability_changes
              (vuln_hash, host, name, old_severity, new_severity)
            VALUES
              (%(raw_hash)s, %(host)s, %(name)s, %(old)s, %(new)s)
        """, {**r, "old": old_sev, "new": new_sev})

    cur.execute("""
        UPDATE vulnerabilities SET
          severity    = %(severity)s,
          cvss        = %(cvss)s,
          status      = %(status)s,
          last_seen   = NOW(),
          source_file = %(source_file)s
        WHERE raw_hash = %(raw_hash)s
    """, r)
    conn.commit()
    cur.close()
    return existing["id"]


def insert_event(conn, r: dict) -> int:
    sql = """
        INSERT INTO events
          (host, event_id, event_type, severity, "user",
           display_name, detected_at, raw_hash, source_file)
        VALUES
          (%(host)s, %(event_id)s, %(event_type)s, %(severity)s, %(user)s,
           %(display_name)s, %(detected_at)s, %(raw_hash)s, %(source_file)s)
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
