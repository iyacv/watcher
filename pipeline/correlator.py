
import os
from datetime import datetime, timedelta, timezone

import config


_PH = "%s" if os.getenv("DATABASE_URL") else "?"

# Log360 event types that suggest active exploitation
_SUSPICIOUS_EVENTS = {
    "authentication failure",
    "brute force",
    "privilege escalation",
    "unauthorized access",
    "suspicious login",
    "malware detected",
    "lateral movement",
    "data exfiltration",
}


def _parse_dt(ts: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(tz=timezone.utc)


def _row_get(row, key):
    """Works for both sqlite3.Row (key access) and psycopg dict_row (dict)."""
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (KeyError, IndexError):
        return None


def correlate(conn, record: dict) -> dict | None:
    """
    Returns a correlation dict if a match is found, otherwise None.
    """
    host   = record.get("host")
    source = record.get("source")
    ts     = _parse_dt(record.get("detected_at", ""))
    window = timedelta(minutes=config.CORRELATION_WINDOW_MINUTES)
    t_lo   = (ts - window).strftime("%Y-%m-%d %H:%M:%S")
    t_hi   = (ts + window).strftime("%Y-%m-%d %H:%M:%S")

    cursor = conn.cursor()

    if source == "f5":
       
        placeholders = ",".join([_PH] * len(_SUSPICIOUS_EVENTS))
        sql = f"""
            SELECT event_id, event_type, detected_at
            FROM events
            WHERE host = {_PH}
              AND LOWER(event_type) IN ({placeholders})
              AND detected_at BETWEEN {_PH} AND {_PH}
            LIMIT 1
        """
        cursor.execute(sql, (host, *_SUSPICIOUS_EVENTS, t_lo, t_hi))
        row = cursor.fetchone()
        if row:
            cursor.close()
            return {
                "host":       host,
               
                "vuln_id":    record.get("name"),
                "event_id":   _row_get(row, "event_id"),
                "event_type": _row_get(row, "event_type"),
                "vuln_time":  record.get("detected_at"),
                "event_time": str(_row_get(row, "detected_at")),
                "severity":   record.get("severity"),
            }

    elif source == "log360":
        # New Log360 event → look for F5 vuln on same host within window
        event_type = record.get("event_type", "").lower()
        if event_type not in _SUSPICIOUS_EVENTS:
            cursor.close()
            return None

        sql = f"""
            SELECT name, severity, detected_at
            FROM vulnerabilities
            WHERE host = {_PH}
              AND detected_at BETWEEN {_PH} AND {_PH}
            ORDER BY severity DESC
            LIMIT 1
        """
        cursor.execute(sql, (host, t_lo, t_hi))
        row = cursor.fetchone()
        if row:
            cursor.close()
            return {
                "host":       host,
                "vuln_id":    _row_get(row, "name"),
                "event_id":   record.get("event_id"),
                "event_type": record.get("event_type"),
                "vuln_time":  str(_row_get(row, "detected_at")),
                "event_time": record.get("detected_at"),
                "severity":   _row_get(row, "severity"),
            }

    cursor.close()
    return None
