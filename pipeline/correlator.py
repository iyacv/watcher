"""
Correlator — detects possible exploitation events.

Logic:
  IF an F5 vulnerability exists for host X
  AND a Log360 event (suspicious type) exists for the same host X
  AND both occurred within CORRELATION_WINDOW_MINUTES of each other
  THEN flag as a correlation (possible active exploitation).

Called after every record is inserted. Checks the opposite source in the DB.
"""

from datetime import datetime, timedelta, timezone

import config

# Log360 event types that suggest active exploitation
#_SUSPICIOUS_EVENTS = {
      #  "authentication failure",
       # "brute force",
        #"privilege escalation",
        #"unauthorized access",
        #"suspicious login",
        #"malware detected",
        #"lateral movement",
        #"data exfiltration",
#}


def _parse_dt(ts: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(tz=timezone.utc)


def correlate(conn, record: dict) -> dict | None:
    """
    Returns a correlation dict if a match is found, otherwise None.
    """
    host   = record.get("host")
    source = record.get("source")
    ts     = _parse_dt(record.get("detected_at", ""))
    window = timedelta(minutes=config.CORRELATION_WINDOW_MINUTES)

    cursor = conn.cursor()

    if source == "f5":
        # New F5 vuln → look for matching suspicious Log360 event on same host
        cursor.execute(
            """
            SELECT event_id, event_type, detected_at
            FROM events
            WHERE host = ?
              AND LOWER(event_type) IN ({placeholders})
              AND detected_at BETWEEN ? AND ?
            LIMIT 1
            """.format(placeholders=",".join(["?"] * len(_SUSPICIOUS_EVENTS))),
            (host, *_SUSPICIOUS_EVENTS,
             (ts - window).strftime("%Y-%m-%d %H:%M:%S"),
             (ts + window).strftime("%Y-%m-%d %H:%M:%S")),
        )
        row = cursor.fetchone()
        if row:
            cursor.close()
            return {
                "host":       host,
                "vuln_id":    record.get("vuln_id"),
                "event_id":   row["event_id"],
                "event_type": row["event_type"],
                "vuln_time":  record.get("detected_at"),
                "event_time": str(row["detected_at"]),
                "severity":   record.get("severity"),
            }

    elif source == "log360":
        # New Log360 event → look for F5 vuln on same host within window
        event_type = record.get("event_type", "").lower()
        if event_type not in _SUSPICIOUS_EVENTS:
            cursor.close()
            return None

        cursor.execute(
            """
            SELECT vuln_id, severity, detected_at
            FROM vulnerabilities
            WHERE host = ?
              AND detected_at BETWEEN ? AND ?
            ORDER BY severity DESC
            LIMIT 1
            """,
            (host,
             (ts - window).strftime("%Y-%m-%d %H:%M:%S"),
             (ts + window).strftime("%Y-%m-%d %H:%M:%S")),
        )
        row = cursor.fetchone()
        if row:
            cursor.close()
            return {
                "host":       host,
                "vuln_id":    row["vuln_id"],
                "event_id":   record.get("event_id"),
                "event_type": record.get("event_type"),
                "vuln_time":  str(row["detected_at"]),
                "event_time": record.get("detected_at"),
                "severity":   row["severity"],
            }

    cursor.close()
    return None
