"""
Deduplication — prevents the same vulnerability/event from being inserted twice.

Uses an in-memory set for the current session and checks the DB for the hash
on startup, so restarts don't re-insert old records.
"""

_seen_hashes: set[str] = set()


def is_duplicate(record: dict) -> bool:
    return record.get("raw_hash") in _seen_hashes


def mark_seen(record: dict):
    h = record.get("raw_hash")
    if h:
        _seen_hashes.add(h)


def load_existing_hashes(conn):
    """Call once at startup to pre-populate from DB so restarts stay clean."""
    cursor = conn.cursor()
    for table in ("vulnerabilities", "events"):
        try:
            cursor.execute(f"SELECT raw_hash FROM {table}")
            for (h,) in cursor.fetchall():
                _seen_hashes.add(h)
        except Exception:
            pass
    cursor.close()
