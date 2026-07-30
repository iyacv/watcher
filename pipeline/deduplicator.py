
_seen_hashes: set[str] = set()


def is_duplicate(record: dict) -> bool:
    return record.get("raw_hash") in _seen_hashes


def mark_seen(record: dict):
    h = record.get("raw_hash")
    if h:
        _seen_hashes.add(h)


def load_existing_hashes(conn):
   
    cursor = conn.cursor()
    for table in ("vulnerabilities", "events"):
        try:
            cursor.execute(f"SELECT raw_hash FROM {table}")
            for row in cursor.fetchall():
                # Postgres RealDictCursor returns dicts; SQLite returns tuples/Rows.
                h = row["raw_hash"] if isinstance(row, dict) else row[0]
                if h:
                    _seen_hashes.add(h)
        except Exception:
            pass
    cursor.close()
