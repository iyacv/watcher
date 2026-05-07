"""Initialize the SQLite database from schema.sql. Idempotent — safe to re-run."""
import sqlite3
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "capstone.db"
SCHEMA = BASE / "storage" / "schema.sql"


def add_column_if_missing(conn, table: str, column: str, column_def: str) -> None:
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")


conn = sqlite3.connect(str(DB))
conn.executescript(SCHEMA.read_text(encoding="utf-8"))

# Migrate older DBs that pre-date these columns
add_column_if_missing(conn, "vulnerabilities", "source_file", "source_file TEXT")
add_column_if_missing(conn, "events",          "source_file", "source_file TEXT")

conn.commit()
conn.close()
print(f"Database ready: {DB}")
