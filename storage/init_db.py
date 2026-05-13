"""Initialize the database. Idempotent — safe to re-run.

Picks SQLite or Postgres based on the DATABASE_URL environment variable.

Flags:
  --reset    Drop existing tables before creating. Wipes all data.
"""
import argparse
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

_TABLES = ("correlations", "vulnerabilities", "events")


def _init_sqlite(reset: bool = False):
    import sqlite3
    db_path = BASE / "capstone.db"
    schema = (BASE / "storage" / "schema.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(str(db_path))
    if reset:
        for tbl in _TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {tbl}")
        conn.commit()
        print(f"Dropped tables: {', '.join(_TABLES)}")
    conn.executescript(schema)
    conn.commit()
    conn.close()
    print(f"SQLite database ready: {db_path}")


def _init_postgres(reset: bool = False):
    import psycopg2
    schema = (BASE / "storage" / "schema.postgres.sql").read_text(encoding="utf-8")
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur = conn.cursor()
    if reset:
        for tbl in _TABLES:
            cur.execute(f"DROP TABLE IF EXISTS {tbl} CASCADE")
        conn.commit()
        print(f"Dropped tables: {', '.join(_TABLES)}")
    cur.execute(schema)
    conn.commit()
    cur.close()
    conn.close()
    host = os.environ["DATABASE_URL"].split("@", 1)[-1].split("/", 1)[0]
    print(f"Postgres database ready at: {host}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reset", action="store_true",
                    help="Drop existing tables before creating. Wipes all data.")
    args = ap.parse_args()

    if os.getenv("DATABASE_URL"):
        _init_postgres(reset=args.reset)
    else:
        _init_sqlite(reset=args.reset)
