"""
Storage backend dispatcher.

If the environment variable ``DATABASE_URL`` is set (e.g. a Postgres URL from
Neon / Supabase / Render), the cloud Postgres backend is used. Otherwise the
local SQLite backend is used.

Exposes the same four functions either way:
  get_connection, insert_vulnerability, insert_event, flag_correlation
"""
import os

if os.getenv("DATABASE_URL"):
    from storage._postgres import (
        get_connection,
        insert_vulnerability,
        insert_event,
        flag_correlation,
    )
    BACKEND = "postgres"
else:
    from storage._sqlite import (
        get_connection,
        insert_vulnerability,
        insert_event,
        flag_correlation,
    )
    BACKEND = "sqlite"

__all__ = [
    "BACKEND",
    "get_connection",
    "insert_vulnerability",
    "insert_event",
    "flag_correlation",
]
