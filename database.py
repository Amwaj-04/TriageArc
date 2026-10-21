from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

try:
    from flask import g, has_app_context
except ImportError:  # Keep command-line foundation checks usable without Flask context.
    g = None
    has_app_context = lambda: False

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TRIAGEARC_DB_PATH", BASE_DIR / "data" / "triagearc.db"))
SCHEMA_PATH = BASE_DIR / "schema.sql"


class ClosingConnection(sqlite3.Connection):
    """SQLite connection that commits/rolls back and always closes on context exit."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def get_connection() -> sqlite3.Connection:
    # Each signed browser session receives its own SQLite workspace. Outside a
    # Flask request (CLI checks, seeding utilities, unit-test setup), use DB_PATH.
    db_path = DB_PATH
    if has_app_context() and g is not None:
        workspace_path = getattr(g, "triagearc_db_path", None)
        if workspace_path:
            db_path = Path(workspace_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


def clear_db() -> None:
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'events')")


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def json_load(value: str):
    return json.loads(value) if value else []
