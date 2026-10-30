"""Database connection management and initialization using sqlite3."""

import sqlite3
from pathlib import Path

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def get_db_connection(db_path: str = "instance/auditor.db") -> sqlite3.Connection:
    """Create and return a configured sqlite3 connection with Row factory."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = "instance/auditor.db") -> None:
    """Initialize SQLite database tables from schema.sql."""
    with get_db_connection(db_path) as conn:
        schema = SCHEMA_FILE.read_text(encoding="utf-8")
        conn.executescript(schema)
        conn.commit()
