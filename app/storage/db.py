"""Database connection management and initialization using sqlite3."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from app.config import Config
from app.storage.errors import DatabaseIntegrityError, StorageError

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def get_db_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Create and return a configured sqlite3 connection with Row factory.

    Enforces foreign keys on every connection.
    """
    path_str = str(db_path) if db_path is not None else Config.DATABASE_PATH
    if path_str != ":memory:":
        Path(path_str).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path_str)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str | Path | None = None) -> None:
    """Initialize SQLite database tables and indexes from schema.sql."""
    conn = get_db_connection(db_path)
    try:
        schema = SCHEMA_FILE.read_text(encoding="utf-8")
        conn.executescript(schema)
        conn.commit()
    except sqlite3.Error as exc:
        raise StorageError(f"Failed to initialize database schema: {exc}") from exc
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite transactions with automatic commit/rollback.

    Wraps sqlite3 exceptions in custom StorageError / DatabaseIntegrityError.
    """
    try:
        with conn:
            yield conn
    except sqlite3.IntegrityError as exc:
        raise DatabaseIntegrityError(f"Database constraint violation: {exc}") from exc
    except sqlite3.Error as exc:
        raise StorageError(f"Database transaction failure: {exc}") from exc
