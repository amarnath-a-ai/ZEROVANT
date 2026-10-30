"""Tests for Database and Repository Layer (Phase 5)."""

from app.storage.db import get_db_connection, init_db


def test_db_initialization_in_memory():
    """Verify SQLite database schema initializes cleanly in memory."""
    conn = get_db_connection(":memory:")
    init_db(":memory:")
    # Ensure foreign keys are active
    pragma = conn.execute("PRAGMA foreign_keys;").fetchone()
    assert pragma[0] == 1
    conn.close()

