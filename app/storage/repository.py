"""Repository interface for scan persistence and querying."""

from typing import Any

from app.storage.db import get_db_connection


class ScanRepository:
    """Manages CRUD persistence for scans, findings, chains, and explanations."""

    def __init__(self, db_path: str = "instance/auditor.db"):
        self.db_path = db_path

    def save_scan(self, scan_data: dict[str, Any]) -> str:
        """Persist a completed scan and its child entities.

        (Detailed implementation in Phase 5)
        """
        raise NotImplementedError("ScanRepository.save_scan will be implemented in Phase 5.")

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve scan record by ID.

        (Detailed implementation in Phase 5)
        """
        raise NotImplementedError("ScanRepository.get_scan will be implemented in Phase 5.")

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        """List historical scans ordered by creation date."""
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

