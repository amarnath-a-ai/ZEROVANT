"""Storage and database exception hierarchy for CI/CD Pipeline Security Auditor."""


class StorageError(Exception):
    """Base exception for storage and database operations."""


class DatabaseIntegrityError(StorageError):
    """Raised when an integrity constraint or foreign key constraint is violated."""


class RecordNotFoundError(StorageError):
    """Raised when an expected database record is not found."""
