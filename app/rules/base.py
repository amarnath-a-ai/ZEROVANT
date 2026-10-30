"""Base definitions for static security rules and findings."""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from app.parser.model import Workflow


class Severity(str, Enum):
    """Finding severity levels aligned with CVSS / GitHub Security Advisory norms."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Security finding produced by a static analysis rule."""

    id: str  # Transient scan ID e.g. 'f-0001'
    rule_id: str
    title: str
    severity: Severity
    file: str
    job: str | None = None
    step: str | None = None
    line: int = 1
    evidence: str = ""
    tags: list[str] = field(default_factory=list)
    base_score: float = 0.0
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Compute a deterministic fingerprint unaffected by upstream line number shifts."""
        raw = f"{self.rule_id}:{self.file}:{self.job or ''}:{self.step or ''}:{self.evidence.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class BaseRule(ABC):
    """Abstract base class for all CI/CD static security analysis rules."""

    id: str = "R000"
    name: str = "base_rule"
    description: str = "Base static security rule"
    default_severity: Severity = Severity.MEDIUM
    tags: list[str] = []

    @abstractmethod
    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """Analyze a workflow model and return any discovered security findings."""
        pass
