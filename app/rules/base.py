"""Base definitions for static security rules and findings."""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

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
        """Compute a deterministic fingerprint unaffected by upstream line number shifts.

        Calculated as sha256(rule_id:file:job:step_name_or_command:evidence)[:16].
        Never incorporates raw line numbers or step indices.
        """
        step_val = self.step or ""
        evidence_val = self.evidence.strip()
        raw = f"{self.rule_id}:{self.file}:{self.job or ''}:{step_val}:{evidence_val}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to standard JSON-serializable dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        return d


class BaseRule(ABC):
    """Abstract base class for all CI/CD static security analysis rules."""

    id: str = "R000"
    name: str = "base_rule"
    description: str = "Base static security rule"
    default_severity: Severity = Severity.MEDIUM
    tags: list[str] = []
    references: list[str] = []
    category: str = "General"

    @abstractmethod
    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """Analyze a workflow model and return any discovered security findings."""
        pass

    def check(self, workflow: Workflow) -> list[Finding]:
        """Alias for evaluate() to adhere to check(workflow) contract."""
        return self.evaluate(workflow)

