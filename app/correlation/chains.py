"""Attack chain models and multi-stage correlation engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.rules.base import Finding


class ChainType(str, Enum):
    """Catalog of known attack-chain templates."""

    PWN_REQUEST = "pwn-request"
    INJECTION_TO_EXFIL = "injection-to-exfil"
    SUPPLY_CHAIN_TAKEOVER = "supply-chain-takeover"
    DEPLOY_BLAST_RADIUS = "deploy-blast-radius"
    RUNNER_PERSISTENCE = "runner-persistence"


@dataclass
class Chain:
    """A correlated multi-stage attack chain combining multiple discrete findings."""

    id: str  # e.g. 'c-001'
    chain_type: ChainType
    finding_ids: list[str] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    narrative: str = ""
    chain_score: float = 0.0


class ChainCorrelator:
    """Correlates individual findings across a workflow or repo into multi-stage attack chains."""

    def correlate(self, findings: list[Finding]) -> list[Chain]:
        """Analyze findings and discover correlated attack chains.

        (Detailed implementation in Phase 3)
        """
        return []

