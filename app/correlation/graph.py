"""Attack graph representation and visualization export for Cytoscape.js."""

from dataclasses import dataclass, field
from typing import Any

from app.correlation.chains import Chain


@dataclass
class AttackGraph:
    """Directed graph representing potential attack paths across workflows and stages."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def to_cytoscape_elements(self) -> list[dict[str, Any]]:
        """Export graph nodes and edges to Cytoscape.js compatible JSON format."""
        elements = []
        for node in self.nodes:
            elements.append({"data": node})
        for edge in self.edges:
            elements.append({"data": edge})
        return elements

    @classmethod
    def from_chains(cls, chains: list[Chain]) -> "AttackGraph":
        """Build an attack graph from discovered attack chains.

        (Detailed implementation in Phase 3)
        """
        nodes = []
        edges = []
        for chain in chains:
            nodes.extend(chain.nodes)
            edges.extend(chain.edges)
        return cls(nodes=nodes, edges=edges)

