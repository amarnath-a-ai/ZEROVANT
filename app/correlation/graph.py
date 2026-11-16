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
        """Export graph nodes and edges to Cytoscape.js compatible JSON element list."""
        elements: list[dict[str, Any]] = []
        for node in self.nodes:
            elements.append({"data": dict(node)})
        for edge in self.edges:
            elements.append({"data": dict(edge)})
        return elements

    def to_dict(self) -> dict[str, Any]:
        """Export raw nodes and edges dictionary."""
        return {
            "nodes": list(self.nodes),
            "edges": list(self.edges),
            "elements": self.to_cytoscape_elements(),
        }

    @classmethod
    def from_chain(cls, chain: Chain) -> "AttackGraph":
        """Build an attack graph from a single discovered attack chain."""
        return cls(nodes=list(chain.nodes), edges=list(chain.edges))

    @classmethod
    def from_chains(cls, chains: list[Chain]) -> "AttackGraph":
        """Build a consolidated attack graph from multiple attack chains, deduplicating elements."""
        seen_node_ids: set[str] = set()
        seen_edge_ids: set[str] = set()
        merged_nodes: list[dict[str, Any]] = []
        merged_edges: list[dict[str, Any]] = []

        for chain in chains:
            for node in chain.nodes:
                nid = node.get("id")
                if nid and nid not in seen_node_ids:
                    seen_node_ids.add(nid)
                    merged_nodes.append(dict(node))
            for edge in chain.edges:
                eid = edge.get("id") or f"{edge.get('source')}->{edge.get('target')}"
                if eid and eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    merged_edges.append(dict(edge))

        return cls(nodes=merged_nodes, edges=merged_edges)

    def validate(self) -> tuple[bool, list[str]]:
        """Validate that all edge source and target references correspond to known node IDs.

        Returns:
            Tuple of (is_valid: bool, errors: list[str])
        """
        errors: list[str] = []
        node_ids = {n["id"] for n in self.nodes if isinstance(n, dict) and "id" in n}

        for edge in self.edges:
            if not isinstance(edge, dict):
                errors.append(f"Invalid edge entry (not a dict): {edge}")
                continue
            eid = edge.get("id", "unnamed-edge")
            source = edge.get("source")
            target = edge.get("target")

            if not source:
                errors.append(f"Edge '{eid}' is missing 'source' attribute")
            elif source not in node_ids:
                errors.append(f"Edge '{eid}' references non-existent source node '{source}'")

            if not target:
                errors.append(f"Edge '{eid}' is missing 'target' attribute")
            elif target not in node_ids:
                errors.append(f"Edge '{eid}' references non-existent target node '{target}'")

        return len(errors) == 0, errors
