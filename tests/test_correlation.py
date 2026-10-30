"""Tests for Attack Chain Correlation and Graph Generation (Phase 3)."""

from app.correlation.chains import ChainCorrelator, ChainType
from app.correlation.graph import AttackGraph


def test_correlation_classes_importable():
    """Verify correlation models and correlator import cleanly."""
    correlator = ChainCorrelator()
    assert correlator is not None
    graph = AttackGraph()
    assert graph.to_cytoscape_elements() == []
    assert len(ChainType) == 5

