"""Correlation module for mapping findings to attack graphs and chains."""

from app.correlation.chains import (
    CHAIN_DEFINITIONS,
    Chain,
    ChainCorrelator,
    ChainDefinition,
    ChainType,
    CorrelationResult,
    JobContext,
)
from app.correlation.graph import AttackGraph

__all__ = [
    "AttackGraph",
    "CHAIN_DEFINITIONS",
    "Chain",
    "ChainCorrelator",
    "ChainDefinition",
    "ChainType",
    "CorrelationResult",
    "JobContext",
]
