"""
BIRL - Byte Interpretation Rewriting Language
A system for navigating the latent identities of byte sequences.

Phase 1: The Lens — Context definitions, coverage-aware validation, residue analysis
Phase 2: The Graph — Weighted interpretation graph, A* pathfinding, overlap analysis
Phase 3: The Rewriter — BIRL syntax compiler, runtime engine, mutation operations
"""

__version__ = "0.3.0"

from birl.core import World, ByteSequence
from birl.context import Context, ValidityTuple, StructuredRange
from birl.residue import ResidueCalculator
from birl.graph import (
    InterpretationGraph,
    EdgeInfo,
    EdgeWeight,
    MutationType,
    Strategy,
)
from birl.compiler import compile_birl
from birl.runtime import Runtime, ExecutionResult

__all__ = [
    "World",
    "ByteSequence",
    "Context",
    "ValidityTuple",
    "StructuredRange",
    "ResidueCalculator",
    "InterpretationGraph",
    "EdgeInfo",
    "EdgeWeight",
    "MutationType",
    "Strategy",
    "compile_birl",
    "Runtime",
    "ExecutionResult",
]
