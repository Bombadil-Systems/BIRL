"""
BIRL Interpretation Graph (Phase 2)

The Graph is the core navigation structure of BIRL. Nodes are Contexts,
edges are valid transitions (rewrites) between them, weighted by cost,
fidelity, stability, and mutation requirements.

BIRL Spec v1.1, Section 3: Weighted Interpretation Graph

Key capabilities:
- Weighted edge model (cost, fidelity, stability, mutation)
- A* pathfinding with configurable optimization strategies
- Magic-byte pruning for performance (addresses Gemini's "Greedy Parser" concern)
- Edge discovery: automatic and manual registration of transitions
- Simultaneous validity tracking (Superposition — addresses "Greedy Parser" overlap)

Addresses Gemini's technical concerns:
1. Greedy Parser Problem → Superposition is explicit, not conflicting. Overlapping
   claims are tracked via OverlapReport, not resolved.
2. Performance Scaling → Magic-byte signatures enable O(1) pruning before parsing.
3. Rewriter foundation → A* planner with composite scoring prepares for Phase 3.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Union

import networkx as nx

from birl.context import Context, ValidityTuple, StructuredRange


# ============================================================================
# Edge Weight Model (Spec v1.1, Section 3.1)
# ============================================================================

class MutationType(Enum):
    """Whether an edge requires byte modification."""
    VIEW_ONLY = 0    # Pure reinterpretation, zero bytes change
    REWRITING = 1    # Bytes must be modified to satisfy target context


class Strategy(Enum):
    """Pathfinding optimization strategies (Spec v1.1, Section 3.2)."""
    ZERO_COPY = "zero_copy"       # Minimize mutation (OIS-ROP style)
    ROBUST = "robust"             # Maximize stability across environments
    SANITIZATION = "sanitization" # Max fidelity for payload, min for container
    FASTEST = "fastest"           # Minimize computational cost
    BALANCED = "balanced"         # Weighted composite of all factors


@dataclass(frozen=True)
class EdgeWeight:
    """Weight tuple for graph edges (Spec v1.1, Section 3.1).
    
    Attributes:
        mutation: VIEW_ONLY (0) or REWRITING (1)
        fidelity: Semantic information preserved [0.0, 1.0]
        stability: Probability transition holds across environments [0.0, 1.0]
        cost: Computational expense (arbitrary units, lower = cheaper)
    """
    mutation: MutationType = MutationType.VIEW_ONLY
    fidelity: float = 1.0
    stability: float = 1.0
    cost: float = 1.0

    def composite_score(self, strategy: Strategy) -> float:
        """Compute a single scalar score for pathfinding.
        
        Lower score = better path. This is the heuristic that A* optimizes.
        """
        mut_penalty = 0.0 if self.mutation == MutationType.VIEW_ONLY else 1.0

        if strategy == Strategy.ZERO_COPY:
            # Heavily penalize any mutation; prefer view-only edges
            return mut_penalty * 100.0 + self.cost + (1.0 - self.stability)

        elif strategy == Strategy.ROBUST:
            # Maximize stability
            return (1.0 - self.stability) * 10.0 + self.cost + mut_penalty

        elif strategy == Strategy.SANITIZATION:
            # Maximize fidelity
            return (1.0 - self.fidelity) * 10.0 + self.cost + mut_penalty * 0.5

        elif strategy == Strategy.FASTEST:
            # Minimize cost
            return self.cost + mut_penalty * 0.1

        else:  # BALANCED
            return (
                self.cost
                + mut_penalty * 5.0
                + (1.0 - self.fidelity) * 3.0
                + (1.0 - self.stability) * 3.0
            )


@dataclass
class EdgeInfo:
    """Complete edge metadata."""
    source: str          # Source context name
    target: str          # Target context name
    weight: EdgeWeight
    edge_type: str       # "isomorphic", "structural", "semantic", "offset"
    description: str = ""
    # Optional: the actual transformation function for Phase 3
    transform: Optional[Callable[[bytes, dict], bytes]] = None
    # Conditions: when is this edge valid?
    condition: Optional[Callable[[bytes], bool]] = None

    def __repr__(self) -> str:
        mut = "view" if self.weight.mutation == MutationType.VIEW_ONLY else "rewrite"
        return (
            f"<Edge {self.source}→{self.target} [{self.edge_type}/{mut}] "
            f"F={self.weight.fidelity:.1f} S={self.weight.stability:.1f} "
            f"C={self.weight.cost:.1f}>"
        )


# ============================================================================
# Magic-Byte Signatures (Performance Pruning)
# ============================================================================

@dataclass(frozen=True)
class MagicSignature:
    """Quick-reject signature for a context.
    
    Before running the full parser, check if the bytes even have a
    chance of satisfying this context. This addresses Gemini's
    "Performance Scaling" concern — O(1) rejection before O(n) parsing.
    """
    offset: int              # Where to check
    pattern: bytes           # What to look for
    description: str = ""

    def matches(self, data: bytes) -> bool:
        end = self.offset + len(self.pattern)
        if end > len(data):
            return False
        return data[self.offset:end] == self.pattern


# Well-known magic signatures
MAGIC_SIGNATURES: dict[str, list[MagicSignature]] = {
    "PE": [MagicSignature(0, b"MZ", "DOS magic")],
    "ELF": [MagicSignature(0, b"\x7fELF", "ELF magic")],
    "ZIP": [
        MagicSignature(0, b"PK\x03\x04", "ZIP local file header"),
        # ZIP can also be detected by EOCD at end — handled specially
    ],
    "PNG": [MagicSignature(0, b"\x89PNG\r\n\x1a\n", "PNG signature")],
    # x86_64 and UTF8 have no magic bytes — they're always candidates
    # Raw has no magic — it matches everything
}


# ============================================================================
# Overlap Report (Greedy Parser Problem)
# ============================================================================

@dataclass
class OverlapRegion:
    """A byte range claimed by multiple contexts simultaneously."""
    start: int
    end: int
    contexts: list[str]  # Which contexts claim this range
    interpretations: dict[str, str]  # context_name → field_id

    @property
    def length(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:
        return (
            f"<Overlap [{self.start:#x}:{self.end:#x}] "
            f"({self.length}B) claimed by: {', '.join(self.contexts)}>"
        )


@dataclass
class OverlapReport:
    """Analysis of byte ranges claimed by multiple contexts.
    
    This directly addresses Gemini's "Greedy Parser" concern:
    overlapping claims are NOT conflicts to resolve — they're
    the fundamental insight that BIRL is built on. This report
    makes them visible and queryable.
    """
    total_bytes: int
    overlapping_regions: list[OverlapRegion]
    total_overlap_bytes: int

    @property
    def overlap_ratio(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return self.total_overlap_bytes / self.total_bytes

    def __repr__(self) -> str:
        return (
            f"<OverlapReport: {self.total_overlap_bytes}/{self.total_bytes} bytes "
            f"({self.overlap_ratio:.1%}) claimed by 2+ contexts across "
            f"{len(self.overlapping_regions)} regions>"
        )


# ============================================================================
# The Interpretation Graph
# ============================================================================

class InterpretationGraph:
    """The BIRL Interpretation Graph.
    
    A directed, weighted graph where:
    - Nodes = Interpretation Contexts
    - Edges = Valid transitions (rewrites) with weight tuples
    
    Supports:
    - A* pathfinding with configurable strategies
    - Magic-byte pruning for fast context rejection
    - Overlap analysis for the Greedy Parser problem
    - Edge discovery (auto and manual)
    """

    def __init__(self) -> None:
        self._graph = nx.DiGraph()
        self._contexts: dict[str, Context] = {}
        self._magic: dict[str, list[MagicSignature]] = {}
        self._edges: dict[tuple[str, str], EdgeInfo] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_context(
        self,
        context: Context,
        magic: Optional[list[MagicSignature]] = None,
    ) -> None:
        """Register a context as a node in the graph."""
        name = context.name
        self._contexts[name] = context
        self._graph.add_node(name, context=context)

        # Use well-known magic if not provided
        if magic is not None:
            self._magic[name] = magic
        elif name in MAGIC_SIGNATURES:
            self._magic[name] = MAGIC_SIGNATURES[name]

    def register_edge(self, edge: EdgeInfo) -> None:
        """Register a transition edge between two contexts."""
        if edge.source not in self._contexts:
            raise KeyError(f"Source context '{edge.source}' not registered")
        if edge.target not in self._contexts:
            raise KeyError(f"Target context '{edge.target}' not registered")

        self._graph.add_edge(
            edge.source,
            edge.target,
            weight=edge.weight,
            edge_info=edge,
        )
        self._edges[(edge.source, edge.target)] = edge

    def get_edge(self, source: str, target: str) -> Optional[EdgeInfo]:
        """Get edge info between two contexts."""
        return self._edges.get((source, target))

    # ------------------------------------------------------------------
    # Magic-Byte Pruning
    # ------------------------------------------------------------------

    def quick_candidates(self, data: bytes) -> list[str]:
        """Fast pre-filter: which contexts could possibly apply to these bytes?
        
        Uses magic-byte signatures for O(1) rejection before O(n) parsing.
        Contexts without magic signatures are always candidates.
        """
        candidates = []
        for name, ctx in self._contexts.items():
            if name in self._magic:
                # Must match at least one magic signature
                if any(sig.matches(data) for sig in self._magic[name]):
                    candidates.append(name)
            else:
                # No magic = always a candidate (e.g., x86, UTF8, Raw)
                candidates.append(name)
        return candidates

    def smart_identify(self, data: bytes) -> list[tuple[str, ValidityTuple]]:
        """Identify all valid contexts, using magic-byte pruning.
        
        This is the performance-optimized version of World.identify().
        Only runs full parsers on contexts that pass the magic-byte check.
        """
        candidates = self.quick_candidates(data)
        results = []

        # Special case: ZIP can be detected by EOCD at end of file
        if "ZIP" in self._contexts and "ZIP" not in candidates:
            if b"PK\x05\x06" in data[-65557:]:
                candidates.append("ZIP")

        for name in candidates:
            if name == "Raw":
                continue
            ctx = self._contexts[name]
            vt = ctx.satisfies(data)
            if vt.valid:
                results.append((name, vt))

        results.sort(key=lambda x: x[1].coverage, reverse=True)
        return results

    # ------------------------------------------------------------------
    # Overlap Analysis (Greedy Parser Problem)
    # ------------------------------------------------------------------

    def analyze_overlaps(
        self,
        data: bytes,
        contexts: Optional[list[str]] = None,
    ) -> OverlapReport:
        """Find byte ranges claimed by multiple contexts simultaneously.
        
        This is the answer to the "Greedy Parser" problem: we don't resolve
        overlaps, we report them. Overlapping claims are the interesting case.
        """
        if contexts is None:
            # Use all contexts that validate
            valid = self.smart_identify(data)
            contexts = [name for name, _ in valid]

        # Build a map: byte_offset → list of (context_name, field_id)
        claims: dict[int, list[tuple[str, str]]] = {}

        for ctx_name in contexts:
            ctx = self._contexts[ctx_name]
            vt = ctx.satisfies(data)
            if not vt.valid:
                continue
            for sr in vt.structured_ranges:
                for offset in range(sr.start, min(sr.end, len(data))):
                    if offset not in claims:
                        claims[offset] = []
                    claims[offset].append((ctx_name, sr.field_id))

        # Find offsets claimed by 2+ contexts
        overlap_offsets = {
            off: claimants
            for off, claimants in claims.items()
            if len(set(c[0] for c in claimants)) >= 2
        }

        if not overlap_offsets:
            return OverlapReport(len(data), [], 0)

        # Merge contiguous overlapping offsets into regions
        sorted_offsets = sorted(overlap_offsets.keys())
        regions: list[OverlapRegion] = []
        region_start = sorted_offsets[0]
        prev = region_start
        region_contexts: set[str] = set()
        region_interps: dict[str, str] = {}

        for off in sorted_offsets:
            ctx_names = set(c[0] for c in overlap_offsets[off])
            if off != prev + 1 and off != region_start:
                # Flush region
                regions.append(OverlapRegion(
                    region_start, prev + 1,
                    list(region_contexts), dict(region_interps),
                ))
                region_start = off
                region_contexts = set()
                region_interps = {}

            region_contexts.update(ctx_names)
            for ctx_name, field_id in overlap_offsets[off]:
                region_interps[ctx_name] = field_id
            prev = off

        # Flush final region
        regions.append(OverlapRegion(
            region_start, prev + 1,
            list(region_contexts), dict(region_interps),
        ))

        total_overlap = sum(r.length for r in regions)
        return OverlapReport(len(data), regions, total_overlap)

    # ------------------------------------------------------------------
    # A* Pathfinding
    # ------------------------------------------------------------------

    def find_path(
        self,
        source: str,
        target: str,
        strategy: Strategy = Strategy.BALANCED,
        data: Optional[bytes] = None,
    ) -> Optional[list[EdgeInfo]]:
        """Find the optimal path between two contexts using A* search.
        
        Args:
            source: Starting context name
            target: Destination context name
            strategy: Optimization strategy (affects edge scoring)
            data: Optional byte data for condition-checking on edges
            
        Returns:
            Ordered list of EdgeInfo objects forming the path, or None
        """
        if source not in self._contexts or target not in self._contexts:
            return None
        if source == target:
            return []

        # A* with composite scoring
        # Priority queue: (score, tiebreaker, node, path)
        counter = 0
        open_set: list[tuple[float, int, str, list[EdgeInfo]]] = []
        heapq.heappush(open_set, (0.0, counter, source, []))
        visited: set[str] = set()
        g_scores: dict[str, float] = {source: 0.0}

        while open_set:
            current_score, _, current, path = heapq.heappop(open_set)

            if current == target:
                return path

            if current in visited:
                continue
            visited.add(current)

            for neighbor in self._graph.successors(current):
                if neighbor in visited:
                    continue

                edge_data = self._graph.edges[current, neighbor]
                edge_info: EdgeInfo = edge_data["edge_info"]
                edge_weight: EdgeWeight = edge_data["weight"]

                # Check edge condition if data is provided
                if data is not None and edge_info.condition is not None:
                    if not edge_info.condition(data):
                        continue

                step_cost = edge_weight.composite_score(strategy)
                tentative_g = g_scores[current] + step_cost

                if tentative_g < g_scores.get(neighbor, float("inf")):
                    g_scores[neighbor] = tentative_g
                    new_path = path + [edge_info]
                    # Heuristic: 0 (Dijkstra's — we don't have a good admissible heuristic)
                    f_score = tentative_g
                    counter += 1
                    heapq.heappush(open_set, (f_score, counter, neighbor, new_path))

        return None  # No path exists

    def find_all_paths(
        self,
        source: str,
        target: str,
        max_depth: int = 5,
    ) -> list[list[EdgeInfo]]:
        """Find all paths up to a given depth (for analysis/comparison)."""
        if source not in self._contexts or target not in self._contexts:
            return []

        all_paths = []
        for nx_path in nx.all_simple_paths(self._graph, source, target, cutoff=max_depth):
            edge_path = []
            for i in range(len(nx_path) - 1):
                edge_info = self._edges.get((nx_path[i], nx_path[i + 1]))
                if edge_info:
                    edge_path.append(edge_info)
            if len(edge_path) == len(nx_path) - 1:
                all_paths.append(edge_path)
        return all_paths

    def path_total_weight(self, path: list[EdgeInfo]) -> EdgeWeight:
        """Compute aggregate weight for a complete path."""
        if not path:
            return EdgeWeight()

        total_cost = sum(e.weight.cost for e in path)
        min_fidelity = min(e.weight.fidelity for e in path)
        min_stability = min(e.weight.stability for e in path)
        has_mutation = any(e.weight.mutation == MutationType.REWRITING for e in path)

        return EdgeWeight(
            mutation=MutationType.REWRITING if has_mutation else MutationType.VIEW_ONLY,
            fidelity=min_fidelity,
            stability=min_stability,
            cost=total_cost,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def nodes(self) -> list[str]:
        return list(self._graph.nodes)

    @property
    def edges(self) -> list[tuple[str, str]]:
        return list(self._graph.edges)

    def neighbors(self, context_name: str) -> list[str]:
        """Get all contexts reachable from this one in one step."""
        return list(self._graph.successors(context_name))

    def reverse_neighbors(self, context_name: str) -> list[str]:
        """Get all contexts that can transition TO this one."""
        return list(self._graph.predecessors(context_name))

    def summary(self) -> str:
        """Human-readable graph summary."""
        lines = [
            f"Interpretation Graph: {len(self._graph.nodes)} contexts, "
            f"{len(self._graph.edges)} edges",
            "",
            "Contexts:",
        ]
        for name in sorted(self._graph.nodes):
            has_magic = "✓" if name in self._magic else "·"
            neighbors = self.neighbors(name)
            lines.append(f"  [{has_magic}] {name} → {neighbors}")

        lines.append("")
        lines.append("Edges:")
        for (src, tgt), info in sorted(self._edges.items()):
            lines.append(f"  {info}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"<InterpretationGraph: {len(self._graph.nodes)} nodes, "
            f"{len(self._graph.edges)} edges>"
        )
