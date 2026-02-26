"""
BIRL Residue Calculator

BIRL Spec v1.1, Section 2: Interpretation Residue

Residue(b, C) = { byte_ranges in b | byte_range ∉ structured_ranges(Satisfies(b, C)) }

Residue is the "dark matter" — bytes that a Context ignores. This is where
polyglot payloads hide, steganographic data lives, and format confusion
attacks exploit gaps between what parsers claim and what they process.

Key operations:
- Single-context residue: What does this parser NOT claim?
- Residue intersection: What do NEITHER parser claim? (Safe harbor for injection)
- Residue analysis: Map all blind spots for a byte sequence
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from birl.context import Context, ValidityTuple, StructuredRange


@dataclass(frozen=True)
class ResidueRange:
    """A contiguous range of bytes unclaimed by any context."""
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:
        return f"<Residue [{self.start:#x}:{self.end:#x}] ({self.length} bytes)>"


@dataclass
class ResidueReport:
    """Complete residue analysis for a byte sequence under one or more contexts."""
    total_bytes: int
    contexts_applied: list[str]
    residue_ranges: list[ResidueRange]
    coverage_by_context: dict[str, float]

    @property
    def total_residue_bytes(self) -> int:
        return sum(r.length for r in self.residue_ranges)

    @property
    def residue_ratio(self) -> float:
        """Fraction of bytes that are unclaimed residue."""
        if self.total_bytes == 0:
            return 0.0
        return self.total_residue_bytes / self.total_bytes

    @property
    def exploitation_potential(self) -> str:
        """Quick assessment of residue for security research."""
        ratio = self.residue_ratio
        if ratio > 0.5:
            return "HIGH — Majority of bytes unclaimed. Wide open for polyglot injection."
        elif ratio > 0.2:
            return "MODERATE — Significant unclaimed regions. Polyglot feasible."
        elif ratio > 0.05:
            return "LOW — Small gaps. Steganographic injection possible but constrained."
        else:
            return "MINIMAL — Almost fully claimed. Very little room for hidden data."

    def __repr__(self) -> str:
        return (
            f"<ResidueReport: {self.total_residue_bytes}/{self.total_bytes} bytes "
            f"unclaimed ({self.residue_ratio:.1%}) across {len(self.contexts_applied)} "
            f"context(s) — {self.exploitation_potential}>"
        )


class ResidueCalculator:
    """Computes interpretation residue for byte sequences.
    
    The core insight: what a parser DOESN'T claim is just as important
    as what it does. Residue regions are structurally invisible to the
    interpreting context — they can contain anything without affecting
    the validity of the primary interpretation.
    
    Usage:
        calc = ResidueCalculator()
        
        # Single context residue
        report = calc.analyze(data, [pe_context])
        
        # Multi-context intersection (find bytes NOBODY claims)
        report = calc.analyze(data, [pe_context, zip_context])
        
        # Find injection points for polyglot construction
        safe_ranges = calc.find_injection_points(data, pe_context, zip_context)
    """

    def _compute_claimed_set(self, data: bytes, context: Context) -> set[int]:
        """Get the set of all byte offsets claimed by a context."""
        result = context.satisfies(data)
        if not result.valid:
            return set()
        claimed = set()
        for sr in result.structured_ranges:
            claimed.update(range(sr.start, min(sr.end, len(data))))
        return claimed

    def _offsets_to_ranges(self, unclaimed: set[int], total_length: int) -> list[ResidueRange]:
        """Convert a set of unclaimed offsets to contiguous ResidueRange objects."""
        if not unclaimed:
            return []
        sorted_offsets = sorted(unclaimed)
        ranges = []
        start = sorted_offsets[0]
        prev = start

        for offset in sorted_offsets[1:]:
            if offset != prev + 1:
                ranges.append(ResidueRange(start, prev + 1))
                start = offset
            prev = offset
        ranges.append(ResidueRange(start, prev + 1))
        return ranges

    def residue(self, data: bytes, context: Context) -> list[ResidueRange]:
        """Compute residue for a single context.
        
        Residue(b, C) = All bytes in b NOT in structured_ranges(Satisfies(b, C))
        """
        claimed = self._compute_claimed_set(data, context)
        all_offsets = set(range(len(data)))
        unclaimed = all_offsets - claimed
        return self._offsets_to_ranges(unclaimed, len(data))

    def residue_intersection(
        self,
        data: bytes,
        context_a: Context,
        context_b: Context,
    ) -> list[ResidueRange]:
        """Find bytes unclaimed by BOTH contexts.
        
        Residue∩(b, C1, C2) = Residue(b, C1) ∩ Residue(b, C2)
        
        These are "safe harbor" regions — bytes that neither parser examines,
        making them ideal for polyglot payload injection.
        """
        claimed_a = self._compute_claimed_set(data, context_a)
        claimed_b = self._compute_claimed_set(data, context_b)
        # Union of all claimed bytes from both contexts
        all_claimed = claimed_a | claimed_b
        all_offsets = set(range(len(data)))
        unclaimed_by_both = all_offsets - all_claimed
        return self._offsets_to_ranges(unclaimed_by_both, len(data))

    def analyze(
        self,
        data: bytes,
        contexts: list[Context],
    ) -> ResidueReport:
        """Full residue analysis across multiple contexts.
        
        Computes the union of all claimed bytes across all contexts,
        then reports what's left over.
        """
        all_claimed: set[int] = set()
        coverage_map: dict[str, float] = {}

        for ctx in contexts:
            claimed = self._compute_claimed_set(data, ctx)
            all_claimed |= claimed
            coverage_map[ctx.name] = len(claimed) / len(data) if data else 0.0

        all_offsets = set(range(len(data)))
        unclaimed = all_offsets - all_claimed
        ranges = self._offsets_to_ranges(unclaimed, len(data))

        return ResidueReport(
            total_bytes=len(data),
            contexts_applied=[ctx.name for ctx in contexts],
            residue_ranges=ranges,
            coverage_by_context=coverage_map,
        )

    def find_injection_points(
        self,
        data: bytes,
        primary_context: Context,
        target_context: Context,
        min_size: int = 16,
    ) -> list[ResidueRange]:
        """Find residue ranges suitable for polyglot injection.
        
        Returns regions that are:
        1. Unclaimed by the primary context (won't break the file's primary identity)
        2. Large enough to hold meaningful structure for the target context
        
        Args:
            data: The byte sequence
            primary_context: The context we want to preserve (e.g., JPEG)
            target_context: The context we want to inject (e.g., ZIP)
            min_size: Minimum useful region size in bytes
            
        Returns:
            List of ResidueRange objects suitable for injection
        """
        # Get residue of primary context (what it doesn't claim)
        residue_ranges = self.residue(data, primary_context)
        # Filter by minimum size
        viable = [r for r in residue_ranges if r.length >= min_size]
        return sorted(viable, key=lambda r: r.length, reverse=True)
