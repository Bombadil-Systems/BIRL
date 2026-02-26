"""
BIRL Context System

A Context is a computable function that maps a byte sequence to a structured
Identity (or error). This module defines the base Context class and the
coverage-aware Satisfies predicate from BIRL Spec v1.1 Section 1.

Key concepts:
- ValidityTuple: (valid, coverage, structured_ranges) — replaces boolean Satisfies
- StructuredRange: A claimed region of bytes with a field identity
- Coverage threshold (τ): Distinguishes "Strong" (intentional) from "Weak" (coincidental) identity
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class StructuredRange:
    """A region of bytes claimed by a Context as a structural field.
    
    Represents the mapping: bytes[start:end] → field_id with semantic meaning.
    """
    start: int
    end: int
    field_id: str
    description: str = ""
    # Nested sub-fields (e.g., PE Optional Header contains many sub-fields)
    children: tuple[StructuredRange, ...] = ()

    @property
    def length(self) -> int:
        return self.end - self.start

    def contains(self, offset: int) -> bool:
        return self.start <= offset < self.end

    def overlaps(self, other: StructuredRange) -> bool:
        return self.start < other.end and other.start < self.end

    def __repr__(self) -> str:
        desc = f" ({self.description})" if self.description else ""
        return f"<{self.field_id} [{self.start:#x}:{self.end:#x}]{desc}>"


@dataclass(frozen=True)
class ValidityTuple:
    """The result of applying the Satisfies predicate.
    
    BIRL Spec v1.1, Section 1.1:
        Satisfies(b, C) → (valid, coverage, structured_ranges)
    
    Attributes:
        valid: Does the context's parser accept these bytes without critical error?
        coverage: Fraction of byte range structurally accounted for [0.0, 1.0]
        structured_ranges: Which byte ranges map to which structural fields
        identity: The parsed structured object (if valid), or None
        errors: Any non-fatal parse warnings/errors encountered
    """
    valid: bool
    coverage: float
    structured_ranges: tuple[StructuredRange, ...]
    identity: Any = None
    errors: tuple[str, ...] = ()

    @property
    def is_strong(self) -> bool:
        """Whether this represents intentional (not coincidental) structure."""
        return self.valid and self.coverage >= 0.5

    @property
    def is_weak(self) -> bool:
        """Coincidental structure — bytes happen to parse but coverage is low."""
        return self.valid and self.coverage < 0.5

    @property
    def total_structured_bytes(self) -> int:
        """Total bytes claimed by structured ranges (non-overlapping)."""
        if not self.structured_ranges:
            return 0
        # Merge overlapping ranges to avoid double-counting
        sorted_ranges = sorted(self.structured_ranges, key=lambda r: r.start)
        merged = []
        for r in sorted_ranges:
            if merged and r.start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], r.end))
            else:
                merged.append([r.start, r.end])
        return sum(end - start for start, end in merged)

    def __repr__(self) -> str:
        strength = "STRONG" if self.is_strong else "WEAK" if self.valid else "INVALID"
        return (
            f"<Validity: {strength} valid={self.valid} "
            f"coverage={self.coverage:.2%} "
            f"fields={len(self.structured_ranges)}>"
        )


class Context(ABC):
    """Base class for all BIRL interpretation contexts.
    
    A Context encapsulates a specific parser / format spec / ISA definition.
    It answers the question: "Can these bytes be meaningfully viewed as X?"
    
    Subclasses implement:
        - name: Human-readable identifier
        - parse(): The actual parsing logic
        - threshold: Minimum coverage for "strong" identity (τ)
    
    Usage:
        ctx = PE_Context()
        result = ctx.satisfies(some_bytes)
        if result.valid and result.coverage > 0.8:
            # High confidence this is a PE file
            identity = result.identity
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this context (e.g., 'PE', 'ELF', 'x86_64')."""
        ...

    @property
    def threshold(self) -> float:
        """Coverage threshold τ for strong identity. Override per context."""
        return 0.5

    @property
    def version(self) -> str:
        """Version string for environment-specific contexts (e.g., DLL builds)."""
        return "generic"

    @abstractmethod
    def parse(self, data: bytes) -> ValidityTuple:
        """Apply this context's parser to the byte sequence.
        
        This is the core interpretation operation. Implementations must:
        1. Attempt to parse `data` according to this context's format spec
        2. Track which byte ranges map to structural fields
        3. Calculate coverage as (structured bytes / total bytes)
        4. Return a ValidityTuple with all findings
        
        Args:
            data: Raw byte sequence to interpret
            
        Returns:
            ValidityTuple with parse results, coverage, and field mappings
        """
        ...

    def satisfies(self, data: bytes) -> ValidityTuple:
        """The BIRL Satisfies predicate with coverage metrics.
        
        Wraps parse() with error handling and coverage calculation.
        This is the public API — subclasses override parse(), not this.
        """
        if not data:
            return ValidityTuple(
                valid=False,
                coverage=0.0,
                structured_ranges=(),
                errors=("Empty byte sequence",),
            )
        try:
            result = self.parse(data)
            # Recalculate coverage from structured ranges if parser didn't
            if result.structured_ranges and result.coverage == 0.0:
                total_structured = result.total_structured_bytes
                recalculated = total_structured / len(data) if data else 0.0
                result = ValidityTuple(
                    valid=result.valid,
                    coverage=min(recalculated, 1.0),
                    structured_ranges=result.structured_ranges,
                    identity=result.identity,
                    errors=result.errors,
                )
            return result
        except Exception as e:
            return ValidityTuple(
                valid=False,
                coverage=0.0,
                structured_ranges=(),
                errors=(f"Parse error: {e}",),
            )

    def get_claimed_offsets(self, data: bytes) -> set[int]:
        """Return all byte offsets claimed by this context.
        
        Used by ResidueCalculator to find unclaimed bytes.
        """
        result = self.satisfies(data)
        claimed = set()
        for sr in result.structured_ranges:
            claimed.update(range(sr.start, sr.end))
        return claimed

    def __repr__(self) -> str:
        return f"<Context:{self.name} v={self.version} τ={self.threshold}>"

    def __hash__(self) -> int:
        return hash((self.name, self.version))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Context):
            return NotImplemented
        return self.name == other.name and self.version == other.version


class RawContext(Context):
    """The trivial context — treats all bytes as an undifferentiated buffer.
    
    Every byte sequence satisfies Raw with 100% coverage (every byte is
    "accounted for" as a raw octet). This is the identity element of
    context composition — the starting point before any interpretation.
    """

    @property
    def name(self) -> str:
        return "Raw"

    @property
    def threshold(self) -> float:
        return 0.0  # Always strong

    def parse(self, data: bytes) -> ValidityTuple:
        return ValidityTuple(
            valid=True,
            coverage=1.0,
            structured_ranges=(
                StructuredRange(0, len(data), "raw_buffer", "Undifferentiated bytes"),
            ),
            identity={"type": "raw", "length": len(data), "data": data},
        )
