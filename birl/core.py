"""
BIRL Core: World and ByteSequence

The World is the interpretation graph — the registry of all known Contexts
and the edges between them. ByteSequence is the wrapper around raw bytes
that enables the fluent pipe-style API.

Usage:
    world = World()
    world.register(PE_Context())
    world.register(ELF_Context())
    
    payload = world.load("suspicious.dll")
    result = payload.interpreting_as("PE")
    print(result.validity)
    print(result.residue())
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from birl.context import Context, RawContext, ValidityTuple, StructuredRange
from birl.residue import ResidueCalculator, ResidueReport, ResidueRange
from birl.graph import InterpretationGraph, EdgeInfo, EdgeWeight, Strategy, MutationType
from birl.edges import register_standard_edges


class World:
    """The BIRL Interpretation Graph.
    
    Registry of all known Contexts. In Phase 2 this becomes a full
    NetworkX graph with weighted edges. For Phase 1, it's the context
    registry and the entry point for loading byte sequences.
    """

    def __init__(self) -> None:
        self._contexts: dict[str, Context] = {}
        self._residue_calc = ResidueCalculator()
        self._graph = InterpretationGraph()
        # Always register Raw as the identity context
        self.register(RawContext())

    def register(self, context: Context) -> None:
        """Register an interpretation context."""
        self._contexts[context.name] = context
        self._graph.register_context(context)

    def build_graph(self) -> None:
        """Build the standard edge library after all contexts are registered.
        
        Call this after registering all contexts to populate the
        interpretation graph with known transitions.
        """
        register_standard_edges(self._graph)

    @property
    def graph(self) -> InterpretationGraph:
        """Access the interpretation graph directly."""
        return self._graph

    def get_context(self, name: str) -> Context:
        """Retrieve a registered context by name."""
        if name not in self._contexts:
            raise KeyError(
                f"Unknown context '{name}'. "
                f"Registered: {list(self._contexts.keys())}"
            )
        return self._contexts[name]

    @property
    def contexts(self) -> list[str]:
        """List all registered context names."""
        return list(self._contexts.keys())

    def load(self, source: Union[str, bytes, Path]) -> ByteSequence:
        """Load bytes into the BIRL system.
        
        Equivalent to BIRL syntax: LOAD <source>
        
        Args:
            source: File path (str/Path) or raw bytes
            
        Returns:
            ByteSequence ready for interpretation
        """
        if isinstance(source, bytes):
            data = source
            origin = "<bytes>"
        elif isinstance(source, (str, Path)):
            path = Path(source)
            data = path.read_bytes()
            origin = str(path)
        else:
            raise TypeError(f"Cannot load from {type(source)}")

        return ByteSequence(
            data=data,
            origin=origin,
            world=self,
        )

    def identify(self, data: bytes) -> list[tuple[str, ValidityTuple]]:
        """Test bytes against ALL registered contexts.
        
        This is the "super-powered file command" from the Phase 1 roadmap.
        Returns all contexts that accept the bytes, sorted by coverage (desc).
        """
        results = []
        for name, ctx in self._contexts.items():
            if name == "Raw":
                continue  # Skip trivial context
            vt = ctx.satisfies(data)
            if vt.valid:
                results.append((name, vt))
        # Sort by coverage descending
        results.sort(key=lambda x: x[1].coverage, reverse=True)
        return results

    def __repr__(self) -> str:
        return f"<World: {len(self._contexts)} contexts registered>"


@dataclass
class InterpretationState:
    """The state of a byte sequence under a specific interpretation.
    
    Tracks the provenance chain (audit trail) as contexts are applied.
    """
    context_name: str
    validity: ValidityTuple
    byte_hash: str  # SHA-256 of current bytes
    parent: Optional[InterpretationState] = None

    @property
    def chain(self) -> list[str]:
        """The full context chain leading to this state."""
        states = []
        current: Optional[InterpretationState] = self
        while current is not None:
            states.append(current.context_name)
            current = current.parent
        return list(reversed(states))

    def __repr__(self) -> str:
        chain_str = " → ".join(self.chain)
        return f"<State: {chain_str} | {self.validity}>"


class ByteSequence:
    """A byte sequence with interpretation capabilities.
    
    This is the primary object users interact with. It wraps raw bytes
    and provides the fluent API for BIRL's pipe syntax:
    
        world.load("file.exe")
            .interpreting_as("PE")
            .select(".sections['.text']")
            .residue()
    """

    def __init__(
        self,
        data: bytes,
        origin: str,
        world: World,
        state: Optional[InterpretationState] = None,
    ) -> None:
        self._data = data
        self._origin = origin
        self._world = world
        self._state = state
        self._residue_calc = ResidueCalculator()

    @property
    def data(self) -> bytes:
        """The raw bytes."""
        return self._data

    @property
    def length(self) -> int:
        return len(self._data)

    @property
    def origin(self) -> str:
        """Where these bytes came from."""
        return self._origin

    @property
    def state(self) -> Optional[InterpretationState]:
        """Current interpretation state, if any context has been applied."""
        return self._state

    @property
    def hash(self) -> str:
        """SHA-256 of current bytes."""
        return hashlib.sha256(self._data).hexdigest()

    def interpreting_as(self, context_name: str) -> ByteSequence:
        """Apply an interpretation context. Equivalent to: | AS <context>
        
        Does NOT modify bytes. Applies the context's parser and records
        the interpretation state with coverage metrics.
        
        Args:
            context_name: Name of a registered context
            
        Returns:
            Self (for chaining), with updated interpretation state
        """
        ctx = self._world.get_context(context_name)
        validity = ctx.satisfies(self._data)

        new_state = InterpretationState(
            context_name=context_name,
            validity=validity,
            byte_hash=self.hash,
            parent=self._state,
        )

        return ByteSequence(
            data=self._data,
            origin=self._origin,
            world=self._world,
            state=new_state,
        )

    def select(self, selector: str) -> ByteSequence:
        """Narrow focus to a sub-structure. Equivalent to: | SELECT <path>
        
        Extracts a byte sub-range based on the current interpretation.
        
        Args:
            selector: Field path in current identity (e.g., ".sections['.text']")
            
        Returns:
            New ByteSequence containing only the selected bytes
        """
        if self._state is None or self._state.validity.identity is None:
            raise ValueError(
                "Cannot SELECT without an active interpretation. "
                "Apply a context first with .interpreting_as()"
            )

        identity = self._state.validity.identity

        # Handle dict-style access for parsed identities
        if isinstance(identity, dict) and "selections" in identity:
            selections = identity["selections"]
            if selector in selections:
                start, end = selections[selector]
                sub_data = self._data[start:end]
                return ByteSequence(
                    data=sub_data,
                    origin=f"{self._origin}|SELECT({selector})",
                    world=self._world,
                    state=self._state,
                )

        # Handle structured range lookup by field_id
        for sr in self._state.validity.structured_ranges:
            if sr.field_id == selector or f".{sr.field_id}" == selector:
                sub_data = self._data[sr.start:sr.end]
                return ByteSequence(
                    data=sub_data,
                    origin=f"{self._origin}|SELECT({selector})",
                    world=self._world,
                    state=self._state,
                )

        raise KeyError(
            f"Selector '{selector}' not found in current interpretation. "
            f"Available fields: {[sr.field_id for sr in self._state.validity.structured_ranges]}"
        )

    def residue(self, context_name: Optional[str] = None) -> ResidueReport:
        """Compute interpretation residue.
        
        If a context is active, computes residue for that context.
        If context_name is given, computes for that specific context.
        
        Returns:
            ResidueReport with unclaimed byte ranges and analysis
        """
        if context_name:
            ctx = self._world.get_context(context_name)
        elif self._state:
            ctx = self._world.get_context(self._state.context_name)
        else:
            raise ValueError(
                "No context specified. Either apply a context with "
                ".interpreting_as() or pass a context_name."
            )
        return self._residue_calc.analyze(self._data, [ctx])

    def superposition(self) -> list[tuple[str, ValidityTuple]]:
        """List all simultaneous valid identities.
        
        The Superposition State (BIRL v1.1 Sec 4.1):
        Ψ(b) = {(C, Identity) | Satisfies(b, C).valid = True}
        
        Returns:
            List of (context_name, ValidityTuple) for all valid contexts
        """
        return self._world.identify(self._data)

    def emit(self, path: str) -> None:
        """Write current bytes to a file. Equivalent to: | EMIT <path>"""
        Path(path).write_bytes(self._data)

    def __repr__(self) -> str:
        state_str = f" | {self._state}" if self._state else ""
        return f"<ByteSequence: {self.length} bytes from {self._origin}{state_str}>"

    def __len__(self) -> int:
        return self.length
