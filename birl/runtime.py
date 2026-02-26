"""
BIRL Runtime Engine (Phase 3)

Executes compiled BIRL programs (PipelineNode ASTs) against a World.

The Runtime:
1. Takes a compiled AST and a World (with graph)
2. Steps through each operation in the pipeline
3. Maintains execution state (current bytes, labels, coordinates, provenance)
4. Produces artifacts (files, coordinate lists, reports)

This is the "Rewriter" — the component that makes BIRL programs actionable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from birl.core import World, ByteSequence
from birl.context import ValidityTuple
from birl.graph import Strategy
from birl.residue import ResidueCalculator, ResidueReport
from birl.compiler import (
    PipelineNode,
    LoadNode,
    AsNode,
    SelectNode,
    RewriteNode,
    EmitNode,
    AssertNode,
    FindOffsetNode,
    SaveCoordinateNode,
    LabelNode,
    RevertToNode,
    ResidueNode,
    EmitStructureNode,
    FindPathNode,
    ASTNode,
)
from birl.forge import (
    PolyglotForge,
    ROPForge,
    StripForge,
    WrapForge,
    ForgeResult,
    ROPChain,
)


class RuntimeError_(Exception):
    """BIRL runtime error."""
    def __init__(self, message: str, operation: Optional[ASTNode] = None):
        op_str = f" at {type(operation).__name__}" if operation else ""
        super().__init__(f"Runtime error{op_str}: {message}")
        self.operation = operation


@dataclass
class Coordinate:
    """A saved coordinate — an offset within interpretation space."""
    name: str
    offset: int
    context: str
    pattern: str = ""
    description: str = ""

    def __repr__(self) -> str:
        return f"<Coord:{self.name} offset={self.offset:#x} ctx={self.context}>"


@dataclass
class ExecutionState:
    """Runtime state during BIRL program execution."""
    # Current byte sequence being operated on
    current: Optional[ByteSequence] = None
    # Named labels (snapshots of state for REVERT_TO)
    labels: dict[str, ByteSequence] = field(default_factory=dict)
    # Saved coordinates (for SAVE_COORDINATE / EMIT_STRUCTURE)
    coordinates: dict[str, Coordinate] = field(default_factory=dict)
    # Provenance log (audit trail)
    provenance: list[dict[str, Any]] = field(default_factory=list)
    # Emitted artifacts
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    # Assertion results
    assertions: list[dict[str, Any]] = field(default_factory=list)
    # Current active context name
    active_context: Optional[str] = None

    def log(self, operation: str, details: dict[str, Any]) -> None:
        """Add to provenance trail."""
        import hashlib
        entry = {
            "step": len(self.provenance),
            "operation": operation,
            "byte_hash": hashlib.sha256(self.current.data).hexdigest()[:16] if self.current else None,
            "byte_length": self.current.length if self.current else 0,
            "active_context": self.active_context,
            **details,
        }
        self.provenance.append(entry)


@dataclass
class ExecutionResult:
    """The result of executing a BIRL program."""
    success: bool
    state: ExecutionState
    errors: list[str] = field(default_factory=list)

    @property
    def coordinates(self) -> dict[str, Coordinate]:
        return self.state.coordinates

    @property
    def artifacts(self) -> list[dict[str, Any]]:
        return self.state.artifacts

    @property
    def provenance(self) -> list[dict[str, Any]]:
        return self.state.provenance

    def summary(self) -> str:
        lines = [
            f"BIRL Execution {'SUCCESS' if self.success else 'FAILED'}",
            f"  Steps: {len(self.state.provenance)}",
            f"  Coordinates: {len(self.state.coordinates)}",
            f"  Artifacts: {len(self.state.artifacts)}",
            f"  Assertions: {len(self.state.assertions)} "
            f"({sum(1 for a in self.state.assertions if a['passed'])} passed)",
        ]
        if self.errors:
            lines.append(f"  Errors: {self.errors}")
        if self.state.coordinates:
            lines.append("  Saved coordinates:")
            for name, coord in self.state.coordinates.items():
                lines.append(f"    {coord}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<ExecutionResult: {'OK' if self.success else 'FAIL'} steps={len(self.state.provenance)}>"


class Runtime:
    """BIRL program execution engine.
    
    Usage:
        world = World()
        # ... register contexts, build graph ...
        
        runtime = Runtime(world)
        result = runtime.execute(compiled_ast)
        
        # Or from source:
        result = runtime.run(birl_source_code)
    """

    def __init__(self, world: World) -> None:
        self._world = world
        self._residue_calc = ResidueCalculator()

    def execute(self, program: PipelineNode) -> ExecutionResult:
        """Execute a compiled BIRL program."""
        state = ExecutionState()
        errors: list[str] = []

        for op in program.operations:
            try:
                self._execute_op(op, state)
            except RuntimeError_ as e:
                errors.append(str(e))
                state.log("ERROR", {"error": str(e)})
                return ExecutionResult(success=False, state=state, errors=errors)
            except Exception as e:
                errors.append(f"Unexpected error: {e}")
                state.log("ERROR", {"error": str(e)})
                return ExecutionResult(success=False, state=state, errors=errors)

        return ExecutionResult(success=True, state=state, errors=errors)

    def run(self, source: str) -> ExecutionResult:
        """Compile and execute BIRL source code."""
        from birl.compiler import compile_birl
        program = compile_birl(source)
        return self.execute(program)

    def _execute_op(self, op: ASTNode, state: ExecutionState) -> None:
        """Dispatch to the appropriate handler."""
        handlers = {
            LoadNode: self._exec_load,
            AsNode: self._exec_as,
            SelectNode: self._exec_select,
            RewriteNode: self._exec_rewrite,
            EmitNode: self._exec_emit,
            AssertNode: self._exec_assert,
            FindOffsetNode: self._exec_find_offset,
            SaveCoordinateNode: self._exec_save_coordinate,
            LabelNode: self._exec_label,
            RevertToNode: self._exec_revert_to,
            ResidueNode: self._exec_residue,
            EmitStructureNode: self._exec_emit_structure,
            FindPathNode: self._exec_find_path,
        }

        handler = handlers.get(type(op))
        if handler is None:
            raise RuntimeError_(f"No handler for {type(op).__name__}", op)
        handler(op, state)

    # ------------------------------------------------------------------
    # Operation Handlers
    # ------------------------------------------------------------------

    def _exec_load(self, op: LoadNode, state: ExecutionState) -> None:
        """LOAD <path_or_bytes>"""
        try:
            state.current = self._world.load(op.source)
        except FileNotFoundError:
            raise RuntimeError_(f"File not found: {op.source}", op)
        state.active_context = None
        state.log("LOAD", {"source": op.source, "size": state.current.length})

    def _exec_as(self, op: AsNode, state: ExecutionState) -> None:
        """AS <context> — apply interpretation"""
        if state.current is None:
            raise RuntimeError_("No data loaded. Use LOAD first.", op)

        state.current = state.current.interpreting_as(op.context_name)
        state.active_context = op.context_name

        vt = state.current.state.validity
        state.log("AS", {
            "context": op.context_name,
            "valid": vt.valid,
            "coverage": f"{vt.coverage:.2%}",
            "fields": len(vt.structured_ranges),
            "kwargs": op.kwargs,
        })

    def _exec_select(self, op: SelectNode, state: ExecutionState) -> None:
        """SELECT <path> — narrow to sub-structure"""
        if state.current is None:
            raise RuntimeError_("No data loaded.", op)

        # Handle RESIDUE as a special selector
        if op.selector == "RESIDUE":
            self._exec_residue(ResidueNode(), state)
            return

        try:
            state.current = state.current.select(op.selector)
        except (KeyError, ValueError) as e:
            raise RuntimeError_(str(e), op)

        state.log("SELECT", {
            "selector": op.selector,
            "result_size": state.current.length,
        })

    def _exec_rewrite(self, op: RewriteNode, state: ExecutionState) -> None:
        """REWRITE <strategy> — apply transformation.
        
        Strategies:
        Basic mutations:
          - nop_sled: Replace bytes with NOPs
          - zero_fill: Replace with zeros
          - xor: XOR with key
          - pad_to_alignment: Pad to alignment boundary
          
        Forge operations (the real transformations):
          - strip: Veriduct-style format destruction (zeroes structural headers)
          - chunk: Split into opaque chunks
          - wrap_png: Wrap current bytes in a PNG container
          - wrap_zip: Wrap current bytes in a ZIP archive
          - inject: Inject payload into residue of a file
          - polyglot_append: Append current bytes to create a polyglot
          - build_rop: Assemble saved coordinates into a ROP chain
        """
        if state.current is None:
            raise RuntimeError_("No data loaded.", op)

        strategy = op.strategy.lower()
        data = bytearray(state.current.data)

        # === Basic Mutations ===
        if strategy == "nop_sled":
            length = int(op.kwargs.get("length", len(data)))
            for i in range(min(length, len(data))):
                data[i] = 0x90
            state.current = self._world.load(bytes(data))

        elif strategy == "zero_fill":
            length = int(op.kwargs.get("length", len(data)))
            for i in range(min(length, len(data))):
                data[i] = 0x00
            state.current = self._world.load(bytes(data))

        elif strategy == "pad_to_alignment":
            alignment = int(op.kwargs.get("alignment", "4"))
            remainder = len(data) % alignment
            if remainder > 0:
                data.extend(b"\x00" * (alignment - remainder))
            state.current = self._world.load(bytes(data))

        elif strategy == "xor":
            key = int(op.kwargs.get("key", "0xFF"), 0)
            data = bytearray(b ^ key for b in data)
            state.current = self._world.load(bytes(data))

        # === Forge: Format Destruction (Veriduct) ===
        elif strategy == "strip":
            if not state.active_context:
                raise RuntimeError_("REWRITE strip requires an active context (use AS first)", op)
            ctx = self._world.get_context(state.active_context)
            forge = StripForge()
            result = forge.strip_headers(state.current.data, ctx)
            if not result.success:
                raise RuntimeError_(f"Strip failed: {result.errors}", op)
            state.current = self._world.load(result.data)
            state.artifacts.append({
                "type": "forge_result", "operation": "strip",
                "forge_result": result,
            })

        elif strategy == "chunk":
            chunk_size = int(op.kwargs.get("size", "256"))
            xor_key = int(op.kwargs.get("key", "0"), 0)
            forge = StripForge()
            chunks = forge.chunk(state.current.data, chunk_size, xor_key)
            state.artifacts.append({
                "type": "forge_chunks", "operation": "chunk",
                "num_chunks": len(chunks),
                "chunk_size": chunk_size,
                "xor_key": xor_key,
                "chunks": chunks,
            })
            # State becomes the first chunk (user can iterate)
            if chunks:
                state.current = self._world.load(chunks[0].data)

        # === Forge: Wrap (Beauty) ===
        elif strategy == "wrap_png":
            width = int(op.kwargs.get("width", "16"))
            forge = WrapForge()
            result = forge.wrap_as_png(state.current.data, width=width)
            state.current = self._world.load(result.data)
            state.artifacts.append({
                "type": "forge_result", "operation": "wrap_png",
                "forge_result": result,
            })

        elif strategy == "wrap_zip":
            filename = op.kwargs.get("filename", "payload.bin")
            forge = WrapForge()
            result = forge.wrap_as_zip(state.current.data, filename=filename)
            state.current = self._world.load(result.data)
            state.artifacts.append({
                "type": "forge_result", "operation": "wrap_zip",
                "forge_result": result,
            })

        # === Forge: Polyglot ===
        elif strategy == "polyglot_append":
            target_ctx_name = op.kwargs.get("target", op.kwargs.get("as", ""))
            if not target_ctx_name:
                raise RuntimeError_("polyglot_append requires target= context name", op)
            if not state.active_context:
                raise RuntimeError_("polyglot_append requires an active context", op)

            # The "payload" to append should be in a label or provided
            payload_label = op.kwargs.get("payload", "")
            if payload_label and payload_label in state.labels:
                payload_data = state.labels[payload_label].data
            else:
                raise RuntimeError_(
                    "polyglot_append requires payload= label name", op
                )

            primary_ctx = self._world.get_context(state.active_context)
            target_ctx = self._world.get_context(target_ctx_name)
            forge = PolyglotForge()
            result = forge.append(state.current.data, primary_ctx, payload_data, target_ctx)

            state.current = self._world.load(result.data)
            state.artifacts.append({
                "type": "forge_result", "operation": "polyglot_append",
                "forge_result": result,
                "is_valid_polyglot": result.is_valid_polyglot,
            })

        # === Forge: Residue Injection ===
        elif strategy == "inject":
            if not state.active_context:
                raise RuntimeError_("REWRITE inject requires an active context", op)
            payload_hex = op.kwargs.get("payload", "")
            if not payload_hex:
                raise RuntimeError_("inject requires payload= (hex string)", op)
            try:
                payload_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
            except ValueError:
                raise RuntimeError_(f"Invalid hex payload: {payload_hex}", op)

            offset_str = op.kwargs.get("offset", "")
            offset = int(offset_str, 0) if offset_str else None

            ctx = self._world.get_context(state.active_context)
            forge = PolyglotForge()
            result = forge.inject_into_residue(
                state.current.data, ctx, payload_bytes, target_offset=offset,
            )
            if not result.success:
                raise RuntimeError_(f"Injection failed: {result.errors}", op)
            state.current = self._world.load(result.data)
            state.artifacts.append({
                "type": "forge_result", "operation": "inject",
                "forge_result": result,
            })

        # === Forge: ROP Chain Assembly ===
        elif strategy == "build_rop":
            base_addr = int(op.kwargs.get("base", "0"), 0)
            ptr_size = int(op.kwargs.get("ptr_size", "8"))

            forge = ROPForge(pointer_size=ptr_size, base_address=base_addr)
            chain = forge.chain_from_coordinates(
                state.coordinates,
                # Build spec from all saved coordinates in order
                [(name, None) for name in state.coordinates.keys()],
            )

            state.artifacts.append({
                "type": "rop_chain",
                "operation": "build_rop",
                "chain": chain,
                "hexdump": chain.hexdump(),
            })
            state.current = self._world.load(chain.raw_bytes)

        else:
            raise RuntimeError_(f"Unknown rewrite strategy: {strategy}", op)

        state.log("REWRITE", {
            "strategy": strategy,
            "kwargs": op.kwargs,
            "result_size": state.current.length if state.current else 0,
        })

    def _exec_emit(self, op: EmitNode, state: ExecutionState) -> None:
        """EMIT <target> — output current bytes"""
        if state.current is None:
            raise RuntimeError_("No data to emit.", op)

        artifact = {
            "type": "bytes",
            "target": op.target,
            "size": state.current.length,
            "data": state.current.data,
        }

        if op.target and op.target != "":
            # Write to file
            Path(op.target).write_bytes(state.current.data)
            artifact["written_to"] = op.target

        state.artifacts.append(artifact)
        state.log("EMIT", {"target": op.target, "size": state.current.length})

    def _exec_assert(self, op: AssertNode, state: ExecutionState) -> None:
        """ASSERT <condition> — verify a property"""
        if state.current is None:
            raise RuntimeError_("No data to assert against.", op)

        condition = op.condition.strip()
        passed = False
        details = {}

        # SATISFIES(Context) or SATISFIES(Context, coverage=X)
        sat_match = _match_satisfies(condition)
        if sat_match:
            ctx_name = sat_match["context"]
            min_coverage = float(op.kwargs.get("coverage", sat_match.get("coverage", "0.0")))
            ctx = self._world.get_context(ctx_name)
            vt = ctx.satisfies(state.current.data)
            passed = vt.valid and vt.coverage >= min_coverage
            details = {
                "check": "SATISFIES",
                "context": ctx_name,
                "valid": vt.valid,
                "coverage": vt.coverage,
                "required_coverage": min_coverage,
            }

        # NOT_SATISFIES(Context)
        elif condition.startswith("NOT_SATISFIES"):
            import re
            m = re.match(r"NOT_SATISFIES\((\w+)\)", condition)
            if m:
                ctx_name = m.group(1)
                ctx = self._world.get_context(ctx_name)
                vt = ctx.satisfies(state.current.data)
                passed = not vt.valid
                details = {"check": "NOT_SATISFIES", "context": ctx_name, "valid": vt.valid}

        # COVERAGE > X
        elif "COVERAGE" in condition:
            import re
            m = re.match(r"COVERAGE\s*(>|>=|<|<=|==)\s*([\d.]+)", condition)
            if m and state.active_context:
                op_str, threshold = m.group(1), float(m.group(2))
                ctx = self._world.get_context(state.active_context)
                vt = ctx.satisfies(state.current.data)
                cov = vt.coverage
                if op_str == ">": passed = cov > threshold
                elif op_str == ">=": passed = cov >= threshold
                elif op_str == "<": passed = cov < threshold
                elif op_str == "<=": passed = cov <= threshold
                elif op_str == "==": passed = abs(cov - threshold) < 0.01
                details = {"check": "COVERAGE", "coverage": cov, "threshold": threshold, "op": op_str}

        else:
            details = {"check": "UNKNOWN", "raw_condition": condition}
            passed = False

        state.assertions.append({"condition": condition, "passed": passed, **details})
        state.log("ASSERT", {"condition": condition, "passed": passed, **details})

        if not passed:
            raise RuntimeError_(
                f"Assertion failed: {condition} — {details}", op
            )

    def _exec_find_offset(self, op: FindOffsetNode, state: ExecutionState) -> None:
        """FIND_OFFSET PATTERN="xx xx" — locate byte pattern"""
        if state.current is None:
            raise RuntimeError_("No data to search.", op)

        pattern = op.pattern
        if not pattern:
            raise RuntimeError_("FIND_OFFSET requires PATTERN=", op)

        # Parse hex pattern (e.g., "59 C3" → b"\x59\xc3")
        try:
            pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
        except ValueError as e:
            raise RuntimeError_(f"Invalid hex pattern: {e}", op)

        # Find all occurrences
        data = state.current.data
        offsets = []
        start = 0
        while True:
            idx = data.find(pattern_bytes, start)
            if idx < 0:
                break
            offsets.append(idx)
            start = idx + 1

        if not offsets:
            raise RuntimeError_(
                f"Pattern {pattern!r} not found in {len(data)} bytes", op
            )

        # Store the FIRST match as the "current find" for SAVE_COORDINATE
        state.log("FIND_OFFSET", {
            "pattern": pattern,
            "matches": len(offsets),
            "first_offset": f"{offsets[0]:#x}",
            "all_offsets": [f"{o:#x}" for o in offsets],
        })

        # Stash in state for SAVE_COORDINATE to pick up
        state._last_find_offset = offsets[0]
        state._last_find_pattern = pattern
        state._last_find_all = offsets

    def _exec_save_coordinate(self, op: SaveCoordinateNode, state: ExecutionState) -> None:
        """SAVE_COORDINATE AS "name" — save the last found offset"""
        offset = getattr(state, "_last_find_offset", None)
        if offset is None:
            raise RuntimeError_("No offset to save. Use FIND_OFFSET first.", op)

        pattern = getattr(state, "_last_find_pattern", "")
        coord = Coordinate(
            name=op.name,
            offset=offset,
            context=state.active_context or "Raw",
            pattern=pattern,
        )
        state.coordinates[op.name] = coord
        state.log("SAVE_COORDINATE", {"name": op.name, "offset": f"{offset:#x}"})

    def _exec_label(self, op: LabelNode, state: ExecutionState) -> None:
        """LABEL <name> — snapshot current state"""
        if state.current is None:
            raise RuntimeError_("No data to label.", op)
        state.labels[op.name] = state.current
        state.log("LABEL", {"name": op.name})

    def _exec_revert_to(self, op: RevertToNode, state: ExecutionState) -> None:
        """REVERT_TO <label> — restore to labeled state"""
        if op.label not in state.labels:
            raise RuntimeError_(f"Unknown label: {op.label}", op)
        state.current = state.labels[op.label]
        state.log("REVERT_TO", {"label": op.label})

    def _exec_residue(self, op: ResidueNode, state: ExecutionState) -> None:
        """RESIDUE — compute residue for current context"""
        if state.current is None or state.active_context is None:
            raise RuntimeError_("Need active interpretation for RESIDUE.", op)

        report = state.current.residue(state.active_context)
        state.artifacts.append({
            "type": "residue_report",
            "context": state.active_context,
            "report": report,
        })
        state.log("RESIDUE", {
            "context": state.active_context,
            "total_residue": report.total_residue_bytes,
            "ratio": f"{report.residue_ratio:.1%}",
            "regions": len(report.residue_ranges),
        })

    def _exec_emit_structure(self, op: EmitStructureNode, state: ExecutionState) -> None:
        """EMIT_STRUCTURE [...] AS <name> — build coordinate payload"""
        structure = []
        for elem in op.elements:
            # Is it a saved coordinate name?
            if elem in state.coordinates:
                structure.append({
                    "type": "coordinate",
                    "name": elem,
                    "offset": state.coordinates[elem].offset,
                })
            # Hex literal?
            elif elem.startswith("0x") or elem.startswith("0X"):
                structure.append({
                    "type": "literal",
                    "value": int(elem, 16),
                })
            # Decimal literal?
            elif elem.isdigit():
                structure.append({
                    "type": "literal",
                    "value": int(elem),
                })
            else:
                structure.append({
                    "type": "reference",
                    "name": elem,
                })

        artifact = {
            "type": "rop_payload" if op.target_name else "structure",
            "name": op.target_name,
            "elements": structure,
            "total_elements": len(structure),
        }
        state.artifacts.append(artifact)
        state.log("EMIT_STRUCTURE", {
            "name": op.target_name,
            "elements": len(structure),
        })

    def _exec_find_path(self, op: FindPathNode, state: ExecutionState) -> None:
        """FIND_PATH SOURCE=X TARGET=Y — graph pathfinding"""
        strategy_name = op.kwargs.get("STRATEGY", op.kwargs.get("strategy", "balanced"))
        strategy_map = {
            "zero_copy": Strategy.ZERO_COPY,
            "robust": Strategy.ROBUST,
            "sanitization": Strategy.SANITIZATION,
            "fastest": Strategy.FASTEST,
            "balanced": Strategy.BALANCED,
        }
        strategy = strategy_map.get(strategy_name.lower(), Strategy.BALANCED)

        path = self._world.graph.find_path(
            op.source, op.target, strategy,
            data=state.current.data if state.current else None,
        )

        if path is None:
            raise RuntimeError_(
                f"No path from {op.source} to {op.target} under {strategy_name}", op
            )

        route = [path[0].source] + [e.target for e in path] if path else []
        total_weight = self._world.graph.path_total_weight(path) if path else None

        state.artifacts.append({
            "type": "path",
            "source": op.source,
            "target": op.target,
            "strategy": strategy_name,
            "route": route,
            "hops": len(path),
            "total_weight": {
                "mutation": total_weight.mutation.name,
                "fidelity": total_weight.fidelity,
                "stability": total_weight.stability,
                "cost": total_weight.cost,
            } if total_weight else None,
        })
        state.log("FIND_PATH", {
            "source": op.source,
            "target": op.target,
            "strategy": strategy_name,
            "route": " → ".join(route),
            "hops": len(path),
        })


# ============================================================================
# Helpers
# ============================================================================

def _match_satisfies(condition: str) -> Optional[dict]:
    """Parse SATISFIES(Context) or SATISFIES(Context, coverage=X)."""
    import re
    # Handle both compact and space-separated forms from the lexer
    cleaned = condition.replace(" ", "")
    m = re.match(r"SATISFIES\((\w+)(?:,?coverage=([\d.]+))?\)", cleaned)
    if m:
        result = {"context": m.group(1)}
        if m.group(2):
            result["coverage"] = m.group(2)
        return result
    return None
