"""
BIRL Production x86 Context — Capstone Disassembler

Wraps Capstone — the industry-standard disassembly engine — as a
BIRL Context. Every successfully decoded instruction becomes a
StructuredRange, giving BIRL instruction-level coverage metrics.

What this catches that the minimal x86 context doesn't:
- Full instruction decoding (not just pattern matching)
- Variable-length instructions handled correctly
- All addressing modes
- Instruction classification (ret, call, jmp, etc.)
- Comprehensive gadget discovery
- ARM/ARM64 support (future)
"""

from __future__ import annotations

from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32,
    CS_GRP_RET, CS_GRP_CALL, CS_GRP_JUMP,
    CS_GRP_INT, CS_GRP_IRET,
)
from birl.context import Context, ValidityTuple, StructuredRange


# Gadget-ending instruction groups
GADGET_TERMINATORS = {CS_GRP_RET, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_INT, CS_GRP_IRET}


class x86ProductionContext(Context):

    def __init__(self, mode: str = "64"):
        self._mode = CS_MODE_64 if mode == "64" else CS_MODE_32
        self._mode_name = mode

    @property
    def name(self) -> str:
        return f"x86_{self._mode_name}"

    @property
    def threshold(self) -> float:
        return 0.5

    @property
    def version(self) -> str:
        return "capstone"

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {
            "instructions": [],
            "gadgets": [],
            "selections": {},
            "stats": {},
        }

        if len(data) < 1:
            return ValidityTuple(False, 0.0, (), errors=("Empty",))

        md = Cs(CS_ARCH_X86, self._mode)
        md.detail = True

        total_decoded = 0
        total_bytes_decoded = 0
        instructions = []
        gadget_candidates = []

        for insn in md.disasm(data, 0):
            total_decoded += 1
            total_bytes_decoded += insn.size

            ranges.append(StructuredRange(
                insn.address, insn.address + insn.size,
                f"insn_{insn.address:#x}",
                f"{insn.mnemonic} {insn.op_str}",
            ))

            insn_info = {
                "address": insn.address,
                "size": insn.size,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": data[insn.address:insn.address + insn.size].hex(),
            }
            instructions.append(insn_info)

            # Check for gadget-terminating instructions
            is_terminator = False
            if insn.groups:
                for group in insn.groups:
                    if group in GADGET_TERMINATORS:
                        is_terminator = True
                        break

            if is_terminator:
                gadget_candidates.append(insn_info)

        # Store only first 1000 instructions in identity to avoid memory issues
        identity["instructions"] = instructions[:1000]
        identity["total_instructions"] = total_decoded

        # --- Gadget Discovery ---
        # Walk backward from each RET to find usable gadgets
        gadgets = self._find_gadgets(data, md)
        identity["gadgets"] = gadgets
        identity["num_gadgets"] = len(gadgets)

        # --- Stats ---
        coverage = total_bytes_decoded / len(data) if data else 0.0
        identity["stats"] = {
            "total_bytes": len(data),
            "decoded_bytes": total_bytes_decoded,
            "coverage": coverage,
            "total_instructions": total_decoded,
            "gadgets_found": len(gadgets),
        }

        # x86 is "valid" if we can decode a significant fraction
        is_valid = coverage > 0.3 and total_decoded > 0

        return ValidityTuple(
            valid=is_valid,
            coverage=coverage,
            structured_ranges=tuple(ranges),
            identity=identity,
            errors=tuple(errors),
        )

    def _find_gadgets(
        self,
        data: bytes,
        md: Cs,
        max_gadget_len: int = 6,
        max_insn_count: int = 5,
    ) -> list[dict]:
        """Find ROP gadgets by searching backward from every RET instruction.
        
        For each RET (0xC3), try disassembling from 1..max_gadget_len bytes
        before it. If the disassembly reaches the RET cleanly, it's a gadget.
        """
        gadgets = []
        seen_offsets: set[int] = set()

        # Find all RET positions
        ret_positions = []
        for i, b in enumerate(data):
            if b == 0xC3:
                ret_positions.append(i)

        for ret_pos in ret_positions:
            for back in range(1, max_gadget_len + 1):
                start = ret_pos - back
                if start < 0:
                    continue
                if start in seen_offsets:
                    continue

                gadget_bytes = data[start:ret_pos + 1]
                # Try to disassemble
                insns = list(md.disasm(gadget_bytes, start))

                if not insns:
                    continue

                # Check if the disassembly reaches exactly the RET
                total_len = sum(i.size for i in insns)
                if total_len != len(gadget_bytes):
                    continue

                # Check last instruction is RET
                if insns[-1].mnemonic != "ret":
                    continue

                # Must have at least one instruction before the RET
                if len(insns) < 2:
                    if back == 0:
                        continue  # Bare RET — we'll include it but mark it

                # Valid gadget
                if len(insns) <= max_insn_count:
                    gadget_str = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
                    gadget_id = insns[0].mnemonic
                    if insns[0].op_str:
                        gadget_id += f"_{insns[0].op_str.replace(',', '').replace(' ', '_')}"
                    gadget_id += "_ret"

                    gadgets.append({
                        "id": gadget_id,
                        "offset": start,
                        "length": len(gadget_bytes),
                        "bytes": gadget_bytes.hex(),
                        "instructions": gadget_str,
                        "num_insns": len(insns),
                    })
                    seen_offsets.add(start)

        # Sort by offset
        gadgets.sort(key=lambda g: g["offset"])

        # Deduplicate by instruction string
        unique_gadgets = []
        seen_insns: set[str] = set()
        for g in gadgets:
            if g["instructions"] not in seen_insns:
                unique_gadgets.append(g)
                seen_insns.add(g["instructions"])

        return unique_gadgets

    def find_specific_gadget(
        self,
        data: bytes,
        pattern: str,
    ) -> list[dict]:
        """Search for a specific gadget pattern like 'pop rcx ; ret'."""
        md = Cs(CS_ARCH_X86, self._mode)
        md.detail = True

        all_gadgets = self._find_gadgets(data, md)
        pattern_lower = pattern.lower().strip()

        return [
            g for g in all_gadgets
            if pattern_lower in g["instructions"].lower()
        ]
