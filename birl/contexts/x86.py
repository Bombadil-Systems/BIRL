"""
BIRL x86 Context

Interprets bytes as x86/x86_64 instructions. This is a simplified
disassembler focused on what BIRL needs:
- Pattern matching for gadget sequences (ret, pop reg; ret, etc.)
- Coverage metrics (what fraction of bytes form valid instructions?)
- Gadget discovery for OIS-ROP navigation

This is intentionally NOT a full disassembler. It recognizes common
instruction patterns and classifies bytes as valid/invalid x86.
For production use, this would wrap capstone or a similar engine.
"""

from __future__ import annotations

from birl.context import Context, ValidityTuple, StructuredRange


# Common x86_64 instruction patterns (opcode -> (name, length))
# This is a minimal set for gadget hunting; extend as needed
GADGET_PATTERNS: dict[bytes, tuple[str, str]] = {
    # POP register + RET gadgets (the bread and butter of ROP)
    b"\x58\xc3": ("pop_rax_ret", "pop rax; ret"),
    b"\x59\xc3": ("pop_rcx_ret", "pop rcx; ret"),
    b"\x5a\xc3": ("pop_rdx_ret", "pop rdx; ret"),
    b"\x5b\xc3": ("pop_rbx_ret", "pop rbx; ret"),
    b"\x5c\xc3": ("pop_rsp_ret", "pop rsp; ret"),
    b"\x5d\xc3": ("pop_rbp_ret", "pop rbp; ret"),
    b"\x5e\xc3": ("pop_rsi_ret", "pop rsi; ret"),
    b"\x5f\xc3": ("pop_rdi_ret", "pop rdi; ret"),
    # REX.W variants for r8-r15
    b"\x41\x58\xc3": ("pop_r8_ret", "pop r8; ret"),
    b"\x41\x59\xc3": ("pop_r9_ret", "pop r9; ret"),
    b"\x41\x5a\xc3": ("pop_r10_ret", "pop r10; ret"),
    b"\x41\x5b\xc3": ("pop_r11_ret", "pop r11; ret"),
    # Single-byte
    b"\xc3": ("ret", "ret"),
    b"\xcc": ("int3", "int3"),
    b"\x90": ("nop", "nop"),
    # Stack operations
    b"\xc9\xc3": ("leave_ret", "leave; ret"),
    # Useful MOV patterns
    b"\x48\x89\xc1\xc3": ("mov_rcx_rax_ret", "mov rcx, rax; ret"),
    b"\x48\x89\xc2\xc3": ("mov_rdx_rax_ret", "mov rdx, rax; ret"),
    # ADD RSP (shadow space skip)
    b"\x48\x83\xc4\x28\xc3": ("add_rsp_28_ret", "add rsp, 0x28; ret"),
    b"\x48\x83\xc4\x38\xc3": ("add_rsp_38_ret", "add rsp, 0x38; ret"),
}

# Single-byte opcode validity map (simplified)
# True = valid as single-byte or start of multi-byte instruction
VALID_LEAD_BYTES = set()
# Most bytes 0x00-0xFF can start SOME x86 instruction
# We mark the clearly invalid ones
for i in range(256):
    VALID_LEAD_BYTES.add(i)
# These are actually invalid/undefined as lead bytes in 64-bit mode
INVALID_LEAD_64 = {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F,
                    0x60, 0x61, 0x62, 0xD4, 0xD5, 0xD6, 0x82}


class x86_Context(Context):

    @property
    def name(self) -> str:
        return "x86_64"

    @property
    def threshold(self) -> float:
        return 0.7  # Code sections should be mostly valid instructions

    def _find_gadgets(self, data: bytes) -> list[tuple[int, str, str]]:
        """Scan for known gadget patterns. Returns (offset, gadget_id, description)."""
        found = []
        for pattern, (gid, desc) in GADGET_PATTERNS.items():
            plen = len(pattern)
            start = 0
            while True:
                idx = data.find(pattern, start)
                if idx < 0:
                    break
                found.append((idx, gid, desc))
                start = idx + 1
        found.sort(key=lambda x: x[0])
        return found

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"gadgets": [], "selections": {}}

        if len(data) < 1:
            return ValidityTuple(False, 0.0, (), errors=("Empty",))

        # Find all gadgets
        gadgets = self._find_gadgets(data)
        for offset, gid, desc in gadgets:
            # Find the pattern length
            for pattern, (pid, _) in GADGET_PATTERNS.items():
                if pid == gid:
                    plen = len(pattern)
                    break
            else:
                plen = 1

            ranges.append(StructuredRange(
                offset, offset + plen, f"gadget_{gid}_{offset:#x}",
                desc,
            ))
            identity["gadgets"].append({
                "id": gid,
                "offset": offset,
                "description": desc,
                "bytes": data[offset:offset + plen].hex(),
            })

        # Simple validity heuristic: check if lead bytes are valid x86_64
        valid_count = 0
        for i, b in enumerate(data):
            if b not in INVALID_LEAD_64:
                valid_count += 1

        # Coverage from gadgets
        claimed: set[int] = set()
        for r in ranges:
            claimed.update(range(r.start, min(r.end, len(data))))

        # For x86, "coverage" means "what fraction contains recognized patterns"
        # This is deliberately conservative — unknown instructions aren't claimed
        coverage = len(claimed) / len(data) if data else 0.0

        # But we also report a validity ratio based on lead byte analysis
        identity["valid_lead_byte_ratio"] = valid_count / len(data) if data else 0.0
        identity["num_gadgets"] = len(gadgets)

        # x86 is "valid" if the bytes could plausibly be code
        is_valid = identity["valid_lead_byte_ratio"] > 0.7

        return ValidityTuple(
            valid=is_valid,
            coverage=coverage,
            structured_ranges=tuple(ranges),
            identity=identity,
            errors=tuple(errors),
        )
