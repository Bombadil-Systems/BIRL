"""
BIRL PE Context — Windows Portable Executable

Parses PE files with full structural coverage tracking.
Every byte claimed by the PE format is mapped to a StructuredRange.
"""

from __future__ import annotations

import struct
from birl.context import Context, ValidityTuple, StructuredRange


class PE_Context(Context):

    @property
    def name(self) -> str:
        return "PE"

    @property
    def threshold(self) -> float:
        return 0.3  # PE files can have large data sections that are "unstructured"

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {}

        if len(data) < 64:
            return ValidityTuple(False, 0.0, (), errors=("Too small for PE",))

        # DOS Header (first 64 bytes)
        magic = data[0:2]
        if magic != b"MZ":
            return ValidityTuple(False, 0.0, (), errors=(f"Bad DOS magic: {magic!r}",))

        ranges.append(StructuredRange(0, 2, "dos_magic", "MZ signature"))

        # e_lfanew — offset to PE header
        if len(data) < 0x3C + 4:
            return ValidityTuple(False, 0.0, tuple(ranges), errors=("Truncated DOS header",))

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        ranges.append(StructuredRange(0x3C, 0x40, "e_lfanew", f"PE header offset: {e_lfanew:#x}"))
        # Claim the full DOS header
        ranges.append(StructuredRange(2, 0x3C, "dos_header_fields", "DOS header fields"))
        ranges.append(StructuredRange(0x40, min(e_lfanew, len(data)), "dos_stub", "DOS stub program"))

        identity["e_lfanew"] = e_lfanew

        # PE Signature
        if len(data) < e_lfanew + 4:
            return ValidityTuple(
                False, 0.0, tuple(ranges),
                errors=(f"Truncated at PE signature (need offset {e_lfanew})",),
            )

        pe_sig = data[e_lfanew:e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            return ValidityTuple(
                False, 0.0, tuple(ranges),
                errors=(f"Bad PE signature: {pe_sig!r}",),
            )

        ranges.append(StructuredRange(e_lfanew, e_lfanew + 4, "pe_signature", "PE\\0\\0"))

        # COFF Header (20 bytes after PE sig)
        coff_offset = e_lfanew + 4
        if len(data) < coff_offset + 20:
            return ValidityTuple(True, 0.0, tuple(ranges), identity=identity,
                                 errors=("Truncated COFF header",))

        machine, num_sections, timestamp, sym_table, num_symbols, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, coff_offset)

        ranges.append(StructuredRange(coff_offset, coff_offset + 20, "coff_header", "COFF file header"))

        identity["machine"] = machine
        identity["num_sections"] = num_sections
        identity["timestamp"] = timestamp
        identity["optional_header_size"] = opt_size
        identity["characteristics"] = characteristics

        machine_names = {0x14c: "i386", 0x8664: "AMD64", 0xAA64: "ARM64"}
        identity["machine_name"] = machine_names.get(machine, f"Unknown({machine:#x})")

        # Optional Header
        opt_offset = coff_offset + 20
        if opt_size > 0 and len(data) >= opt_offset + opt_size:
            ranges.append(StructuredRange(
                opt_offset, opt_offset + opt_size, "optional_header",
                f"Optional header ({opt_size} bytes)",
            ))

            # Parse PE32/PE32+ magic
            if opt_size >= 2:
                opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
                identity["pe_format"] = "PE32+" if opt_magic == 0x20B else "PE32"

                # Entry point and image base
                if opt_magic == 0x20B and opt_size >= 28:  # PE32+
                    entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
                    image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
                    identity["entry_point_rva"] = entry_rva
                    identity["image_base"] = image_base
                elif opt_magic == 0x10B and opt_size >= 32:  # PE32
                    entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
                    image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
                    identity["entry_point_rva"] = entry_rva
                    identity["image_base"] = image_base

        # Section Headers
        section_table_offset = opt_offset + opt_size
        sections = []
        selections = {}

        for i in range(num_sections):
            sh_offset = section_table_offset + (i * 40)
            if len(data) < sh_offset + 40:
                errors.append(f"Truncated section header {i}")
                break

            sec_name_raw = data[sh_offset:sh_offset + 8]
            sec_name = sec_name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
            virtual_size, virtual_addr, raw_size, raw_offset = \
                struct.unpack_from("<IIII", data, sh_offset + 8)
            characteristics_sec = struct.unpack_from("<I", data, sh_offset + 36)[0]

            ranges.append(StructuredRange(
                sh_offset, sh_offset + 40, f"section_header_{sec_name}",
                f"Section header: {sec_name}",
            ))

            # Claim the section's raw data
            if raw_offset > 0 and raw_size > 0 and raw_offset + raw_size <= len(data):
                ranges.append(StructuredRange(
                    raw_offset, raw_offset + raw_size, f"section_data_{sec_name}",
                    f"Section data: {sec_name}",
                ))
                selections[f".sections['{sec_name}']"] = (raw_offset, raw_offset + raw_size)

            sections.append({
                "name": sec_name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_addr,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics_sec,
            })

        identity["sections"] = sections
        identity["selections"] = selections

        # Calculate coverage
        total_claimed = 0
        claimed_set: set[int] = set()
        for r in ranges:
            claimed_set.update(range(r.start, min(r.end, len(data))))
        coverage = len(claimed_set) / len(data) if data else 0.0

        return ValidityTuple(
            valid=True,
            coverage=min(coverage, 1.0),
            structured_ranges=tuple(ranges),
            identity=identity,
            errors=tuple(errors),
        )
