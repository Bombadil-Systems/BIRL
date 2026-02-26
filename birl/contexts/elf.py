"""
BIRL ELF Context — Executable and Linkable Format

Parses ELF binaries with structural coverage tracking.
"""

from __future__ import annotations

import struct
from birl.context import Context, ValidityTuple, StructuredRange


class ELF_Context(Context):

    @property
    def name(self) -> str:
        return "ELF"

    @property
    def threshold(self) -> float:
        return 0.3

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {}

        if len(data) < 16:
            return ValidityTuple(False, 0.0, (), errors=("Too small for ELF",))

        # ELF Magic
        if data[0:4] != b"\x7fELF":
            return ValidityTuple(False, 0.0, (), errors=("Bad ELF magic",))

        ranges.append(StructuredRange(0, 4, "elf_magic", "\\x7fELF"))

        # ELF identification bytes
        ei_class = data[4]   # 1=32bit, 2=64bit
        ei_data = data[5]    # 1=LE, 2=BE
        ei_version = data[6]

        ranges.append(StructuredRange(4, 16, "elf_ident", "ELF identification"))

        identity["class"] = "ELF64" if ei_class == 2 else "ELF32"
        identity["endian"] = "little" if ei_data == 1 else "big"

        is_64 = ei_class == 2
        fmt_prefix = "<" if ei_data == 1 else ">"

        # ELF Header
        if is_64:
            if len(data) < 64:
                return ValidityTuple(True, 0.0, tuple(ranges), identity=identity,
                                     errors=("Truncated ELF64 header",))
            hdr_fmt = f"{fmt_prefix}HHIQQQIHHHHHH"
            hdr_size = 64
            hdr = struct.unpack_from(hdr_fmt, data, 16)
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
                e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr
        else:
            if len(data) < 52:
                return ValidityTuple(True, 0.0, tuple(ranges), identity=identity,
                                     errors=("Truncated ELF32 header",))
            hdr_fmt = f"{fmt_prefix}HHIIIIIHHHHHH"
            hdr_size = 52
            hdr = struct.unpack_from(hdr_fmt, data, 16)
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
                e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr

        ranges.append(StructuredRange(16, hdr_size, "elf_header", "ELF header fields"))

        type_names = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
        identity["type"] = type_names.get(e_type, f"Unknown({e_type})")
        identity["machine"] = e_machine
        identity["entry_point"] = e_entry
        identity["ph_offset"] = e_phoff
        identity["sh_offset"] = e_shoff
        identity["num_program_headers"] = e_phnum
        identity["num_section_headers"] = e_shnum

        # Program Headers
        if e_phoff > 0 and e_phnum > 0:
            ph_total = e_phnum * e_phentsize
            if e_phoff + ph_total <= len(data):
                ranges.append(StructuredRange(
                    e_phoff, e_phoff + ph_total, "program_headers",
                    f"{e_phnum} program headers",
                ))

        # Section Headers
        selections = {}
        sections = []
        if e_shoff > 0 and e_shnum > 0:
            sh_total = e_shnum * e_shentsize
            if e_shoff + sh_total <= len(data):
                ranges.append(StructuredRange(
                    e_shoff, e_shoff + sh_total, "section_headers",
                    f"{e_shnum} section headers",
                ))

            # Parse each section header for data ranges
            for i in range(e_shnum):
                sh_off = e_shoff + (i * e_shentsize)
                if sh_off + e_shentsize > len(data):
                    break

                if is_64:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                        struct.unpack_from(f"{fmt_prefix}IIQQqq", data, sh_off)
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                        struct.unpack_from(f"{fmt_prefix}IIIIII", data, sh_off)

                # SHT_NOBITS (8) sections don't occupy file space
                if sh_type != 8 and sh_offset > 0 and sh_size > 0:
                    end = min(sh_offset + sh_size, len(data))
                    if sh_offset < len(data):
                        sec_id = f"section_{i}"
                        ranges.append(StructuredRange(
                            sh_offset, end, sec_id,
                            f"Section {i} data (type={sh_type})",
                        ))
                        selections[f".sections[{i}]"] = (sh_offset, end)

                sections.append({
                    "index": i,
                    "name_offset": sh_name,
                    "type": sh_type,
                    "flags": sh_flags,
                    "address": sh_addr,
                    "offset": sh_offset,
                    "size": sh_size,
                })

        identity["sections"] = sections
        identity["selections"] = selections

        # Coverage
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
