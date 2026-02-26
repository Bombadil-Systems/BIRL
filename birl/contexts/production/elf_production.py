"""
BIRL Production ELF Context — Kaitai Struct

Wraps the Kaitai-compiled ELF parser for production-grade parsing.
"""

from __future__ import annotations

import io
import struct
from kaitaistruct import KaitaiStream
from birl.kaitai_parsers.elf import Elf as KaitaiElf
from birl.context import Context, ValidityTuple, StructuredRange


class ELFProductionContext(Context):

    @property
    def name(self) -> str:
        return "ELF"

    @property
    def threshold(self) -> float:
        return 0.3

    @property
    def version(self) -> str:
        return "kaitai"

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"sections": [], "segments": [], "selections": {}}

        if len(data) < 16:
            return ValidityTuple(False, 0.0, (), errors=("Too small for ELF",))

        if data[0:4] != b"\x7fELF":
            return ValidityTuple(False, 0.0, (), errors=("Bad ELF magic",))

        try:
            stream = KaitaiStream(io.BytesIO(data))
            elf = KaitaiElf(stream)
        except Exception as e:
            return ValidityTuple(False, 0.0, (), errors=(f"Kaitai parse error: {e}",))

        # ELF identification (16 bytes)
        ranges.append(StructuredRange(0, 16, "elf_ident", "ELF identification"))

        ei_class = data[4]
        identity["class"] = "ELF64" if ei_class == 2 else "ELF32"
        identity["endian"] = "little" if data[5] == 1 else "big"

        is_64 = ei_class == 2
        fmt = "<" if data[5] == 1 else ">"

        # ELF header
        hdr_size = 64 if is_64 else 52
        ranges.append(StructuredRange(16, hdr_size, "elf_header", "ELF header"))

        try:
            header = elf.header
            identity["type"] = str(header.e_type) if hasattr(header, "e_type") else "?"
            identity["machine"] = str(header.machine) if hasattr(header, "machine") else "?"
            identity["entry_point"] = header.entry_point if hasattr(header, "entry_point") else 0

            # Program headers
            if hasattr(header, "program_headers") and header.program_headers:
                ph_offset = header.ofs_program_headers
                ph_size = header.program_header_size
                ph_count = header.num_program_headers

                if ph_offset and ph_count:
                    ph_total = ph_count * ph_size
                    if ph_offset + ph_total <= len(data):
                        ranges.append(StructuredRange(
                            ph_offset, ph_offset + ph_total,
                            "program_headers", f"{ph_count} program headers",
                        ))

                    for i, phdr in enumerate(header.program_headers):
                        try:
                            seg_offset = phdr.offset
                            seg_filesz = phdr.filesz
                            seg_type = str(phdr.type)

                            if seg_offset > 0 and seg_filesz > 0 and seg_offset + seg_filesz <= len(data):
                                ranges.append(StructuredRange(
                                    seg_offset, seg_offset + seg_filesz,
                                    f"segment_{i}", f"Segment {i} ({seg_type}, {seg_filesz}B)",
                                ))
                            identity["segments"].append({
                                "index": i,
                                "type": seg_type,
                                "offset": seg_offset,
                                "filesz": seg_filesz,
                            })
                        except Exception as e:
                            errors.append(f"Segment {i} error: {e}")

            # Section headers
            if hasattr(header, "section_headers") and header.section_headers:
                sh_offset = header.ofs_section_headers
                sh_size = header.section_header_size
                sh_count = header.num_section_headers

                if sh_offset and sh_count:
                    sh_total = sh_count * sh_size
                    if sh_offset + sh_total <= len(data):
                        ranges.append(StructuredRange(
                            sh_offset, sh_offset + sh_total,
                            "section_headers", f"{sh_count} section headers",
                        ))

                    for i, shdr in enumerate(header.section_headers):
                        try:
                            sec_offset = shdr.ofs_body
                            sec_size = shdr.len_body
                            sec_type = str(shdr.type)
                            sec_name = ""
                            try:
                                sec_name = shdr.name if isinstance(shdr.name, str) else f"section_{i}"
                            except Exception:
                                sec_name = f"section_{i}"

                            # SHT_NOBITS doesn't occupy file space
                            if sec_offset > 0 and sec_size > 0 and sec_offset + sec_size <= len(data):
                                if "nobits" not in sec_type.lower():
                                    ranges.append(StructuredRange(
                                        sec_offset, sec_offset + sec_size,
                                        f"section_{sec_name}", f"Section: {sec_name} ({sec_size}B)",
                                    ))
                                    identity["selections"][f".sections['{sec_name}']"] = (sec_offset, sec_offset + sec_size)
                                    identity["selections"][f".sections[{i}]"] = (sec_offset, sec_offset + sec_size)

                            identity["sections"].append({
                                "index": i,
                                "name": sec_name,
                                "type": sec_type,
                                "offset": sec_offset,
                                "size": sec_size,
                            })
                        except Exception as e:
                            errors.append(f"Section {i} error: {e}")

        except Exception as e:
            errors.append(f"Header parse error: {e}")

        # Coverage
        claimed: set[int] = set()
        for r in ranges:
            claimed.update(range(r.start, min(r.end, len(data))))
        coverage = len(claimed) / len(data) if data else 0.0

        return ValidityTuple(
            valid=True,
            coverage=min(coverage, 1.0),
            structured_ranges=tuple(ranges),
            identity=identity,
            errors=tuple(errors),
        )
