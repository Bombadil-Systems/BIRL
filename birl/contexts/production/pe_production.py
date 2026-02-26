"""
BIRL Production PE Context

Wraps the `pefile` library — the industry-standard Python PE parser —
as a BIRL Context. Every field that pefile recognizes becomes a
StructuredRange with precise byte offsets, giving BIRL production-grade
coverage metrics on real-world Windows executables.

What this catches that the minimal PE context doesn't:
- Data directories (import table, export table, resource table, etc.)
- Certificate/signature tables (Authenticode)
- Relocations, TLS, debug directories
- Rich header
- Overlay data detection
- Bound imports, delay imports
- .NET CLR headers
"""

from __future__ import annotations

import pefile
from birl.context import Context, ValidityTuple, StructuredRange


class PEProductionContext(Context):

    @property
    def name(self) -> str:
        return "PE"

    @property
    def threshold(self) -> float:
        return 0.3

    @property
    def version(self) -> str:
        return f"pefile-{pefile.__version__}"

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {}

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as e:
            return ValidityTuple(False, 0.0, (), errors=(str(e),))
        except Exception as e:
            return ValidityTuple(False, 0.0, (), errors=(f"Parse error: {e}",))

        # --- DOS Header (0x00 - 0x3F) ---
        ranges.append(StructuredRange(0, 0x40, "dos_header", "DOS header"))

        # --- DOS Stub ---
        e_lfanew = pe.DOS_HEADER.e_lfanew
        if e_lfanew > 0x40:
            ranges.append(StructuredRange(0x40, e_lfanew, "dos_stub", "DOS stub"))

        identity["e_lfanew"] = e_lfanew

        # --- Rich Header (if present) ---
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
            # pefile doesn't give exact offsets for Rich header easily
            # but it's between DOS header and PE signature
            rich_start = 0x80  # Typical Rich header start
            rich_data = pe.get_data(0x40, e_lfanew - 0x40)
            rich_idx = rich_data.find(b"Rich")
            if rich_idx >= 0:
                ranges.append(StructuredRange(
                    0x40, 0x40 + rich_idx + 8, "rich_header",
                    "Rich header (build metadata)",
                ))

        # --- PE Signature ---
        ranges.append(StructuredRange(e_lfanew, e_lfanew + 4, "pe_signature", "PE\\0\\0"))

        # --- COFF/File Header ---
        fh_offset = e_lfanew + 4
        ranges.append(StructuredRange(fh_offset, fh_offset + 20, "coff_header", "COFF file header"))

        identity["machine"] = pe.FILE_HEADER.Machine
        identity["num_sections"] = pe.FILE_HEADER.NumberOfSections
        identity["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        identity["characteristics"] = pe.FILE_HEADER.Characteristics

        machine_map = {0x14c: "i386", 0x8664: "AMD64", 0xAA64: "ARM64"}
        identity["machine_name"] = machine_map.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
        identity["pe_format"] = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"

        # --- Optional Header ---
        oh_offset = fh_offset + 20
        oh_size = pe.FILE_HEADER.SizeOfOptionalHeader
        if oh_size > 0:
            ranges.append(StructuredRange(
                oh_offset, oh_offset + oh_size, "optional_header",
                f"Optional header ({identity['pe_format']}, {oh_size}B)",
            ))

        identity["entry_point_rva"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        identity["image_base"] = pe.OPTIONAL_HEADER.ImageBase
        identity["size_of_image"] = pe.OPTIONAL_HEADER.SizeOfImage
        identity["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

        # --- Data Directories ---
        dd_names = [
            "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION",
            "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
            "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
            "IAT", "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED",
        ]
        data_dirs = []
        for i, entry in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if entry.VirtualAddress > 0 and entry.Size > 0:
                dd_name = dd_names[i] if i < len(dd_names) else f"DD_{i}"
                # Convert RVA to file offset
                try:
                    file_offset = pe.get_offset_from_rva(entry.VirtualAddress)
                    if file_offset is not None and file_offset < len(data):
                        end = min(file_offset + entry.Size, len(data))
                        ranges.append(StructuredRange(
                            file_offset, end,
                            f"data_dir_{dd_name.lower()}",
                            f"Data directory: {dd_name} ({entry.Size}B)",
                        ))
                        data_dirs.append({
                            "name": dd_name,
                            "rva": entry.VirtualAddress,
                            "size": entry.Size,
                            "file_offset": file_offset,
                        })
                except Exception:
                    pass

        identity["data_directories"] = data_dirs

        # --- Section Headers ---
        sections = []
        selections = {}
        sec_table_offset = oh_offset + oh_size

        for i, section in enumerate(pe.sections):
            sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")

            # Section header
            sh_offset = sec_table_offset + (i * 40)
            ranges.append(StructuredRange(
                sh_offset, sh_offset + 40,
                f"section_header_{sec_name}", f"Section header: {sec_name}",
            ))

            # Section raw data
            raw_offset = section.PointerToRawData
            raw_size = section.SizeOfRawData
            if raw_offset > 0 and raw_size > 0 and raw_offset < len(data):
                end = min(raw_offset + raw_size, len(data))
                ranges.append(StructuredRange(
                    raw_offset, end,
                    f"section_data_{sec_name}", f"Section data: {sec_name} ({raw_size}B)",
                ))
                selections[f".sections['{sec_name}']"] = (raw_offset, end)

            sections.append({
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "virtual_address": section.VirtualAddress,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": section.Characteristics,
                "entropy": section.get_entropy(),
            })

        identity["sections"] = sections
        identity["selections"] = selections

        # --- Imports ---
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii", errors="replace") if entry.dll else "?"
                funcs = []
                for imp in entry.imports:
                    fname = imp.name.decode("ascii", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    funcs.append({"name": fname, "ordinal": imp.ordinal, "address": imp.address})
                imports.append({"dll": dll_name, "functions": funcs})

        identity["imports"] = imports

        # --- Exports ---
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                ename = exp.name.decode("ascii", errors="replace") if exp.name else f"ord_{exp.ordinal}"
                exports.append({"name": ename, "ordinal": exp.ordinal, "address": exp.address})

        identity["exports"] = exports

        # --- Overlay (data after last section) ---
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None and overlay_offset < len(data):
            # Overlay is NOT claimed — it's residue by definition
            # But we record it in identity for analysis
            identity["overlay_offset"] = overlay_offset
            identity["overlay_size"] = len(data) - overlay_offset

        # --- Authenticode Signature ---
        identity["is_signed"] = bool(data_dirs and any(d["name"] == "SECURITY" for d in data_dirs))

        # --- Warnings from pefile ---
        if pe.get_warnings():
            for w in pe.get_warnings():
                errors.append(f"pefile warning: {w}")

        # --- Calculate coverage ---
        claimed: set[int] = set()
        for r in ranges:
            claimed.update(range(r.start, min(r.end, len(data))))
        coverage = len(claimed) / len(data) if data else 0.0

        pe.close()

        return ValidityTuple(
            valid=True,
            coverage=min(coverage, 1.0),
            structured_ranges=tuple(ranges),
            identity=identity,
            errors=tuple(errors),
        )
