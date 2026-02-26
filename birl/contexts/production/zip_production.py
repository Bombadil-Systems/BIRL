"""
BIRL Production ZIP Context — Kaitai Struct

Wraps the Kaitai-compiled ZIP parser. ZIP is critical for polyglot
research because it seeks from the END of file.
"""

from __future__ import annotations

import io
import struct
from kaitaistruct import KaitaiStream
from birl.kaitai_parsers.zip import Zip as KaitaiZip
from birl.context import Context, ValidityTuple, StructuredRange


class ZIPProductionContext(Context):

    @property
    def name(self) -> str:
        return "ZIP"

    @property
    def threshold(self) -> float:
        return 0.15

    @property
    def version(self) -> str:
        return "kaitai"

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"files": [], "selections": {}}

        if len(data) < 22:
            return ValidityTuple(False, 0.0, (), errors=("Too small for ZIP",))

        # Find EOCD
        eocd_sig = b"PK\x05\x06"
        eocd_pos = data.rfind(eocd_sig, max(0, len(data) - 65557))
        if eocd_pos < 0:
            return ValidityTuple(False, 0.0, (), errors=("No EOCD found",))

        try:
            stream = KaitaiStream(io.BytesIO(data))
            zf = KaitaiZip(stream)
        except Exception as e:
            # Kaitai's ZIP parser reads from the start (local files)
            # Fall back to manual EOCD-based parsing for appended ZIPs
            return self._parse_from_eocd(data, eocd_pos)

        # Parse sections from Kaitai
        try:
            for i, section in enumerate(zf.sections):
                sec_offset = section._io.pos() if hasattr(section._io, 'pos') else 0
                body = section.body

                if hasattr(body, 'header') and hasattr(body.header, 'file_name'):
                    fname = body.header.file_name if isinstance(body.header.file_name, str) else body.header.file_name.decode("utf-8", errors="replace")
                    identity["files"].append({"name": fname})
        except Exception as e:
            errors.append(f"Kaitai walk error: {e}")
            return self._parse_from_eocd(data, eocd_pos)

        # Use EOCD-based parsing for reliable coverage tracking
        return self._parse_from_eocd(data, eocd_pos)

    def _parse_from_eocd(self, data: bytes, eocd_pos: int) -> ValidityTuple:
        """Parse ZIP from EOCD backward — handles appended ZIPs (polyglots)."""
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"files": [], "selections": {}}

        if eocd_pos + 22 > len(data):
            return ValidityTuple(False, 0.0, (), errors=("Truncated EOCD",))

        # EOCD
        _, disk_num, disk_cd, entries_disk, entries_total, cd_size, cd_offset, comment_len = \
            struct.unpack_from("<IHHHHIIH", data, eocd_pos)

        eocd_total = 22 + comment_len
        ranges.append(StructuredRange(
            eocd_pos, min(eocd_pos + eocd_total, len(data)),
            "eocd", f"End of Central Directory ({entries_total} entries)",
        ))

        identity["num_entries"] = entries_total
        identity["cd_offset"] = cd_offset
        identity["cd_size"] = cd_size

        # Central Directory
        if cd_offset + cd_size <= len(data):
            ranges.append(StructuredRange(
                cd_offset, cd_offset + cd_size,
                "central_directory", f"Central directory ({cd_size}B)",
            ))

        # Walk CD entries for local file headers
        pos = cd_offset
        for i in range(entries_total):
            if pos + 46 > len(data):
                break
            if data[pos:pos + 4] != b"PK\x01\x02":
                errors.append(f"Bad CD entry at {pos:#x}")
                break

            fname_len = struct.unpack_from("<H", data, pos + 28)[0]
            extra_len = struct.unpack_from("<H", data, pos + 30)[0]
            comment_len_e = struct.unpack_from("<H", data, pos + 32)[0]
            comp_size = struct.unpack_from("<I", data, pos + 20)[0]
            local_offset = struct.unpack_from("<I", data, pos + 42)[0]

            if pos + 46 + fname_len <= len(data):
                fname = data[pos + 46:pos + 46 + fname_len].decode("utf-8", errors="replace")
                identity["files"].append({
                    "name": fname,
                    "compressed_size": comp_size,
                    "local_offset": local_offset,
                })

            pos += 46 + fname_len + extra_len + comment_len_e

        # Local file headers + data
        for finfo in identity["files"]:
            lh = finfo.get("local_offset", -1)
            if lh < 0 or lh + 30 > len(data):
                continue
            if data[lh:lh + 4] != b"PK\x03\x04":
                continue

            fn_len = struct.unpack_from("<H", data, lh + 26)[0]
            ex_len = struct.unpack_from("<H", data, lh + 28)[0]
            c_size = struct.unpack_from("<I", data, lh + 18)[0]

            header_total = 30 + fn_len + ex_len
            data_end = lh + header_total + c_size

            ranges.append(StructuredRange(
                lh, min(lh + header_total, len(data)),
                f"local_header_{finfo['name']}", f"Local: {finfo['name']}",
            ))
            if c_size > 0 and data_end <= len(data):
                ranges.append(StructuredRange(
                    lh + header_total, data_end,
                    f"file_data_{finfo['name']}", f"Data: {finfo['name']}",
                ))

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
