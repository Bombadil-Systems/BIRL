"""
BIRL ZIP Context

Parses ZIP archives. ZIP is especially important for BIRL because:
1. ZIP parsers seek from the END of file (End of Central Directory)
2. This means ZIP structures can be appended to ANY file format
3. The "polyglot" case (JPEG+ZIP, PDF+ZIP) is the classic interpretation boundary
"""

from __future__ import annotations

import struct
from birl.context import Context, ValidityTuple, StructuredRange


class ZIP_Context(Context):

    EOCD_SIGNATURE = b"PK\x05\x06"
    LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
    CENTRAL_DIR_SIGNATURE = b"PK\x01\x02"

    @property
    def name(self) -> str:
        return "ZIP"

    @property
    def threshold(self) -> float:
        return 0.15  # ZIP appended to other formats will have low coverage

    def _find_eocd(self, data: bytes) -> int:
        """Find End of Central Directory record (search from end)."""
        # EOCD is at least 22 bytes, can have comment up to 65535
        min_eocd_offset = max(0, len(data) - 65557)
        idx = data.rfind(self.EOCD_SIGNATURE, min_eocd_offset)
        return idx

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"files": [], "selections": {}}

        if len(data) < 22:
            return ValidityTuple(False, 0.0, (), errors=("Too small for ZIP",))

        # Find EOCD (End of Central Directory)
        eocd_offset = self._find_eocd(data)
        if eocd_offset < 0:
            return ValidityTuple(False, 0.0, (), errors=("No EOCD signature found",))

        if len(data) < eocd_offset + 22:
            return ValidityTuple(False, 0.0, (), errors=("Truncated EOCD",))

        # Parse EOCD
        disk_num, disk_cd, num_entries_disk, num_entries_total, cd_size, cd_offset, comment_len = \
            struct.unpack_from("<HHHHIIH", data, eocd_offset + 4)

        eocd_total = 22 + comment_len
        ranges.append(StructuredRange(
            eocd_offset, min(eocd_offset + eocd_total, len(data)),
            "end_of_central_directory", f"EOCD ({num_entries_total} entries)",
        ))

        identity["num_entries"] = num_entries_total
        identity["cd_offset"] = cd_offset
        identity["cd_size"] = cd_size

        # Parse Central Directory
        if cd_offset + cd_size <= len(data):
            ranges.append(StructuredRange(
                cd_offset, cd_offset + cd_size,
                "central_directory", f"Central directory ({cd_size} bytes)",
            ))

            # Walk central directory entries
            pos = cd_offset
            for i in range(num_entries_total):
                if pos + 46 > len(data):
                    errors.append(f"Truncated central dir entry {i}")
                    break
                if data[pos:pos + 4] != self.CENTRAL_DIR_SIGNATURE:
                    errors.append(f"Bad central dir signature at {pos:#x}")
                    break

                fname_len, extra_len, comment_len_entry = \
                    struct.unpack_from("<HHH", data, pos + 28)
                compressed_size = struct.unpack_from("<I", data, pos + 20)[0]
                local_header_offset = struct.unpack_from("<I", data, pos + 42)[0]

                entry_size = 46 + fname_len + extra_len + comment_len_entry
                filename = data[pos + 46:pos + 46 + fname_len].decode("utf-8", errors="replace")

                identity["files"].append({
                    "name": filename,
                    "compressed_size": compressed_size,
                    "local_header_offset": local_header_offset,
                })

                pos += entry_size

        # Parse Local File Headers and data
        for file_info in identity["files"]:
            lh_offset = file_info["local_header_offset"]
            if lh_offset + 30 > len(data):
                continue
            if data[lh_offset:lh_offset + 4] != self.LOCAL_FILE_SIGNATURE:
                continue

            fname_len_local = struct.unpack_from("<H", data, lh_offset + 26)[0]
            extra_len_local = struct.unpack_from("<H", data, lh_offset + 28)[0]
            comp_size_local = struct.unpack_from("<I", data, lh_offset + 18)[0]

            header_total = 30 + fname_len_local + extra_len_local
            data_start = lh_offset + header_total
            data_end = data_start + comp_size_local

            ranges.append(StructuredRange(
                lh_offset, min(lh_offset + header_total, len(data)),
                f"local_header_{file_info['name']}", f"Local header: {file_info['name']}",
            ))

            if data_end <= len(data) and comp_size_local > 0:
                ranges.append(StructuredRange(
                    data_start, data_end,
                    f"file_data_{file_info['name']}", f"File data: {file_info['name']}",
                ))

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
