"""
BIRL PNG Context

Parses PNG image files with chunk-level structural coverage.
"""

from __future__ import annotations

import struct
from birl.context import Context, ValidityTuple, StructuredRange


class PNG_Context(Context):

    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    @property
    def name(self) -> str:
        return "PNG"

    @property
    def threshold(self) -> float:
        return 0.8  # PNG files should have high coverage

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"chunks": [], "selections": {}}

        if len(data) < 8:
            return ValidityTuple(False, 0.0, (), errors=("Too small for PNG",))

        if data[0:8] != self.PNG_SIGNATURE:
            return ValidityTuple(False, 0.0, (), errors=("Bad PNG signature",))

        ranges.append(StructuredRange(0, 8, "png_signature", "PNG file signature"))

        # Parse chunks
        offset = 8
        chunk_index = 0

        while offset + 8 <= len(data):
            if offset + 8 > len(data):
                break

            chunk_length = struct.unpack_from(">I", data, offset)[0]
            chunk_type = data[offset + 4:offset + 8].decode("ascii", errors="replace")

            # Total chunk size: 4 (length) + 4 (type) + data + 4 (CRC)
            chunk_total = 12 + chunk_length
            chunk_end = offset + chunk_total

            if chunk_end > len(data):
                errors.append(f"Truncated chunk {chunk_type} at {offset:#x}")
                # Claim what we can
                ranges.append(StructuredRange(
                    offset, len(data), f"chunk_{chunk_index}_{chunk_type}",
                    f"Truncated {chunk_type} chunk",
                ))
                break

            ranges.append(StructuredRange(
                offset, chunk_end, f"chunk_{chunk_index}_{chunk_type}",
                f"{chunk_type} chunk ({chunk_length} bytes data)",
            ))

            # Extract IHDR details
            if chunk_type == "IHDR" and chunk_length >= 13:
                data_start = offset + 8
                width, height = struct.unpack_from(">II", data, data_start)
                bit_depth = data[data_start + 8]
                color_type = data[data_start + 9]
                identity["width"] = width
                identity["height"] = height
                identity["bit_depth"] = bit_depth
                identity["color_type"] = color_type

            identity["chunks"].append({
                "type": chunk_type,
                "length": chunk_length,
                "offset": offset,
            })

            chunk_index += 1
            offset = chunk_end

            if chunk_type == "IEND":
                break

        # If there are trailing bytes after IEND, they're NOT claimed
        # (this is where polyglot data could hide)

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
