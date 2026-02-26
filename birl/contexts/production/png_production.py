"""
BIRL Production PNG Context — Kaitai Struct

Wraps the Kaitai-compiled PNG parser for production-grade parsing
with full chunk-level coverage tracking.
"""

from __future__ import annotations

import io
from kaitaistruct import KaitaiStream
from birl.kaitai_parsers.png import Png
from birl.context import Context, ValidityTuple, StructuredRange


class PNGProductionContext(Context):

    @property
    def name(self) -> str:
        return "PNG"

    @property
    def threshold(self) -> float:
        return 0.8

    @property
    def version(self) -> str:
        return "kaitai"

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {"chunks": [], "selections": {}}

        if len(data) < 8:
            return ValidityTuple(False, 0.0, (), errors=("Too small for PNG",))

        if data[0:8] != b"\x89PNG\r\n\x1a\n":
            return ValidityTuple(False, 0.0, (), errors=("Bad PNG signature",))

        try:
            stream = KaitaiStream(io.BytesIO(data))
            png = Png(stream)
        except Exception as e:
            return ValidityTuple(False, 0.0, (), errors=(f"Kaitai parse error: {e}",))

        # PNG signature
        ranges.append(StructuredRange(0, 8, "png_signature", "PNG file signature"))

        # IHDR is parsed separately by Kaitai as a top-level attribute
        # It occupies bytes 8..33 (4 len + 4 type + 13 data + 4 CRC = 25 bytes)
        ihdr_total = 4 + 4 + 13 + 4  # 25 bytes
        ranges.append(StructuredRange(8, 8 + ihdr_total, "chunk_0_IHDR", f"IHDR chunk (13B data)"))
        identity["chunks"].append({"type": "IHDR", "length": 13, "offset": 8})

        if hasattr(png, "ihdr"):
            ihdr = png.ihdr
            if hasattr(ihdr, "width"):
                identity["width"] = ihdr.width
                identity["height"] = ihdr.height
            if hasattr(ihdr, "bit_depth"):
                identity["bit_depth"] = ihdr.bit_depth
            if hasattr(ihdr, "color_type"):
                identity["color_type"] = ihdr.color_type.value if hasattr(ihdr.color_type, "value") else ihdr.color_type

        # Walk remaining chunks (IDAT, IEND, etc.)
        offset = 8 + ihdr_total
        for i, chunk in enumerate(png.chunks):
            try:
                chunk_type = chunk.type
                chunk_len = chunk.len
                # Each chunk: 4 (length) + 4 (type) + data + 4 (CRC) = 12 + data
                chunk_total = 12 + chunk_len
                chunk_end = offset + chunk_total

                if chunk_end > len(data):
                    errors.append(f"Truncated chunk {chunk_type} at {offset:#x}")
                    ranges.append(StructuredRange(offset, len(data), f"chunk_{i}_{chunk_type}", f"Truncated {chunk_type}"))
                    break

                ranges.append(StructuredRange(
                    offset, chunk_end, f"chunk_{i}_{chunk_type}",
                    f"{chunk_type} chunk ({chunk_len}B data)",
                ))

                # Extract IHDR details
                if chunk_type == "IHDR" and hasattr(chunk, "body"):
                    body = chunk.body
                    if hasattr(body, "width"):
                        identity["width"] = body.width
                        identity["height"] = body.height
                        identity["bit_depth"] = body.bit_depth
                        identity["color_type"] = body.color_type.value if hasattr(body.color_type, "value") else body.color_type

                identity["chunks"].append({
                    "type": chunk_type,
                    "length": chunk_len,
                    "offset": offset,
                })

                offset = chunk_end

                if chunk_type == "IEND":
                    break
            except Exception as e:
                errors.append(f"Error parsing chunk {i}: {e}")
                break

        # Trailing data after IEND is NOT claimed (polyglot space)
        if offset < len(data):
            identity["trailing_bytes"] = len(data) - offset

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
