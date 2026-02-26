"""
BIRL Forge — The Transformation Engine

This is what makes BIRL a tool instead of a viewer. The Forge
contains actual transformation functions that CREATE artifacts:

- PolyglotForge: Combine two formats into one file that satisfies both
- ROPForge: Assemble gadget coordinates into an executable ROP chain  
- InjectionForge: Write payloads into residue regions
- StripForge: Veriduct-style format destruction
- WrapForge: Dress raw bytes in a format container

Each forge operation:
1. Validates inputs against source context
2. Performs the actual byte manipulation
3. Validates output against target context(s)
4. Returns the result with full provenance

The philosophy: you're not "converting" — you're navigating to a
latent identity and making it real.
"""

from __future__ import annotations

import struct
import hashlib
import zlib
from dataclasses import dataclass, field
from typing import Any, Optional

from birl.context import Context, ValidityTuple, StructuredRange
from birl.residue import ResidueCalculator, ResidueRange


# ============================================================================
# Forge Result
# ============================================================================

@dataclass
class ForgeResult:
    """The output of a forge operation."""
    success: bool
    data: bytes
    description: str
    # Validation against target context(s)
    validations: dict[str, ValidityTuple] = field(default_factory=dict)
    # What changed
    mutations: list[dict[str, Any]] = field(default_factory=list)
    # Source and result hashes for provenance
    source_hash: str = ""
    result_hash: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid_polyglot(self) -> bool:
        """Are ALL target contexts satisfied?"""
        return all(v.valid for v in self.validations.values())

    def __repr__(self) -> str:
        status = "OK" if self.success else "FAIL"
        contexts = ", ".join(
            f"{k}={'✓' if v.valid else '✗'}({v.coverage:.0%})"
            for k, v in self.validations.items()
        )
        return f"<ForgeResult: {status} {len(self.data)}B [{contexts}]>"


# ============================================================================
# Polyglot Forge
# ============================================================================

class PolyglotForge:
    """Build files that are simultaneously valid under multiple contexts.
    
    This is the core "digital alchemy" — taking a file that IS format A
    and making it ALSO format B, without breaking A.
    
    Strategies:
    - append: Append B's structure after A's content (works for ZIP, which seeks from end)
    - inject_residue: Place B's critical structures into A's residue regions
    - header_cavity: Use A's header slack space for B's magic/header
    
    Usage:
        forge = PolyglotForge()
        result = forge.append(
            primary_data=png_bytes,
            primary_context=PNG_Context(),
            payload_data=zip_bytes,
            payload_context=ZIP_Context(),
        )
        # result.data is now a valid PNG AND a valid ZIP
    """

    def __init__(self) -> None:
        self._residue_calc = ResidueCalculator()

    def append(
        self,
        primary_data: bytes,
        primary_context: Context,
        payload_data: bytes,
        payload_context: Context,
    ) -> ForgeResult:
        """Append payload after primary content.
        
        Works when the payload format seeks from the end of file (ZIP)
        or has magic bytes that can be found anywhere (certain formats).
        
        The primary format must tolerate trailing data (PNG stops at IEND,
        JPEG stops at FFD9, etc.).
        """
        source_hash = hashlib.sha256(primary_data).hexdigest()[:16]

        # Validate primary
        primary_vt = primary_context.satisfies(primary_data)
        if not primary_vt.valid:
            return ForgeResult(
                success=False, data=b"", description="Primary data invalid",
                source_hash=source_hash, errors=["Primary data doesn't satisfy its context"],
            )

        # Build polyglot
        polyglot = primary_data + payload_data
        result_hash = hashlib.sha256(polyglot).hexdigest()[:16]

        # Validate both contexts on the result
        primary_check = primary_context.satisfies(polyglot)
        payload_check = payload_context.satisfies(polyglot)

        validations = {
            primary_context.name: primary_check,
            payload_context.name: payload_check,
        }

        mutations = [{
            "type": "append",
            "offset": len(primary_data),
            "length": len(payload_data),
            "description": f"Appended {payload_context.name} after {primary_context.name}",
        }]

        success = primary_check.valid and payload_check.valid

        return ForgeResult(
            success=success,
            data=polyglot,
            description=(
                f"Polyglot: {primary_context.name}+{payload_context.name} "
                f"({'VALID' if success else 'INVALID'})"
            ),
            validations=validations,
            mutations=mutations,
            source_hash=source_hash,
            result_hash=result_hash,
            errors=[] if success else [
                f"{k}: valid={v.valid}" for k, v in validations.items() if not v.valid
            ],
        )

    def inject_into_residue(
        self,
        primary_data: bytes,
        primary_context: Context,
        payload: bytes,
        target_offset: Optional[int] = None,
        min_region_size: int = 0,
    ) -> ForgeResult:
        """Inject payload bytes into residue regions of the primary format.
        
        Finds unclaimed byte ranges and writes the payload there.
        The primary format remains valid because residue bytes are 
        structurally invisible to its parser.
        
        Args:
            primary_data: The file to inject into
            primary_context: Format context of the primary file
            payload: Bytes to inject
            target_offset: Specific offset to inject at (must be in residue)
            min_region_size: Minimum residue region size to consider
        """
        source_hash = hashlib.sha256(primary_data).hexdigest()[:16]

        # Find residue regions
        residue_ranges = self._residue_calc.residue(primary_data, primary_context)
        viable = [r for r in residue_ranges if r.length >= max(len(payload), min_region_size)]

        if not viable and target_offset is None:
            return ForgeResult(
                success=False, data=primary_data,
                description="No residue region large enough for payload",
                source_hash=source_hash,
                errors=[
                    f"Payload is {len(payload)} bytes, "
                    f"largest residue is {max((r.length for r in residue_ranges), default=0)} bytes"
                ],
            )

        result = bytearray(primary_data)

        if target_offset is not None:
            # Inject at specific offset
            inject_at = target_offset
            # Verify it's in residue
            in_residue = any(r.start <= inject_at < r.end for r in residue_ranges)
            if not in_residue:
                return ForgeResult(
                    success=False, data=primary_data,
                    description=f"Offset {inject_at:#x} is not in residue",
                    source_hash=source_hash,
                    errors=[f"Offset {inject_at:#x} is claimed by {primary_context.name}"],
                )
        else:
            # Use largest residue region
            inject_at = viable[0].start

        # Perform injection
        end = min(inject_at + len(payload), len(result))
        result[inject_at:end] = payload[:end - inject_at]

        result_bytes = bytes(result)
        result_hash = hashlib.sha256(result_bytes).hexdigest()[:16]

        # Verify primary is still valid
        check = primary_context.satisfies(result_bytes)

        mutations = [{
            "type": "residue_injection",
            "offset": inject_at,
            "length": min(len(payload), end - inject_at),
            "description": f"Injected {len(payload)} bytes at residue offset {inject_at:#x}",
        }]

        return ForgeResult(
            success=check.valid,
            data=result_bytes,
            description=f"Residue injection at {inject_at:#x} ({len(payload)} bytes)",
            validations={primary_context.name: check},
            mutations=mutations,
            source_hash=source_hash,
            result_hash=result_hash,
            errors=[] if check.valid else [f"Injection broke {primary_context.name} validity"],
        )


# ============================================================================
# ROP Forge
# ============================================================================

@dataclass
class ROPGadget:
    """A single ROP gadget — a coordinate in signed code space."""
    name: str
    offset: int           # Offset within the substrate
    pattern: bytes        # The actual instruction bytes
    description: str = ""
    substrate: str = ""   # Which DLL/binary this is from

    def __repr__(self) -> str:
        return f"<Gadget:{self.name} @{self.offset:#x} [{self.pattern.hex()}] {self.description}>"


@dataclass
class ROPChain:
    """An assembled ROP chain — ready to deploy."""
    entries: list[dict[str, Any]]
    raw_bytes: bytes        # The chain as a flat byte sequence
    pointer_size: int = 8   # 8 for x64, 4 for x86
    base_address: int = 0   # Base address of the substrate in memory

    @property
    def num_entries(self) -> int:
        return len(self.entries)

    @property
    def total_bytes(self) -> int:
        return len(self.raw_bytes)

    def hexdump(self) -> str:
        """Formatted chain for inspection."""
        lines = [f"ROP Chain: {self.num_entries} entries, {self.total_bytes} bytes"]
        for i, entry in enumerate(self.entries):
            etype = entry.get("type", "?")
            if etype == "gadget":
                addr = entry["address"]
                lines.append(
                    f"  [{i:3d}] GADGET  {addr:#018x}  {entry.get('name', '?')} "
                    f"// {entry.get('description', '')}"
                )
            elif etype == "value":
                val = entry["value"]
                lines.append(f"  [{i:3d}] VALUE   {val:#018x}")
            elif etype == "padding":
                lines.append(f"  [{i:3d}] PADDING {entry.get('count', 0)} bytes")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<ROPChain: {self.num_entries} entries, {self.total_bytes}B>"


class ROPForge:
    """Assemble ROP chains from gadget coordinates.
    
    Takes gadget locations found by BIRL's x86 context and
    assembles them into a deployable ROP chain — a flat byte
    sequence of addresses and data values.
    
    This is OIS-ROP made real: the output contains ZERO code bytes.
    Every address points into existing signed binaries.
    
    Usage:
        forge = ROPForge(pointer_size=8, base_address=0x7FF800000000)
        
        chain = forge.build_chain([
            forge.gadget("pop_rcx", offset=0x1234, pattern=b"\\x59\\xc3"),
            forge.value(0x41414141),  # RCX = target address
            forge.gadget("pop_rdx", offset=0x5678, pattern=b"\\x5a\\xc3"),
            forge.value(0x1000),      # RDX = size
            forge.gadget("call_vprotect", offset=0x9ABC),
        ])
        
        chain.raw_bytes  # → the flat payload
        chain.hexdump()  # → human-readable chain
    """

    def __init__(
        self,
        pointer_size: int = 8,
        base_address: int = 0,
        substrate_name: str = "",
    ) -> None:
        self._ptr_size = pointer_size
        self._base = base_address
        self._substrate = substrate_name
        self._pack_fmt = "<Q" if pointer_size == 8 else "<I"

    def gadget(
        self,
        name: str,
        offset: int,
        pattern: bytes = b"",
        description: str = "",
    ) -> dict[str, Any]:
        """Define a gadget entry for the chain."""
        return {
            "type": "gadget",
            "name": name,
            "offset": offset,
            "address": self._base + offset,
            "pattern": pattern,
            "description": description or name,
        }

    def value(self, val: int, description: str = "") -> dict[str, Any]:
        """Define a data value entry (e.g., argument for pop reg)."""
        return {
            "type": "value",
            "value": val,
            "description": description,
        }

    def padding(self, count: int = 1) -> dict[str, Any]:
        """Shadow space / alignment padding."""
        return {
            "type": "padding",
            "count": count * self._ptr_size,
        }

    def build_chain(self, entries: list[dict[str, Any]]) -> ROPChain:
        """Assemble entries into a flat ROP chain."""
        raw = bytearray()

        for entry in entries:
            etype = entry["type"]
            if etype == "gadget":
                raw += struct.pack(self._pack_fmt, entry["address"])
            elif etype == "value":
                raw += struct.pack(self._pack_fmt, entry["value"])
            elif etype == "padding":
                raw += b"\x00" * entry["count"]

        return ROPChain(
            entries=entries,
            raw_bytes=bytes(raw),
            pointer_size=self._ptr_size,
            base_address=self._base,
        )

    def chain_from_coordinates(
        self,
        coordinates: dict[str, Any],
        chain_spec: list[tuple[str, Optional[int]]],
    ) -> ROPChain:
        """Build a chain from saved BIRL coordinates.
        
        Args:
            coordinates: Dict of name → Coordinate from BIRL runtime
            chain_spec: List of (name_or_"VALUE", value_or_None)
                       e.g., [("pop_rcx", None), ("VALUE", 0x1000), ("pop_rdx", None)]
        """
        entries = []
        for name, val in chain_spec:
            if name == "VALUE":
                entries.append(self.value(val or 0))
            elif name == "PADDING":
                entries.append(self.padding(val or 1))
            elif name in coordinates:
                coord = coordinates[name]
                offset = coord.offset if hasattr(coord, "offset") else coord["offset"]
                entries.append(self.gadget(
                    name=name,
                    offset=offset,
                    description=getattr(coord, "pattern", ""),
                ))
            else:
                entries.append({
                    "type": "value",
                    "value": val or 0,
                    "description": f"Unresolved: {name}",
                })

        return self.build_chain(entries)


# ============================================================================
# Strip Forge (Veriduct)
# ============================================================================

class StripForge:
    """Veriduct-style format destruction.
    
    Strips format identity while preserving semantic content.
    The output is opaque bytes that no context recognizes,
    but that can be reconstituted with the right interpretation.
    
    Methods:
    - strip_headers: Zero out format magic/headers
    - chunk: Split into opaque chunks
    - scramble: Reversible byte-level transformation
    """

    def strip_headers(
        self,
        data: bytes,
        context: Context,
    ) -> ForgeResult:
        """Zero out all structural header bytes, preserving content."""
        source_hash = hashlib.sha256(data).hexdigest()[:16]
        vt = context.satisfies(data)
        if not vt.valid:
            return ForgeResult(
                success=False, data=data,
                description="Can't strip — data doesn't satisfy context",
                source_hash=source_hash,
                errors=["Invalid input for context"],
            )

        result = bytearray(data)
        mutations = []

        for sr in vt.structured_ranges:
            # Zero out header/structural fields but not content sections
            if any(kw in sr.field_id.lower() for kw in 
                   ("header", "magic", "signature", "directory", "ident")):
                for i in range(sr.start, min(sr.end, len(result))):
                    result[i] = 0x00
                mutations.append({
                    "type": "zero_fill",
                    "offset": sr.start,
                    "length": sr.end - sr.start,
                    "field": sr.field_id,
                    "description": f"Zeroed {sr.field_id}",
                })

        result_bytes = bytes(result)
        result_hash = hashlib.sha256(result_bytes).hexdigest()[:16]

        # Verify the format is now BROKEN
        post_check = context.satisfies(result_bytes)

        return ForgeResult(
            success=not post_check.valid,  # Success = format is destroyed
            data=result_bytes,
            description=f"Stripped {context.name} identity ({len(mutations)} fields zeroed)",
            validations={context.name: post_check},
            mutations=mutations,
            source_hash=source_hash,
            result_hash=result_hash,
        )

    def chunk(
        self,
        data: bytes,
        chunk_size: int = 256,
        xor_key: int = 0,
    ) -> list[ForgeResult]:
        """Split data into opaque chunks, optionally XOR'd.
        
        Returns a list of ForgeResults, one per chunk.
        Reassembly requires knowing the order and XOR key.
        """
        source_hash = hashlib.sha256(data).hexdigest()[:16]
        chunks = []

        for i in range(0, len(data), chunk_size):
            chunk_data = data[i:i + chunk_size]
            if xor_key:
                chunk_data = bytes(b ^ xor_key for b in chunk_data)

            chunks.append(ForgeResult(
                success=True,
                data=chunk_data,
                description=f"Chunk {len(chunks)} [{i:#x}:{i+len(chunk_data):#x}]",
                mutations=[{
                    "type": "chunk",
                    "index": len(chunks),
                    "source_offset": i,
                    "length": len(chunk_data),
                    "xor_key": xor_key,
                }],
                source_hash=source_hash,
                result_hash=hashlib.sha256(chunk_data).hexdigest()[:16],
            ))

        return chunks

    @staticmethod
    def reassemble(chunks: list[ForgeResult], xor_key: int = 0) -> bytes:
        """Reassemble chunked data."""
        # Sort by source offset
        ordered = sorted(chunks, key=lambda c: c.mutations[0]["source_offset"])
        result = bytearray()
        for chunk in ordered:
            data = chunk.data
            if xor_key:
                data = bytes(b ^ xor_key for b in data)
            result.extend(data)
        return bytes(result)


# ============================================================================
# Wrap Forge
# ============================================================================

class WrapForge:
    """Wrap raw bytes in a format container.
    
    The inverse of StripForge: take opaque bytes and dress them
    in valid format headers so they satisfy a target context.
    
    This is Beauty's core operation made concrete.
    """

    def wrap_as_png(
        self,
        payload: bytes,
        width: int = 1,
        height: Optional[int] = None,
    ) -> ForgeResult:
        """Wrap arbitrary bytes as PNG IDAT chunk data.
        
        The payload becomes the compressed image data inside
        a valid PNG container.
        """
        source_hash = hashlib.sha256(payload).hexdigest()[:16]

        if height is None:
            # Calculate height to fit payload (RGB, 1 filter byte per row)
            row_size = width * 3 + 1  # RGB + filter byte
            height = max(1, (len(payload) + row_size - 1) // row_size)

        signature = b"\x89PNG\r\n\x1a\n"

        def make_chunk(ctype: bytes, cdata: bytes) -> bytes:
            length = struct.pack(">I", len(cdata))
            crc = struct.pack(">I", zlib.crc32(ctype + cdata) & 0xFFFFFFFF)
            return length + ctype + cdata + crc

        # IHDR
        ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        ihdr = make_chunk(b"IHDR", ihdr_data)

        # IDAT — compress the payload as image data
        # Prepend filter bytes (0 = no filter) for each row
        row_size = width * 3
        padded = bytearray()
        offset = 0
        for _ in range(height):
            padded.append(0)  # Filter byte
            row = payload[offset:offset + row_size]
            padded.extend(row)
            if len(row) < row_size:
                padded.extend(b"\x00" * (row_size - len(row)))
            offset += row_size

        compressed = zlib.compress(bytes(padded))
        idat = make_chunk(b"IDAT", compressed)
        iend = make_chunk(b"IEND", b"")

        result = signature + ihdr + idat + iend
        result_hash = hashlib.sha256(result).hexdigest()[:16]

        return ForgeResult(
            success=True,
            data=result,
            description=f"Wrapped {len(payload)}B payload as {width}x{height} PNG",
            mutations=[{
                "type": "wrap_png",
                "payload_size": len(payload),
                "width": width,
                "height": height,
                "compressed_size": len(compressed),
            }],
            source_hash=source_hash,
            result_hash=result_hash,
        )

    def wrap_as_zip(
        self,
        payload: bytes,
        filename: str = "data.bin",
    ) -> ForgeResult:
        """Wrap arbitrary bytes inside a ZIP archive."""
        source_hash = hashlib.sha256(payload).hexdigest()[:16]

        crc = zlib.crc32(payload) & 0xFFFFFFFF
        fname = filename.encode("utf-8")

        # Local file header
        local = struct.pack("<IHHHHHIIIHH",
            0x04034b50, 20, 0, 0, 0, 0,
            crc, len(payload), len(payload),
            len(fname), 0,
        ) + fname + payload

        # Central directory
        cd = struct.pack("<IHHHHHHIIIHHHHHII",
            0x02014b50, 20, 20, 0, 0, 0, 0,
            crc, len(payload), len(payload),
            len(fname), 0, 0, 0, 0, 0, 0,
        ) + fname

        cd_offset = len(local)
        cd_size = len(cd)

        # EOCD
        eocd = struct.pack("<IHHHHIIH",
            0x06054b50, 0, 0, 1, 1,
            cd_size, cd_offset, 0,
        )

        result = local + cd + eocd
        result_hash = hashlib.sha256(result).hexdigest()[:16]

        return ForgeResult(
            success=True,
            data=result,
            description=f"Wrapped {len(payload)}B as ZIP ({filename})",
            mutations=[{
                "type": "wrap_zip",
                "payload_size": len(payload),
                "filename": filename,
            }],
            source_hash=source_hash,
            result_hash=result_hash,
        )
