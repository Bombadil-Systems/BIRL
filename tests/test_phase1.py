"""
BIRL Phase 1 Test Suite

Tests the core Lens capabilities:
1. Context registration and the Satisfies predicate
2. Coverage metrics
3. Residue calculation
4. Superposition (multi-context identification)
5. Fluent API (pipe-style chaining)
6. Polyglot detection via residue intersection
"""

import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from birl import World, ByteSequence
from birl.context import RawContext, ValidityTuple, StructuredRange
from birl.residue import ResidueCalculator
from birl.contexts import PE_Context, ELF_Context, ZIP_Context, PNG_Context, UTF8_Context, x86_Context


def build_minimal_pe() -> bytes:
    """Construct a minimal valid PE file for testing."""
    # DOS Header
    dos_header = bytearray(128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 128)  # e_lfanew

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # COFF Header (x86_64, 1 section)
    coff = struct.pack("<HHIIIHH",
        0x8664,  # Machine: AMD64
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        112,     # SizeOfOptionalHeader (PE32+)
        0x22,    # Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    )

    # Optional Header (PE32+ minimal)
    opt = bytearray(112)
    struct.pack_into("<H", opt, 0, 0x20B)   # Magic: PE32+
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase

    # Section Header (.text)
    section = bytearray(40)
    section[0:6] = b".text\x00"
    struct.pack_into("<I", section, 8, 256)    # VirtualSize
    struct.pack_into("<I", section, 12, 0x1000) # VirtualAddress
    struct.pack_into("<I", section, 16, 256)    # SizeOfRawData
    struct.pack_into("<I", section, 20, 512)    # PointerToRawData
    struct.pack_into("<I", section, 36, 0x60000020)  # Characteristics (CODE|EXEC|READ)

    # Padding to reach section data offset
    header_end = 128 + 4 + 20 + 112 + 40  # = 304
    padding = b"\x00" * (512 - header_end)

    # Section data (some x86 instructions)
    code = bytearray(256)
    # NOP sled
    code[0:10] = b"\x90" * 10
    # pop rcx; ret
    code[10:12] = b"\x59\xc3"
    # pop rdx; ret  
    code[14:16] = b"\x5a\xc3"
    # ret
    code[20] = 0xc3

    return bytes(dos_header + pe_sig + coff + opt + section + padding + code)


def build_minimal_elf() -> bytes:
    """Construct a minimal valid ELF64 binary."""
    # ELF Header (64 bytes)
    elf = bytearray(256)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2   # ELFCLASS64
    elf[5] = 1   # ELFDATA2LSB
    elf[6] = 1   # EV_CURRENT
    struct.pack_into("<H", elf, 16, 2)    # ET_EXEC
    struct.pack_into("<H", elf, 18, 0x3E)  # EM_X86_64
    struct.pack_into("<I", elf, 20, 1)     # EV_CURRENT
    struct.pack_into("<Q", elf, 24, 0x400000)  # Entry point
    struct.pack_into("<Q", elf, 32, 64)    # ph offset
    struct.pack_into("<Q", elf, 40, 120)   # sh offset
    struct.pack_into("<H", elf, 52, 64)    # eh size
    struct.pack_into("<H", elf, 54, 56)    # ph entry size
    struct.pack_into("<H", elf, 56, 1)     # ph num
    struct.pack_into("<H", elf, 58, 64)    # sh entry size
    struct.pack_into("<H", elf, 60, 1)     # sh num
    # Program header at offset 64 (56 bytes)
    struct.pack_into("<I", elf, 64, 1)     # PT_LOAD
    struct.pack_into("<Q", elf, 72, 200)   # offset
    struct.pack_into("<Q", elf, 80, 0x400000)  # vaddr
    struct.pack_into("<Q", elf, 96, 56)    # filesz
    struct.pack_into("<Q", elf, 104, 56)   # memsz
    # Section header at offset 120 (64 bytes)
    struct.pack_into("<I", elf, 124, 1)    # SHT_PROGBITS
    struct.pack_into("<Q", elf, 144, 200)  # sh_offset
    struct.pack_into("<Q", elf, 152, 56)   # sh_size

    return bytes(elf)


def build_minimal_zip() -> bytes:
    """Construct a minimal valid ZIP with one file."""
    filename = b"hello.txt"
    file_data = b"Hello from BIRL!"
    
    # Local file header
    local = struct.pack("<IHHHHHIIIHH",
        0x04034b50,  # signature
        20,          # version needed
        0,           # flags
        0,           # compression (store)
        0,           # mod time
        0,           # mod date
        0,           # crc32 (we're lazy)
        len(file_data),  # compressed size
        len(file_data),  # uncompressed size
        len(filename),   # filename length
        0,               # extra length
    )
    local += filename + file_data

    # Central directory entry
    cd_offset = 0
    cd = struct.pack("<IHHHHHHIIIHHHHHII",
        0x02014b50,     # signature
        20,             # version made by
        20,             # version needed
        0, 0, 0, 0,    # flags, compression, mod time, mod date
        0,              # crc32
        len(file_data), # compressed size
        len(file_data), # uncompressed size
        len(filename),  # filename length
        0, 0,           # extra length, comment length
        0, 0,           # disk number, internal attrs
        0,              # external attrs
        0,              # local header offset
    )
    cd += filename

    cd_start = len(local)
    cd_size = len(cd)

    # End of central directory
    eocd = struct.pack("<IHHHHIIH",
        0x06054b50,  # signature
        0, 0,        # disk numbers
        1, 1,        # entries
        cd_size,     # cd size
        cd_start,    # cd offset
        0,           # comment length
    )

    return local + cd + eocd


def build_minimal_png() -> bytes:
    """Construct a minimal valid PNG (1x1 white pixel)."""
    import zlib

    signature = b"\x89PNG\r\n\x1a\n"

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        import struct
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return length + chunk_type + data + crc

    # IHDR: 1x1, 8-bit RGB
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)

    # IDAT: compressed scanline (filter byte 0 + RGB white)
    raw_data = b"\x00\xff\xff\xff"
    compressed = zlib.compress(raw_data)
    idat = make_chunk(b"IDAT", compressed)

    # IEND
    iend = make_chunk(b"IEND", b"")

    return signature + ihdr + idat + iend


# ============================================================================
# TESTS
# ============================================================================

passed = 0
failed = 0

def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name} — {detail}")


def test_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# --- Test 1: World and Context Registration ---
test_section("1. World & Context Registration")

world = World()
test("World initializes with Raw context", "Raw" in world.contexts)

world.register(PE_Context())
world.register(ELF_Context())
world.register(ZIP_Context())
world.register(PNG_Context())
world.register(UTF8_Context())
world.register(x86_Context())

test("All 7 contexts registered", len(world.contexts) == 7,
     f"Got {len(world.contexts)}: {world.contexts}")


# --- Test 2: PE Context with Coverage ---
test_section("2. PE Context — Satisfies with Coverage")

pe_bytes = build_minimal_pe()
pe_ctx = PE_Context()
result = pe_ctx.satisfies(pe_bytes)

test("PE parse is valid", result.valid)
test("PE coverage > 0.5", result.coverage > 0.5, f"coverage={result.coverage:.2%}")
test("PE has structured ranges", len(result.structured_ranges) > 0,
     f"ranges={len(result.structured_ranges)}")
test("PE identity has sections", "sections" in (result.identity or {}),
     f"identity keys: {list((result.identity or {}).keys())}")
test("PE identity shows AMD64", (result.identity or {}).get("machine_name") == "AMD64")
test("PE is STRONG identity", result.is_strong)

# Verify ELF does NOT satisfy PE
elf_bytes = build_minimal_elf()
result_elf_as_pe = pe_ctx.satisfies(elf_bytes)
test("ELF bytes do NOT satisfy PE", not result_elf_as_pe.valid)


# --- Test 3: ELF Context ---
test_section("3. ELF Context — Satisfies with Coverage")

elf_ctx = ELF_Context()
result = elf_ctx.satisfies(elf_bytes)

test("ELF parse is valid", result.valid)
test("ELF coverage > 0", result.coverage > 0, f"coverage={result.coverage:.2%}")
test("ELF identity shows ELF64", (result.identity or {}).get("class") == "ELF64")

# PE bytes should not satisfy ELF
result_pe_as_elf = elf_ctx.satisfies(pe_bytes)
test("PE bytes do NOT satisfy ELF", not result_pe_as_elf.valid)


# --- Test 4: ZIP Context ---
test_section("4. ZIP Context — Satisfies with Coverage")

zip_bytes = build_minimal_zip()
zip_ctx = ZIP_Context()
result = zip_ctx.satisfies(zip_bytes)

test("ZIP parse is valid", result.valid)
test("ZIP coverage > 0.5", result.coverage > 0.5, f"coverage={result.coverage:.2%}")
test("ZIP found 1 file", len((result.identity or {}).get("files", [])) == 1)


# --- Test 5: PNG Context ---
test_section("5. PNG Context")

png_bytes = build_minimal_png()
png_ctx = PNG_Context()
result = png_ctx.satisfies(png_bytes)

test("PNG parse is valid", result.valid)
test("PNG coverage > 0.9", result.coverage > 0.9, f"coverage={result.coverage:.2%}")
test("PNG found IHDR chunk", any(c["type"] == "IHDR" for c in (result.identity or {}).get("chunks", [])))


# --- Test 6: UTF-8 Context ---
test_section("6. UTF-8 Context")

text = "Hello, BIRL! 🔬 Testing UTF-8 context with unicode."
utf8_ctx = UTF8_Context()
result = utf8_ctx.satisfies(text.encode("utf-8"))

test("UTF-8 text is valid", result.valid)
test("UTF-8 coverage ~1.0", result.coverage > 0.99, f"coverage={result.coverage:.2%}")

# Binary data should have low UTF-8 coverage
result_bin = utf8_ctx.satisfies(pe_bytes)
test("PE bytes are NOT valid UTF-8 text", not result_bin.valid,
     f"valid={result_bin.valid} coverage={result_bin.coverage:.2%}")


# --- Test 7: x86 Context (Gadget Finding) ---
test_section("7. x86 Context — Gadget Discovery")

x86_ctx = x86_Context()

# The .text section of our PE starts at offset 512
text_section = pe_bytes[512:768]
result = x86_ctx.satisfies(text_section)

test("x86 parse finds gadgets", (result.identity or {}).get("num_gadgets", 0) > 0,
     f"gadgets={result.identity}")
test("x86 found pop_rcx_ret", any(
    g["id"] == "pop_rcx_ret" for g in (result.identity or {}).get("gadgets", [])
))
test("x86 found pop_rdx_ret", any(
    g["id"] == "pop_rdx_ret" for g in (result.identity or {}).get("gadgets", [])
))


# --- Test 8: Residue Calculator ---
test_section("8. Residue Analysis")

calc = ResidueCalculator()

# PE residue — should find unclaimed bytes (padding, alignment)
pe_residue = calc.analyze(pe_bytes, [PE_Context()])
test("PE residue report generated", pe_residue.total_bytes == len(pe_bytes))
test("PE has some residue", pe_residue.total_residue_bytes > 0,
     f"residue={pe_residue.total_residue_bytes} bytes")
print(f"       → {pe_residue}")

# PNG should have minimal residue  
png_residue = calc.analyze(png_bytes, [PNG_Context()])
test("PNG has minimal residue", png_residue.residue_ratio < 0.1,
     f"ratio={png_residue.residue_ratio:.2%}")


# --- Test 9: Residue Intersection (Polyglot Analysis) ---
test_section("9. Residue Intersection — Polyglot Detection")

# Create a fake polyglot: PNG with ZIP appended
polyglot = png_bytes + zip_bytes
png_result = PNG_Context().satisfies(polyglot)
zip_result = ZIP_Context().satisfies(polyglot)

test("Polyglot satisfies PNG", png_result.valid)
test("Polyglot satisfies ZIP", zip_result.valid,
     f"valid={zip_result.valid}, errors={zip_result.errors}")

# Find intersection residue
intersection = calc.residue_intersection(polyglot, PNG_Context(), ZIP_Context())
test("Residue intersection calculated", intersection is not None)

# Full multi-context analysis
multi_report = calc.analyze(polyglot, [PNG_Context(), ZIP_Context()])
test("Multi-context reduces total residue",
     multi_report.residue_ratio < calc.analyze(polyglot, [PNG_Context()]).residue_ratio,
     f"multi={multi_report.residue_ratio:.2%}")


# --- Test 10: Superposition ---
test_section("10. Superposition — Simultaneous Identity")

seq = world.load(polyglot)
identities = seq.superposition()

test("Polyglot has multiple identities", len(identities) >= 2,
     f"found {len(identities)}: {[name for name, _ in identities]}")

identity_names = [name for name, _ in identities]
test("PNG in superposition", "PNG" in identity_names)
test("ZIP in superposition", "ZIP" in identity_names)


# --- Test 11: Fluent API (Pipe-Style) ---
test_section("11. Fluent API — Pipe-Style Chaining")

seq = world.load(pe_bytes)
test("Load returns ByteSequence", isinstance(seq, ByteSequence))
test("ByteSequence has correct length", seq.length == len(pe_bytes))

# Interpret as PE
interpreted = seq.interpreting_as("PE")
test("interpreting_as returns ByteSequence", isinstance(interpreted, ByteSequence))
test("Interpretation state is set", interpreted.state is not None)
test("State shows PE context", interpreted.state.context_name == "PE")
test("State validity is valid", interpreted.state.validity.valid)

# Chain: Load → Interpret → Residue
residue = interpreted.residue()
test("Residue from fluent API works", residue.total_bytes == len(pe_bytes))

# Select sub-structure
try:
    text_sec = interpreted.select(".sections['.text']")
    test("SELECT .text section works", text_sec.length == 256,
         f"length={text_sec.length}")
    
    # Chain further: reinterpret section as x86
    as_code = text_sec.interpreting_as("x86_64")
    test("Reinterpret section as x86 works", as_code.state.validity.valid)
    test("Chain records provenance",
         len(as_code.state.chain) == 2,
         f"chain={as_code.state.chain}")
except Exception as e:
    test("SELECT .text section works", False, str(e))
    test("Reinterpret section as x86 works", False, "skipped")
    test("Chain records provenance", False, "skipped")


# --- Test 12: Injection Point Discovery ---
test_section("12. Injection Point Discovery")

points = calc.find_injection_points(pe_bytes, PE_Context(), ZIP_Context(), min_size=4)
test("Found injection points in PE", len(points) > 0,
     f"found {len(points)} points")
if points:
    print(f"       → Largest: {points[0]}")


# --- Test 13: Edge Cases ---
test_section("13. Edge Cases")

# Empty bytes
empty_result = pe_ctx.satisfies(b"")
test("Empty bytes → invalid", not empty_result.valid)

# Single byte
single_result = pe_ctx.satisfies(b"\x00")
test("Single byte → invalid PE", not single_result.valid)

# Random noise
import random
random.seed(42)
noise = bytes(random.randint(0, 255) for _ in range(1024))
noise_identities = world.load(noise).superposition()
test("Random noise identity check", True)  # Just shouldn't crash
print(f"       → Random noise identified as: {[n for n, _ in noise_identities]}")


# ============================================================================
# RESULTS
# ============================================================================

print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed + failed} passed ({passed/(passed+failed)*100:.0f}%)")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)
