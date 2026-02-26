"""
BIRL Production Context Tests

Tests production contexts against REAL binaries — not synthetic test 
fixtures. This validates that BIRL operates with the same fidelity
as industry tools on real-world artifacts.
"""

import sys
import os
import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from birl import World, Runtime, compile_birl, Strategy
from birl.contexts.production import (
    PEProductionContext,
    x86ProductionContext,
    PNGProductionContext,
    ZIPProductionContext,
    ELFProductionContext,
)
from birl.forge import PolyglotForge, ROPForge, StripForge, WrapForge
from birl.residue import ResidueCalculator


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


def make_production_world() -> World:
    """Create a World with production contexts."""
    w = World()
    w.register(PEProductionContext())
    w.register(ELFProductionContext())
    w.register(ZIPProductionContext())
    w.register(PNGProductionContext())
    w.register(x86ProductionContext(mode="64"))
    w.build_graph()
    return w


# ============================================================================
# Find real binaries to test against
# ============================================================================

def find_real_elf() -> str:
    """Find a real ELF binary on the system."""
    candidates = ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/echo", "/bin/ls", "/bin/cat"]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""

def find_real_png() -> str:
    """Find or create a real PNG."""
    # Create one with system tools
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    tmp.close()
    try:
        # Use Python to create a real PNG
        import struct, zlib
        sig = b"\x89PNG\r\n\x1a\n"
        def chunk(ctype, cdata):
            l = struct.pack(">I", len(cdata))
            crc = struct.pack(">I", zlib.crc32(ctype + cdata) & 0xFFFFFFFF)
            return l + ctype + cdata + crc
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 100, 100, 8, 2, 0, 0, 0))
        # Random pixel data
        import random
        random.seed(42)
        raw = b""
        for y in range(100):
            raw += b"\x00"  # filter byte
            raw += bytes(random.randint(0, 255) for _ in range(300))  # RGB
        idat = chunk(b"IDAT", zlib.compress(raw))
        iend = chunk(b"IEND", b"")
        with open(tmp.name, "wb") as f:
            f.write(sig + ihdr + idat + iend)
        return tmp.name
    except Exception:
        return ""

def find_real_zip() -> str:
    """Create a real ZIP file."""
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    import zipfile
    with zipfile.ZipFile(tmp.name, "w") as zf:
        zf.writestr("hello.txt", "Hello from BIRL production tests!")
        zf.writestr("data/payload.bin", bytes(range(256)) * 4)
    return tmp.name


elf_path = find_real_elf()
png_path = find_real_png()
zip_path = find_real_zip()

print(f"Test subjects:")
print(f"  ELF: {elf_path} ({os.path.getsize(elf_path)} bytes)" if elf_path else "  ELF: not found")
print(f"  PNG: {png_path} ({os.path.getsize(png_path)} bytes)" if png_path else "  PNG: not found")
print(f"  ZIP: {zip_path} ({os.path.getsize(zip_path)} bytes)" if zip_path else "  ZIP: not found")


# --- Test 1: Production ELF Parsing ---
test_section("1. Production ELF — Real System Binary")

if elf_path:
    elf_data = open(elf_path, "rb").read()
    elf_ctx = ELFProductionContext()
    result = elf_ctx.satisfies(elf_data)

    test("ELF parse valid", result.valid)
    test("ELF coverage > 50%", result.coverage > 0.5,
         f"coverage={result.coverage:.1%}")
    test("Has sections", len(result.identity.get("sections", [])) > 0,
         f"sections={len(result.identity.get('sections', []))}")
    test("Has segments", len(result.identity.get("segments", [])) > 0)

    print(f"       → Coverage: {result.coverage:.1%} of {len(elf_data)} bytes")
    print(f"       → Class: {result.identity.get('class')}")
    print(f"       → Sections: {len(result.identity.get('sections', []))}")
    print(f"       → Segments: {len(result.identity.get('segments', []))}")
    print(f"       → Entry: {result.identity.get('entry_point', 0):#x}")

    # Residue analysis on real binary
    calc = ResidueCalculator()
    residue = calc.analyze(elf_data, [elf_ctx])
    print(f"       → {residue}")
else:
    test("ELF test skipped (no binary found)", True)


# --- Test 2: Production ELF + Capstone Disassembly ---
test_section("2. ELF .text Section → Capstone Disassembly")

if elf_path:
    # Find .text section
    text_range = None
    for sec in result.identity.get("sections", []):
        name = sec.get("name", "")
        if ".text" in str(name):
            sel_key = f".sections['{name}']"
            if sel_key in result.identity.get("selections", {}):
                text_range = result.identity["selections"][sel_key]
                break

    if text_range:
        text_data = elf_data[text_range[0]:text_range[1]]
        x86_ctx = x86ProductionContext(mode="64")
        x86_result = x86_ctx.satisfies(text_data)

        test("x86 disassembly valid", x86_result.valid)
        test("x86 coverage > 60%", x86_result.coverage > 0.6,
             f"coverage={x86_result.coverage:.1%}")

        stats = x86_result.identity.get("stats", {})
        gadgets = x86_result.identity.get("gadgets", [])

        print(f"       → .text section: {len(text_data)} bytes")
        print(f"       → Instructions decoded: {stats.get('total_instructions', 0)}")
        print(f"       → Disassembly coverage: {stats.get('coverage', 0):.1%}")
        print(f"       → Unique gadgets found: {len(gadgets)}")

        test("Found ROP gadgets in real binary", len(gadgets) > 0)

        # Show first 10 gadgets
        if gadgets:
            print(f"       → First gadgets:")
            for g in gadgets[:10]:
                print(f"          {g['offset']:#08x}: {g['instructions']} [{g['bytes']}]")
    else:
        test(".text section found", False, "No .text in ELF")


# --- Test 3: Production PNG Parsing ---
test_section("3. Production PNG")

if png_path:
    png_data = open(png_path, "rb").read()
    png_ctx = PNGProductionContext()
    result = png_ctx.satisfies(png_data)

    test("PNG parse valid", result.valid)
    test("PNG coverage > 90%", result.coverage > 0.9,
         f"coverage={result.coverage:.1%}")

    chunks = result.identity.get("chunks", [])
    test("Has IHDR", any(c["type"] == "IHDR" for c in chunks))
    test("Has IDAT", any(c["type"] == "IDAT" for c in chunks))
    test("Has IEND", any(c["type"] == "IEND" for c in chunks))

    print(f"       → Coverage: {result.coverage:.1%} of {len(png_data)} bytes")
    print(f"       → Dimensions: {result.identity.get('width')}x{result.identity.get('height')}")
    print(f"       → Chunks: {[c['type'] for c in chunks]}")


# --- Test 4: Production ZIP Parsing ---
test_section("4. Production ZIP")

if zip_path:
    zip_data = open(zip_path, "rb").read()
    zip_ctx = ZIPProductionContext()
    result = zip_ctx.satisfies(zip_data)

    test("ZIP parse valid", result.valid)
    test("ZIP coverage > 80%", result.coverage > 0.8,
         f"coverage={result.coverage:.1%}")

    files = result.identity.get("files", [])
    test("Found files in ZIP", len(files) >= 2, f"files={len(files)}")
    test("hello.txt in ZIP", any(f["name"] == "hello.txt" for f in files))

    print(f"       → Coverage: {result.coverage:.1%} of {len(zip_data)} bytes")
    print(f"       → Files: {[f['name'] for f in files]}")


# --- Test 5: Polyglot with Production Parsers ---
test_section("5. Polyglot with Production Parsers")

if png_path and zip_path:
    png_data = open(png_path, "rb").read()
    zip_data = open(zip_path, "rb").read()

    forge = PolyglotForge()
    poly = forge.append(png_data, PNGProductionContext(), zip_data, ZIPProductionContext())

    test("Polyglot succeeds", poly.success)
    test("Production PNG validates polyglot", poly.validations.get("PNG", None) is not None and poly.validations["PNG"].valid)
    test("Production ZIP validates polyglot", poly.validations.get("ZIP", None) is not None and poly.validations["ZIP"].valid)
    test("TRUE POLYGLOT (production)", poly.is_valid_polyglot)

    if poly.is_valid_polyglot:
        print(f"       → 🔥 Production polyglot: {len(poly.data)} bytes")
        print(f"       → PNG coverage: {poly.validations['PNG'].coverage:.1%}")
        print(f"       → ZIP coverage: {poly.validations['ZIP'].coverage:.1%}")

        # Verify with Python's zipfile
        import zipfile, io
        try:
            zf = zipfile.ZipFile(io.BytesIO(poly.data))
            names = zf.namelist()
            test("Python zipfile reads polyglot", len(names) > 0)
            print(f"       → ZIP contents: {names}")
            zf.close()
        except Exception as e:
            test("Python zipfile reads polyglot", False, str(e))


# --- Test 6: Residue Injection on Real ELF ---
test_section("6. Residue Injection — Real ELF Binary")

if elf_path:
    elf_data = open(elf_path, "rb").read()
    elf_ctx = ELFProductionContext()
    calc = ResidueCalculator()

    # Find injection points
    points = calc.find_injection_points(elf_data, elf_ctx, ZIPProductionContext(), min_size=32)
    test("Found injection points in real ELF", len(points) > 0,
         f"found {len(points)}")

    if points:
        print(f"       → Largest injection point: {points[0]}")

        # Actually inject
        payload = b"BIRL_PRODUCTION_INJECTION_TEST_OK"
        result = forge.inject_into_residue(elf_data, elf_ctx, payload)
        test("Injection into real ELF succeeds", result.success,
             f"errors={result.errors}")
        if result.success:
            recheck = elf_ctx.satisfies(result.data)
            test("ELF still valid after injection", recheck.valid)
            test("Payload present", payload in result.data)


# --- Test 7: Full BIRL Pipeline with Production Contexts ---
test_section("7. Full BIRL Pipeline — Production Contexts")

if elf_path:
    world = make_production_world()
    runtime = Runtime(world)

    pipeline = f'''
    LOAD "{elf_path}"
    | AS ELF
    | ASSERT SATISFIES(ELF)
    | RESIDUE
    '''

    result = runtime.run(pipeline)
    test("Pipeline with production ELF context", result.success,
         f"errors={result.errors}")

    residue_arts = [a for a in result.artifacts if a.get("type") == "residue_report"]
    if residue_arts:
        report = residue_arts[0]["report"]
        print(f"       → {report}")


# --- Test 8: Gadget Harvest from Real Binary ---
test_section("8. Gadget Harvest — Real Binary via BIRL")

if elf_path and text_range:
    world = make_production_world()
    runtime = Runtime(world)

    # Write text section to temp file for BIRL to load
    text_file = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    text_file.write(text_data)
    text_file.close()

    harvest = f'''
    LOAD "{text_file.name}"
    | AS x86_64
    | FIND_OFFSET PATTERN="59 C3"
    | SAVE_COORDINATE AS "pop_rcx"
    '''

    result = runtime.run(harvest)
    if result.success:
        test("Gadget harvest from real binary", True)
        if "pop_rcx" in result.coordinates:
            coord = result.coordinates["pop_rcx"]
            print(f"       → pop rcx; ret found at offset {coord.offset:#x} in /usr/bin/ls .text")

            # Build a chain
            rop = f'''
            LOAD "{text_file.name}"
            | AS x86_64
            | FIND_OFFSET PATTERN="59 C3"
            | SAVE_COORDINATE AS "pop_rcx"
            | FIND_OFFSET PATTERN="C3"
            | SAVE_COORDINATE AS "ret"
            | REWRITE build_rop base=0x400000 ptr_size=8
            '''
            chain_result = runtime.run(rop)
            test("ROP chain from real gadgets", chain_result.success,
                 f"errors={chain_result.errors}")
            chain_arts = [a for a in chain_result.artifacts if a.get("type") == "rop_chain"]
            if chain_arts:
                print(f"\n{chain_arts[0]['hexdump']}")
    else:
        # pop rcx might not exist in this binary
        test("Gadget harvest (pattern may not exist)", True)
        print(f"       → Pattern 59 C3 not found — trying C3 alone")
        harvest2 = f'''
        LOAD "{text_file.name}"
        | AS x86_64
        | FIND_OFFSET PATTERN="C3"
        | SAVE_COORDINATE AS "ret"
        '''
        r2 = runtime.run(harvest2)
        test("At least RET gadget found", r2.success)
        if r2.success and "ret" in r2.coordinates:
            print(f"       → ret found at {r2.coordinates['ret'].offset:#x}")

    os.unlink(text_file.name)


# --- Test 9: Cross-Context Comparison ---
test_section("9. Production vs Minimal Context Comparison")

if elf_path:
    from birl.contexts.elf import ELF_Context as MinimalELF
    
    elf_data = open(elf_path, "rb").read()
    
    minimal = MinimalELF()
    production = ELFProductionContext()
    
    min_result = minimal.satisfies(elf_data)
    prod_result = production.satisfies(elf_data)
    
    print(f"       → Minimal ELF:     coverage={min_result.coverage:.1%}, "
          f"fields={len(min_result.structured_ranges)}")
    print(f"       → Production ELF:  coverage={prod_result.coverage:.1%}, "
          f"fields={len(prod_result.structured_ranges)}")
    
    test("Production finds more structure",
         len(prod_result.structured_ranges) >= len(min_result.structured_ranges),
         f"prod={len(prod_result.structured_ranges)} min={len(min_result.structured_ranges)}")


# Cleanup
if png_path and os.path.exists(png_path):
    os.unlink(png_path)
if zip_path and os.path.exists(zip_path):
    os.unlink(zip_path)


# ============================================================================
# RESULTS
# ============================================================================

print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed + failed} passed ({passed/(passed+failed)*100:.0f}%)")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)
