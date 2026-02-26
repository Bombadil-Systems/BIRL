"""
BIRL Forge Test Suite — Digital Alchemy

Tests that BIRL can actually CREATE things:
1. Build a PNG+ZIP polyglot from scratch
2. Inject payload into PE residue without breaking the PE
3. Assemble a real ROP chain from coordinates
4. Veriduct-style strip → chunk → reassemble
5. Wrap arbitrary bytes as valid PNG
6. Wrap arbitrary bytes as valid ZIP
7. Full pipeline: Load PE → find gadgets → build ROP chain → wrap as ZIP
8. Full pipeline: Build polyglot entirely through BIRL syntax
"""

import struct
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from birl import World, compile_birl, Runtime
from birl.forge import PolyglotForge, ROPForge, StripForge, WrapForge, ForgeResult
from birl.contexts import PE_Context, ELF_Context, ZIP_Context, PNG_Context, UTF8_Context, x86_Context
from birl.context import ValidityTuple
from birl.residue import ResidueCalculator

from test_phase1 import build_minimal_pe, build_minimal_elf, build_minimal_zip, build_minimal_png


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

def make_world() -> World:
    w = World()
    w.register(PE_Context())
    w.register(ELF_Context())
    w.register(ZIP_Context())
    w.register(PNG_Context())
    w.register(UTF8_Context())
    w.register(x86_Context())
    w.build_graph()
    return w


# --- Test 1: Polyglot Construction (PNG + ZIP) ---
test_section("1. Polyglot Forge: PNG + ZIP")

png_data = build_minimal_png()
zip_data = build_minimal_zip()

forge = PolyglotForge()
result = forge.append(
    primary_data=png_data,
    primary_context=PNG_Context(),
    payload_data=zip_data,
    payload_context=ZIP_Context(),
)

test("Polyglot construction succeeds", result.success)
test("Result is valid PNG", result.validations.get("PNG", None) is not None and 
     result.validations["PNG"].valid)
test("Result is valid ZIP", result.validations.get("ZIP", None) is not None and
     result.validations["ZIP"].valid)
test("Result is valid polyglot", result.is_valid_polyglot)
test("Result is larger than either input", len(result.data) > len(png_data))
print(f"       → {result}")
print(f"       → PNG coverage: {result.validations['PNG'].coverage:.1%}")
print(f"       → ZIP coverage: {result.validations['ZIP'].coverage:.1%}")


# --- Test 2: Residue Injection ---
test_section("2. Residue Injection into PE")

pe_data = build_minimal_pe()
pe_ctx = PE_Context()

# Find residue
calc = ResidueCalculator()
residue = calc.residue(pe_data, pe_ctx)
test("PE has residue regions", len(residue) > 0)
if residue:
    print(f"       → Largest residue: {residue[0]} ({residue[0].length} bytes)")

# Inject a marker payload into residue
marker = b"BIRL_WAS_HERE_1337"
result = forge.inject_into_residue(
    primary_data=pe_data,
    primary_context=pe_ctx,
    payload=marker,
)

test("Injection succeeds", result.success, f"errors={result.errors}")
test("PE is still valid after injection",
     result.validations.get("PE", None) is not None and result.validations["PE"].valid,
     f"validations={result.validations}")
test("Marker is present in result", marker in result.data)
test("Bytes changed", result.data != pe_data)
test("Length unchanged", len(result.data) == len(pe_data))
print(f"       → {result}")


# --- Test 3: ROP Chain Assembly ---
test_section("3. ROP Chain Assembly")

rop_forge = ROPForge(pointer_size=8, base_address=0x7FF8_0000_0000)

chain = rop_forge.build_chain([
    rop_forge.gadget("pop_rcx", offset=0x1234, pattern=b"\x59\xc3", description="pop rcx; ret"),
    rop_forge.value(0x0000_DEAD_BEEF_0000, description="RCX = target address"),
    rop_forge.gadget("pop_rdx", offset=0x5678, pattern=b"\x5a\xc3", description="pop rdx; ret"),
    rop_forge.value(0x1000, description="RDX = size"),
    rop_forge.padding(5),  # Shadow space
    rop_forge.gadget("call_vprotect", offset=0x9ABC, description="VirtualProtect"),
])

test("ROP chain assembled", chain.num_entries == 6)
test("Chain has raw bytes", len(chain.raw_bytes) > 0)
test("Chain is correct size", chain.total_bytes == 80,  # 3 gadgets(24) + 2 values(16) + 5*8 padding(40) = 80
     f"got {chain.total_bytes}")

# Verify the first entry points to the right address
first_addr = struct.unpack("<Q", chain.raw_bytes[:8])[0]
test("First gadget address correct",
     first_addr == 0x7FF8_0000_0000 + 0x1234,
     f"got {first_addr:#x}")

print(f"\n{chain.hexdump()}")


# --- Test 4: Veriduct Strip + Chunk + Reassemble ---
test_section("4. Veriduct: Strip → Chunk → Reassemble")

strip_forge = StripForge()

# Strip PE headers
strip_result = strip_forge.strip_headers(pe_data, pe_ctx)
test("Strip succeeds (format destroyed)", strip_result.success)
test("Stripped data is NOT valid PE",
     not strip_result.validations.get("PE", ValidityTuple(True, 0, ())).valid
     if strip_result.validations else True)
print(f"       → {strip_result}")

# Chunk it
chunks = strip_forge.chunk(pe_data, chunk_size=128, xor_key=0xAA)
test("Chunking produces multiple chunks", len(chunks) > 1,
     f"got {len(chunks)}")
print(f"       → {len(chunks)} chunks of ~128 bytes, XOR key=0xAA")

# Reassemble
reassembled = strip_forge.reassemble(chunks, xor_key=0xAA)
test("Reassembly restores original", reassembled == pe_data)


# --- Test 5: Wrap as PNG ---
test_section("5. Wrap Forge: Arbitrary Bytes → Valid PNG")

secret_message = b"This is a secret payload hidden inside a PNG image. BIRL made this."
wrap_forge = WrapForge()

png_result = wrap_forge.wrap_as_png(secret_message, width=8)
test("Wrap as PNG succeeds", png_result.success)

# Verify it's actually a valid PNG
png_ctx = PNG_Context()
png_check = png_ctx.satisfies(png_result.data)
test("Wrapped result is valid PNG", png_check.valid)
test("PNG has IHDR chunk", any(
    c["type"] == "IHDR" for c in png_check.identity.get("chunks", [])
))
print(f"       → {png_result}")
print(f"       → Payload: {len(secret_message)}B → PNG: {len(png_result.data)}B")


# --- Test 6: Wrap as ZIP ---
test_section("6. Wrap Forge: Arbitrary Bytes → Valid ZIP")

zip_result = wrap_forge.wrap_as_zip(secret_message, filename="hidden_payload.bin")
test("Wrap as ZIP succeeds", zip_result.success)

zip_ctx = ZIP_Context()
zip_check = zip_ctx.satisfies(zip_result.data)
test("Wrapped result is valid ZIP", zip_check.valid)
test("ZIP contains our file", any(
    f["name"] == "hidden_payload.bin" for f in zip_check.identity.get("files", [])
))
print(f"       → {zip_result}")


# --- Test 7: Full Pipeline via BIRL Syntax — PE → Gadgets → ROP Chain ---
test_section("7. Full BIRL Pipeline: PE → Gadgets → ROP Chain")

pe_file = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
pe_file.write(pe_data)
pe_file.close()

world = make_world()
runtime = Runtime(world)

pipeline_source = f'''
// Full OIS-ROP pipeline: navigate PE, harvest gadgets, build chain
LOAD "{pe_file.name}"
| AS PE
| SELECT .sections['.text']
| AS x86_64

// Harvest gadgets
| FIND_OFFSET PATTERN="59 C3"
| SAVE_COORDINATE AS "pop_rcx"
| FIND_OFFSET PATTERN="5A C3"
| SAVE_COORDINATE AS "pop_rdx"
| FIND_OFFSET PATTERN="C3"
| SAVE_COORDINATE AS "ret"

// Assemble the chain from coordinates
| REWRITE build_rop base=0x7FF800000000 ptr_size=8
'''

result = runtime.run(pipeline_source)
test("Full pipeline executes", result.success, f"errors={result.errors}")

# Find the ROP chain artifact
chain_artifacts = [a for a in result.artifacts if a.get("type") == "rop_chain"]
test("ROP chain artifact created", len(chain_artifacts) > 0)

if chain_artifacts:
    chain = chain_artifacts[0]["chain"]
    test("Chain has entries", chain.num_entries > 0)
    test("Chain has raw bytes", len(chain.raw_bytes) > 0)
    print(f"\n{chain.hexdump()}")

os.unlink(pe_file.name)


# --- Test 8: Full Pipeline — Build Polyglot Through BIRL Syntax ---
test_section("8. Full BIRL Pipeline: Build PNG+ZIP Polyglot")

png_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
png_file.write(png_data)
png_file.close()

with tempfile.NamedTemporaryFile(suffix=".polyglot", delete=False) as out:
    polyglot_path = out.name

# First wrap some secret data as ZIP, then fuse with PNG
polyglot_source = f'''
// Step 1: Load the cover image
LOAD "{png_file.name}"
| AS PNG
| ASSERT SATISFIES(PNG)
| LABEL cover_image

// Step 2: Take raw payload and wrap as ZIP
LOAD "{png_file.name}"
| REWRITE wrap_zip filename="secret.bin"
| LABEL zip_payload

// Step 3: Revert to cover and build polyglot
| REVERT_TO cover_image
| AS PNG
| REWRITE polyglot_append target=ZIP payload=zip_payload

// Step 4: Verify and emit
| ASSERT SATISFIES(PNG)
| EMIT "{polyglot_path}"
'''

result = runtime.run(polyglot_source)
test("Polyglot pipeline executes", result.success, f"errors={result.errors}")

if result.success and os.path.exists(polyglot_path):
    polyglot_data = open(polyglot_path, "rb").read()
    test("Polyglot file written", len(polyglot_data) > 0)

    # Verify it's BOTH formats
    png_v = PNG_Context().satisfies(polyglot_data)
    zip_v = ZIP_Context().satisfies(polyglot_data)
    test("Output is valid PNG", png_v.valid)
    test("Output is valid ZIP", zip_v.valid)
    test("TRUE POLYGLOT achieved", png_v.valid and zip_v.valid)

    if png_v.valid and zip_v.valid:
        print(f"       → 🔥 POLYGLOT: {len(polyglot_data)}B file is BOTH PNG and ZIP")
        print(f"       → PNG coverage: {png_v.coverage:.1%}")
        print(f"       → ZIP coverage: {zip_v.coverage:.1%}")

    os.unlink(polyglot_path)

os.unlink(png_file.name)


# --- Test 9: Veriduct Pipeline Through BIRL Syntax ---
test_section("9. Veriduct Pipeline: Strip Format Identity")

pe_file2 = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
pe_file2.write(pe_data)
pe_file2.close()

strip_source = f'''
LOAD "{pe_file2.name}"
| AS PE
| ASSERT SATISFIES(PE)
| REWRITE strip
'''

result = runtime.run(strip_source)
test("Strip pipeline executes", result.success, f"errors={result.errors}")

if result.success:
    stripped = result.state.current.data
    pe_check = PE_Context().satisfies(stripped)
    test("Stripped result is NOT valid PE", not pe_check.valid)
    print(f"       → Original: valid PE. Stripped: valid={pe_check.valid}")

os.unlink(pe_file2.name)


# --- Test 10: Wrap → Verify Round-Trip ---
test_section("10. Wrap → Extract Round-Trip Verification")

original_payload = b"BIRL_FORGE_TEST_" + bytes(range(256))

# Wrap as ZIP
zip_wrapped = WrapForge().wrap_as_zip(original_payload, "test_data.bin")
test("Wrap as ZIP succeeds", zip_wrapped.success)

# Verify ZIP is valid
zip_v = ZIP_Context().satisfies(zip_wrapped.data)
test("ZIP container valid", zip_v.valid)

# Extract via Python zipfile to verify actual usability
import io, zipfile
try:
    zf = zipfile.ZipFile(io.BytesIO(zip_wrapped.data))
    extracted = zf.read("test_data.bin")
    test("ZIP extractable by Python zipfile", extracted == original_payload)
    zf.close()
except Exception as e:
    test("ZIP extractable by Python zipfile", False, str(e))


# ============================================================================
# RESULTS
# ============================================================================

print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed + failed} passed ({passed/(passed+failed)*100:.0f}%)")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)
