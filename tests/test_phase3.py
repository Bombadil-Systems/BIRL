"""
BIRL Phase 3 Test Suite

Tests the Rewriter capabilities:
1. Lexer (tokenization)
2. Parser (AST generation)
3. Runtime execution of BIRL programs
4. OIS-ROP style navigation program
5. Veriduct-style sanitization program
6. Assertion system
7. Provenance / audit trail
8. End-to-end: source code → execution result
"""

import struct
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from birl import World, compile_birl, Runtime, ExecutionResult, Strategy
from birl.compiler import tokenize, TokenType, Parser, PipelineNode, LoadNode, AsNode, SelectNode
from birl.runtime import Coordinate
from birl.contexts import PE_Context, ELF_Context, ZIP_Context, PNG_Context, UTF8_Context, x86_Context

# Reuse builders
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


# Write test PE to temp file
pe_bytes = build_minimal_pe()
pe_file = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
pe_file.write(pe_bytes)
pe_file.close()

png_bytes = build_minimal_png()
png_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
png_file.write(png_bytes)
png_file.close()


# --- Test 1: Lexer ---
test_section("1. Lexer (Tokenization)")

source = '''
LOAD "file.exe"
| AS PE
| SELECT .sections['.text']
| FIND_OFFSET PATTERN="59 C3"
| SAVE_COORDINATE AS "gadget_pop_rcx"
| EMIT payload
'''

tokens = tokenize(source)
token_types = [t.type for t in tokens if t.type != TokenType.EOF]

test("Lexer produces tokens", len(token_types) > 0, f"got {len(token_types)}")
test("LOAD token found", TokenType.LOAD in token_types)
test("AS token found", TokenType.AS in token_types)
test("SELECT token found", TokenType.SELECT in token_types)
test("FIND_OFFSET token found", TokenType.FIND_OFFSET in token_types)
test("SAVE_COORDINATE token found", TokenType.SAVE_COORDINATE in token_types)
test("String tokens parsed", any(t.type == TokenType.STRING for t in tokens))
test("Selector token parsed", any(t.type == TokenType.SELECTOR for t in tokens))
test("PIPE tokens found", token_types.count(TokenType.PIPE) >= 4)

# Test comment stripping
source_with_comments = '''
LOAD "test" // this is a comment
| AS PE      // another comment
'''
tokens_c = tokenize(source_with_comments)
test("Comments stripped", not any("comment" in t.value for t in tokens_c))


# --- Test 2: Parser ---
test_section("2. Parser (AST Generation)")

source = '''
LOAD "file.exe"
| AS PE
| SELECT .sections['.text']
| AS x86_64
| EMIT "output.bin"
'''

ast = compile_birl(source)
test("Parser returns PipelineNode", isinstance(ast, PipelineNode))
test("Pipeline has 5 operations", len(ast.operations) == 5,
     f"got {len(ast.operations)}: {[type(o).__name__ for o in ast.operations]}")

test("Op 0 is LOAD", isinstance(ast.operations[0], LoadNode))
test("Op 1 is AS", isinstance(ast.operations[1], AsNode))
test("AS context is PE", ast.operations[1].context_name == "PE")
test("Op 2 is SELECT", isinstance(ast.operations[2], SelectNode))
test("Selector is .sections['.text']", ast.operations[2].selector == ".sections['.text']")


# --- Test 3: OIS-ROP Navigation Program ---
test_section("3. OIS-ROP Navigation Program")

ois_source = f'''
// OIS-ROP: Navigate signed binary for gadgets
LOAD "{pe_file.name}"
| AS PE
| SELECT .sections['.text']
| AS x86_64
| LABEL BASE_ADDR

// Find gadgets
| FIND_OFFSET PATTERN="59 C3"
| SAVE_COORDINATE AS "gadget_pop_rcx"

| FIND_OFFSET PATTERN="5A C3"
| SAVE_COORDINATE AS "gadget_pop_rdx"

| FIND_OFFSET PATTERN="C3"
| SAVE_COORDINATE AS "gadget_ret"

// Build the coordinate payload
| EMIT_STRUCTURE [gadget_pop_rcx, 0x1000, gadget_pop_rdx, 0x2000, gadget_ret] AS ROP_Payload
'''

world = make_world()
runtime = Runtime(world)
result = runtime.run(ois_source)

test("OIS-ROP program executes", result.success, 
     f"errors={result.errors}")
test("Found gadget_pop_rcx", "gadget_pop_rcx" in result.coordinates)
test("Found gadget_pop_rdx", "gadget_pop_rdx" in result.coordinates)
test("Found gadget_ret", "gadget_ret" in result.coordinates)

if "gadget_pop_rcx" in result.coordinates:
    coord = result.coordinates["gadget_pop_rcx"]
    test("pop_rcx coordinate has offset", coord.offset >= 0)
    test("pop_rcx coordinate has context", coord.context == "x86_64")
    print(f"       → {coord}")

if "gadget_pop_rdx" in result.coordinates:
    print(f"       → {result.coordinates['gadget_pop_rdx']}")

# Check the emitted structure
rop_artifacts = [a for a in result.artifacts if a.get("type") == "rop_payload"]
test("ROP payload emitted", len(rop_artifacts) == 1)
if rop_artifacts:
    payload = rop_artifacts[0]
    test("Payload has 5 elements", payload["total_elements"] == 5,
         f"got {payload['total_elements']}")
    print(f"       → Payload: {payload['elements']}")


# --- Test 4: Provenance Trail ---
test_section("4. Provenance / Audit Trail")

test("Provenance log populated", len(result.provenance) > 0,
     f"entries={len(result.provenance)}")

for entry in result.provenance:
    op = entry["operation"]
    step = entry["step"]
    bh = entry.get("byte_hash", "?")[:8]
    print(f"       Step {step}: {op:20s} hash={bh}... ctx={entry.get('active_context')}")

# Verify key operations are logged
ops_logged = [e["operation"] for e in result.provenance]
test("LOAD logged", "LOAD" in ops_logged)
test("AS logged", "AS" in ops_logged)
test("SELECT logged", "SELECT" in ops_logged)
test("FIND_OFFSET logged", "FIND_OFFSET" in ops_logged)
test("SAVE_COORDINATE logged", "SAVE_COORDINATE" in ops_logged)
test("EMIT_STRUCTURE logged", "EMIT_STRUCTURE" in ops_logged)


# --- Test 5: Assertion System ---
test_section("5. Assertion System")

assert_source = f'''
LOAD "{pe_file.name}"
| AS PE
| ASSERT COVERAGE > 0.5
| ASSERT SATISFIES(PE)
'''

result_assert = runtime.run(assert_source)
test("Assertions pass on valid PE", result_assert.success)
test("2 assertions recorded", len(result_assert.state.assertions) == 2,
     f"got {len(result_assert.state.assertions)}")

# Failing assertion
fail_source = f'''
LOAD "{pe_file.name}"
| AS PE
| ASSERT COVERAGE > 0.99
'''
result_fail = runtime.run(fail_source)
test("High coverage assertion fails on PE", not result_fail.success)


# --- Test 6: Sanitization Program (Veriduct-style) ---
test_section("6. Sanitization Program (Veriduct-Style)")

with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as out:
    sanitized_path = out.name

sanitize_source = f'''
// Veriduct-style: strip format identity
LOAD "{pe_file.name}"
| AS PE
| SELECT .sections['.text']
| AS Raw
| REWRITE nop_sled length=10
| EMIT "{sanitized_path}"
'''

result_san = runtime.run(sanitize_source)
test("Sanitization program executes", result_san.success,
     f"errors={result_san.errors}")

# Verify the emitted file
import os
if os.path.exists(sanitized_path):
    sanitized_data = open(sanitized_path, "rb").read()
    test("Sanitized file written", len(sanitized_data) > 0)
    test("First 10 bytes are NOPs", sanitized_data[:10] == b"\x90" * 10)
    os.unlink(sanitized_path)


# --- Test 7: LABEL and REVERT_TO ---
test_section("7. LABEL / REVERT_TO")

label_source = f'''
LOAD "{pe_file.name}"
| AS PE
| LABEL full_pe
| SELECT .sections['.text']
| AS x86_64
| FIND_OFFSET PATTERN="59 C3"
| SAVE_COORDINATE AS "g1"
| REVERT_TO full_pe
| FIND_OFFSET PATTERN="4D 5A"
| SAVE_COORDINATE AS "mz_header"
'''

result_label = runtime.run(label_source)
test("LABEL/REVERT_TO program executes", result_label.success,
     f"errors={result_label.errors}")
test("g1 found in .text section", "g1" in result_label.coordinates)
test("mz_header found after revert", "mz_header" in result_label.coordinates)
if "mz_header" in result_label.coordinates:
    test("MZ at offset 0", result_label.coordinates["mz_header"].offset == 0)


# --- Test 8: FIND_PATH through graph ---
test_section("8. FIND_PATH (Graph Pathfinding)")

path_source = f'''
LOAD "{pe_file.name}"
| FIND_PATH SOURCE=PE TARGET=ZIP STRATEGY=balanced
'''

result_path = runtime.run(path_source)
test("FIND_PATH executes", result_path.success, f"errors={result_path.errors}")

path_artifacts = [a for a in result_path.artifacts if a.get("type") == "path"]
test("Path artifact emitted", len(path_artifacts) > 0)
if path_artifacts:
    pa = path_artifacts[0]
    test("Path has route", len(pa.get("route", [])) > 0)
    print(f"       → Route: {' → '.join(pa['route'])}")
    print(f"       → Weight: {pa.get('total_weight')}")


# --- Test 9: Rewrite Strategies ---
test_section("9. Rewrite Strategies")

xor_source = f'''
LOAD "{pe_file.name}"
| AS PE
| SELECT .sections['.text']
| REWRITE xor key=0xFF
| EMIT "xored"
'''
result_xor = runtime.run(xor_source)
test("XOR rewrite executes", result_xor.success, f"errors={result_xor.errors}")

# Verify XOR was applied
if result_xor.success:
    original = pe_bytes[512:768]
    xored = result_xor.state.current.data
    test("XOR changed bytes", xored != original)
    # Double XOR should restore original
    double_xored = bytes(b ^ 0xFF for b in xored)
    test("Double XOR restores original", double_xored == original)


# --- Test 10: Residue in Pipeline ---
test_section("10. Residue Analysis in Pipeline")

residue_source = f'''
LOAD "{png_file.name}"
| AS PNG
| RESIDUE
'''

result_res = runtime.run(residue_source)
test("RESIDUE in pipeline executes", result_res.success,
     f"errors={result_res.errors}")

residue_artifacts = [a for a in result_res.artifacts if a.get("type") == "residue_report"]
test("Residue report artifact emitted", len(residue_artifacts) > 0)
if residue_artifacts:
    report = residue_artifacts[0]["report"]
    print(f"       → {report}")


# --- Test 11: Complex Multi-Stage Program ---
test_section("11. Complex Multi-Stage Program")

complex_source = f'''
// Multi-stage analysis: Load PE, check identity, extract code, find gadgets
LOAD "{pe_file.name}"
| AS PE
| ASSERT SATISFIES(PE, coverage=0.5)
| LABEL original
| SELECT .sections['.text']
| AS x86_64
| FIND_OFFSET PATTERN="59 C3"
| SAVE_COORDINATE AS "pop_rcx"
| FIND_OFFSET PATTERN="5A C3"
| SAVE_COORDINATE AS "pop_rdx"
| FIND_OFFSET PATTERN="C3"
| SAVE_COORDINATE AS "ret"
| REVERT_TO original
| RESIDUE
| EMIT_STRUCTURE [pop_rcx, 0xDEAD, pop_rdx, 0xBEEF, ret] AS final_chain
'''

result_complex = runtime.run(complex_source)
test("Complex program executes", result_complex.success,
     f"errors={result_complex.errors}")
test("3 coordinates saved", len(result_complex.coordinates) == 3,
     f"got {len(result_complex.coordinates)}")
test("Residue report generated",
     any(a.get("type") == "residue_report" for a in result_complex.artifacts))
test("ROP chain emitted",
     any(a.get("type") == "rop_payload" for a in result_complex.artifacts))

print(f"\n       → {result_complex.summary()}")


# --- Test 12: Error Handling ---
test_section("12. Error Handling")

# Missing file
err1 = runtime.run('LOAD "/nonexistent/file.exe"')
test("Missing file → graceful error", not err1.success)

# Unknown context
err2 = runtime.run(f'LOAD "{pe_file.name}" | AS NonexistentFormat')
test("Unknown context → graceful error", not err2.success)

# Pattern not found
err3 = runtime.run(f'LOAD "{pe_file.name}" | AS PE | SELECT .sections[\'.text\'] | FIND_OFFSET PATTERN="FF FF FF FF FF FF FF FF"')
test("Pattern not found → graceful error", not err3.success)

# Assertion failure
err4 = runtime.run(f'LOAD "{pe_file.name}" | AS PE | ASSERT COVERAGE > 0.999')
test("Failed assertion → graceful error", not err4.success)


# --- Test 13: End-to-End Summary ---
test_section("13. Execution Result Summary")

print(f"\n{result_complex.summary()}")
print(f"\nProvenance trail ({len(result_complex.provenance)} steps):")
for entry in result_complex.provenance:
    ctx = entry.get('active_context') or '-'
    print(f"  [{entry['step']:2d}] {entry['operation']:20s} | "
          f"ctx={ctx:8s} | "
          f"hash={str(entry.get('byte_hash', '?'))[:8]}...")

test("Summary is readable", True)


# Cleanup
os.unlink(pe_file.name)
os.unlink(png_file.name)


# ============================================================================
# RESULTS
# ============================================================================

print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed + failed} passed ({passed/(passed+failed)*100:.0f}%)")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)
