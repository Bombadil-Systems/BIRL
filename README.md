# BIRL: Byte Interpretation Rewriting Language

> Security research tool for analyzing parser coverage gaps across file formats. Built for detection engineers, pentesters, and format researchers. Use responsibly and only on systems you're authorized to test.

A framework for analyzing how bytes are interpreted across file formats, finding the gaps between parsers, and building transformations that exploit those gaps.

Most security tools parse files one format at a time. BIRL parses them as *many formats simultaneously*, measures which bytes each parser actually claims, and identifies the ones nobody does. Those unclaimed bytes, the residue, are where polyglots live, where payloads hide, and where detection breaks down.

## Install

```bash
pip install -e .
```

Requires Python 3.10+. Dependencies: `pefile`, `capstone`, `kaitaistruct`, `networkx`.

## What it does

**Identify** what formats a file satisfies, with coverage metrics:

```bash
birl identify suspicious.exe
```

**Measure residue** — bytes no parser claims, ranked by size:

```bash
birl residue firmware.bin -v
```

**Harvest ROP gadgets** from signed binaries:

```bash
birl gadgets /usr/bin/ls
```

**Build polyglots** — files valid under two formats simultaneously:

```bash
birl polyglot cover.png payload.zip -o stego.png
```

**Inject data** into a file's residue regions without breaking format validity:

```bash
birl inject target.exe DEADBEEFCAFE -o modified.exe
```

**Strip format identity** (destroys headers/signatures, same approach as Veriduct):

```bash
birl strip malware.exe -o stripped.bin
```

**Wrap raw bytes** in a format container:

```bash
birl wrap shellcode.bin --as zip -o delivery.zip
```

**Find transformation paths** between format contexts using A* search:

```bash
birl path PE ZIP --strategy sanitization --compare
```

**Execute BIRL programs** — a pipe syntax for chaining operations:

```bash
birl run exploit_chain.birl -v
```

## BIRL programs

BIRL has its own scripting language for chaining operations. This example loads a signed DLL, finds the `.text` section, reinterprets it as x86, and harvests ROP gadgets:

```
LOAD "kernel32.dll"
| AS PE
| SELECT .sections['.text']
| AS x86_64
| FIND_OFFSET PATTERN="59 C3"
| SAVE_COORDINATE AS "pop_rcx"
| FIND_OFFSET PATTERN="5A C3"
| SAVE_COORDINATE AS "pop_rdx"
| REWRITE build_rop base=0x7FF800000000
| EMIT "rop_chain.bin"
```

Programs are compiled through lexical analysis, AST generation, context resolution, and A* path planning before execution.

## Python API

```python
from birl import World, Runtime

world = World()
# Registers PE, ELF, ZIP, PNG, x86_64, UTF-8 contexts
# with production parsers (pefile, Capstone, Kaitai Struct)

runtime = Runtime(world)
result = runtime.run(open("program.birl").read())

print(result.summary())
for name, coord in result.coordinates.items():
    print(f"  {name}: offset={coord.offset:#x}")
```

## Architecture

- **Contexts** — Format parsers that return validity plus byte-level coverage maps. Supported: PE, ELF, ZIP, PNG, x86_64, UTF-8.
- **Residue** — The complement of all claimed byte ranges. These are the bytes no parser accounts for.
- **Graph** — Weighted interpretation transitions between contexts, with A* pathfinding across strategies (zero-copy, sanitization, robust, fastest, balanced).
- **Forge** — Transformation engine: polyglot construction, ROP chain assembly, payload injection, format wrapping/stripping.
- **Compiler** — Lexer and parser for the BIRL pipe syntax.
- **Runtime** — Executes compiled BIRL programs with full provenance tracking (every operation records context, byte hash, and chain history).

## Tests

```bash
python tests/test_phase1.py      # Core: contexts, coverage, residue (49 tests)
python tests/test_phase2.py      # Graph: edges, pathfinding, strategies (40 tests)
python tests/test_phase3.py      # Compiler + runtime: BIRL programs (59 tests)
python tests/test_forge.py       # Forge: polyglots, injection, wrapping (39 tests)
python tests/test_production.py  # Production parsers vs minimal (29 tests)
```

216 tests total.

## Test harness

BIRL includes a harness that generates artifacts for testing against external security tools:

```bash
birl-harness generate --output-dir ./harness_output
birl-harness verify ./harness_output
birl-harness report ./harness_output
```

Each artifact ships with a JSON manifest describing what it is, what contexts it should satisfy, and expected detection behavior.

## License

MIT — see [LICENSE](LICENSE).

---

*Bombadil Systems LLC — [bombadil.systems](https://bombadil.systems)*
