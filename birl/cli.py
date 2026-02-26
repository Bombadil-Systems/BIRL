#!/usr/bin/env python3
"""
BIRL — Byte Interpretation Rewriting Language

Command-line interface for navigating interpretation space.

Usage:
    birl identify <file>              Show all contexts a file satisfies
    birl residue <file>               Show unclaimed byte regions
    birl gadgets <file>               Find ROP gadgets in a binary
    birl polyglot <file1> <file2>     Fuse two files into a polyglot
    birl inject <file> <payload>      Inject payload into file's residue
    birl strip <file>                 Destroy format identity (Veriduct)
    birl wrap <file> --as png|zip     Wrap bytes in a format container
    birl run <program.birl>           Execute a BIRL program
    birl path <source> <target>       Find interpretation path between contexts
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

# Ensure birl package is importable
birl_root = Path(__file__).resolve().parent.parent
if str(birl_root) not in sys.path:
    sys.path.insert(0, str(birl_root))

from birl import World, Runtime, compile_birl, Strategy
from birl.residue import ResidueCalculator
from birl.forge import PolyglotForge, ROPForge, StripForge, WrapForge

# Try production contexts first, fall back to minimal
try:
    from birl.contexts.production import (
        PEProductionContext,
        x86ProductionContext,
        PNGProductionContext,
        ZIPProductionContext,
        ELFProductionContext,
    )
    PRODUCTION = True
except ImportError:
    PRODUCTION = False

from birl.contexts import (
    PE_Context,
    ELF_Context,
    ZIP_Context,
    PNG_Context,
    UTF8_Context,
    x86_Context,
)


# ============================================================================
# Formatting helpers
# ============================================================================

class C:
    """ANSI colors."""
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"

    @staticmethod
    def off():
        C.BOLD = C.DIM = C.RED = C.GREEN = C.YELLOW = ""
        C.BLUE = C.MAGENTA = C.CYAN = C.WHITE = C.RESET = ""


def header(text: str) -> str:
    return f"\n{C.BOLD}{C.CYAN}{'─' * 60}{C.RESET}\n{C.BOLD}  {text}{C.RESET}\n{C.BOLD}{C.CYAN}{'─' * 60}{C.RESET}"


def ok(text: str) -> str:
    return f"  {C.GREEN}✓{C.RESET} {text}"


def warn(text: str) -> str:
    return f"  {C.YELLOW}⚠{C.RESET} {text}"


def fail(text: str) -> str:
    return f"  {C.RED}✗{C.RESET} {text}"


def dim(text: str) -> str:
    return f"{C.DIM}{text}{C.RESET}"


def bar(ratio: float, width: int = 30) -> str:
    filled = int(ratio * width)
    empty = width - filled
    if ratio > 0.8:
        color = C.GREEN
    elif ratio > 0.4:
        color = C.YELLOW
    else:
        color = C.RED
    return f"{color}{'█' * filled}{'░' * empty}{C.RESET} {ratio:.1%}"


def filesize(n: int) -> str:
    if n > 1_000_000:
        return f"{n/1_000_000:.1f} MB"
    if n > 1_000:
        return f"{n/1_000:.1f} KB"
    return f"{n} B"


# ============================================================================
# World setup
# ============================================================================

def make_world(use_production: bool = True) -> World:
    w = World()
    if use_production and PRODUCTION:
        w.register(PEProductionContext())
        w.register(ELFProductionContext())
        w.register(ZIPProductionContext())
        w.register(PNGProductionContext())
        w.register(x86ProductionContext(mode="64"))
    else:
        w.register(PE_Context())
        w.register(ELF_Context())
        w.register(ZIP_Context())
        w.register(PNG_Context())
        w.register(x86_Context())
    w.register(UTF8_Context())
    w.build_graph()
    return w


# ============================================================================
# Commands
# ============================================================================

def cmd_identify(args):
    """Identify all contexts a file satisfies."""
    data = Path(args.file).read_bytes()
    world = make_world()

    print(header(f"IDENTIFY: {args.file}"))
    print(f"  {C.DIM}Size: {filesize(len(data))}  |  Engine: {'production' if PRODUCTION else 'minimal'}{C.RESET}")

    identities = world.identify(data)

    if not identities:
        print(fail("No context matches this file"))
        return

    for ctx_name, vt in identities:
        status = f"{C.GREEN}VALID{C.RESET}" if vt.valid else f"{C.RED}INVALID{C.RESET}"
        strong = f" {C.BOLD}[STRONG]{C.RESET}" if vt.is_strong else ""
        print(f"\n  {C.BOLD}{ctx_name}{C.RESET}  {status}{strong}")
        print(f"    Coverage: {bar(vt.coverage)}")
        print(f"    Fields:   {len(vt.structured_ranges)}")

        if vt.identity:
            # Show key identity info
            for key in ("machine_name", "pe_format", "class", "endian",
                        "width", "height", "num_entries", "total_instructions",
                        "num_gadgets"):
                if key in vt.identity:
                    print(f"    {key}: {vt.identity[key]}")

            # Show sections
            sections = vt.identity.get("sections", [])
            if sections and len(sections) <= 20:
                sec_names = [s.get("name", "?") for s in sections if s.get("name")]
                if sec_names:
                    print(f"    Sections: {', '.join(sec_names[:10])}")
                    if len(sec_names) > 10:
                        print(f"              ...and {len(sec_names) - 10} more")

            # Show imports (PE)
            imports = vt.identity.get("imports", [])
            if imports:
                dll_names = [i["dll"] for i in imports[:8]]
                print(f"    Imports:  {', '.join(dll_names)}")
                if len(imports) > 8:
                    print(f"              ...and {len(imports) - 8} more DLLs")

            # Show chunks (PNG)
            chunks = vt.identity.get("chunks", [])
            if chunks:
                print(f"    Chunks:   {', '.join(c['type'] for c in chunks[:10])}")

            # Show files (ZIP)
            files = vt.identity.get("files", [])
            if files:
                print(f"    Files:    {', '.join(f['name'] for f in files[:8])}")
                if len(files) > 8:
                    print(f"              ...and {len(files) - 8} more")

    # Superposition check
    valid_contexts = [name for name, vt in identities if vt.valid]
    if len(valid_contexts) > 1:
        print(f"\n  {C.MAGENTA}⚛ SUPERPOSITION: This file simultaneously satisfies "
              f"{', '.join(valid_contexts)}{C.RESET}")


def cmd_residue(args):
    """Show unclaimed byte regions."""
    data = Path(args.file).read_bytes()
    world = make_world()
    calc = ResidueCalculator()

    print(header(f"RESIDUE: {args.file}"))
    print(f"  {C.DIM}Size: {filesize(len(data))}{C.RESET}")

    identities = world.identify(data)
    if not identities:
        print(fail("No context matches — entire file is residue"))
        return

    for ctx_name, vt in identities:
        if not vt.valid:
            continue

        ctx = world.get_context(ctx_name)
        ranges = calc.residue(data, ctx)

        print(f"\n  {C.BOLD}{ctx_name}{C.RESET}  coverage={bar(vt.coverage)}")
        total_residue = sum(r.length for r in ranges)
        residue_pct = total_residue / len(data) if data else 0

        if not ranges:
            print(ok("No residue — parser claims all bytes"))
        else:
            print(f"    Unclaimed: {C.YELLOW}{filesize(total_residue)}{C.RESET} ({residue_pct:.1%}) across {len(ranges)} region(s)")
            for r in ranges[:15]:
                print(f"    {C.DIM}[{r.start:#08x}:{r.end:#08x}]{C.RESET} {filesize(r.length)}")
                if args.verbose:
                    preview = data[r.start:min(r.start + 32, r.end)]
                    hex_str = " ".join(f"{b:02x}" for b in preview)
                    print(f"      {C.DIM}{hex_str}{C.RESET}")
            if len(ranges) > 15:
                print(f"    {C.DIM}...and {len(ranges) - 15} more regions{C.RESET}")

    # Multi-context residue intersection
    valid = [(name, vt) for name, vt in identities if vt.valid]
    if len(valid) > 1:
        ctx_a = world.get_context(valid[0][0])
        ctx_b = world.get_context(valid[1][0])
        intersection = calc.residue_intersection(data, ctx_a, ctx_b)
        if intersection:
            total_shared = sum(r.length for r in intersection)
            print(f"\n  {C.MAGENTA}Shared blind spot ({valid[0][0]} ∩ {valid[1][0]}): "
                  f"{filesize(total_shared)} — neither parser claims these bytes{C.RESET}")


def cmd_gadgets(args):
    """Find ROP gadgets in a binary."""
    data = Path(args.file).read_bytes()
    world = make_world()

    print(header(f"GADGETS: {args.file}"))

    # Identify format to find code sections
    identities = world.identify(data)
    code_data = data
    section_name = "(raw file)"

    for ctx_name, vt in identities:
        if ctx_name in ("PE", "ELF") and vt.valid:
            selections = vt.identity.get("selections", {})
            for key, (start, end) in selections.items():
                if ".text" in key:
                    code_data = data[start:end]
                    section_name = key
                    break
            break

    print(f"  {C.DIM}Analyzing: {section_name} ({filesize(len(code_data))}){C.RESET}")

    # Use production Capstone context if available
    if PRODUCTION:
        from birl.contexts.production.x86_production import x86ProductionContext
        ctx = x86ProductionContext(mode="64")
    else:
        ctx = x86_Context()

    vt = ctx.satisfies(code_data)
    gadgets = vt.identity.get("gadgets", [])

    if not gadgets:
        print(warn("No gadgets found"))
        return

    print(f"\n  {C.GREEN}{len(gadgets)} unique gadgets found{C.RESET}")
    print(f"  {C.DIM}Disassembly coverage: {vt.identity.get('stats', {}).get('coverage', 0):.1%}{C.RESET}")

    # Categorize
    categories = {"pop": [], "mov": [], "xchg": [], "add": [], "sub": [],
                  "xor": [], "call": [], "jmp": [], "other": []}
    for g in gadgets:
        insn = g["instructions"].split(";")[0].strip().split()[0] if g.get("instructions") else ""
        categorized = False
        for cat in categories:
            if cat in insn:
                categories[cat].append(g)
                categorized = True
                break
        if not categorized:
            categories["other"].append(g)

    for cat, glist in categories.items():
        if not glist:
            continue
        print(f"\n  {C.BOLD}{cat.upper()}{C.RESET} ({len(glist)})")
        limit = args.limit if hasattr(args, 'limit') else 10
        for g in glist[:limit]:
            print(f"    {C.CYAN}{g['offset']:#08x}{C.RESET}  {g['instructions']}  {C.DIM}[{g['bytes']}]{C.RESET}")
        if len(glist) > limit:
            print(f"    {C.DIM}...and {len(glist) - limit} more{C.RESET}")

    if args.output:
        out = {"file": args.file, "section": section_name,
               "total": len(gadgets), "gadgets": gadgets}
        Path(args.output).write_text(json.dumps(out, indent=2))
        print(f"\n  {ok(f'Saved to {args.output}')}")


def cmd_polyglot(args):
    """Fuse two files into a polyglot."""
    primary_data = Path(args.file1).read_bytes()
    payload_data = Path(args.file2).read_bytes()
    world = make_world()

    print(header(f"POLYGLOT: {args.file1} + {args.file2}"))

    # Auto-detect contexts
    id1 = world.identify(primary_data)
    id2 = world.identify(payload_data)

    if not id1 or not id2:
        print(fail("Could not identify one or both files"))
        return

    ctx1_name = id1[0][0]
    ctx2_name = id2[0][0]
    ctx1 = world.get_context(ctx1_name)
    ctx2 = world.get_context(ctx2_name)

    print(f"  Primary: {C.BOLD}{ctx1_name}{C.RESET} ({filesize(len(primary_data))})")
    print(f"  Payload: {C.BOLD}{ctx2_name}{C.RESET} ({filesize(len(payload_data))})")

    forge = PolyglotForge()
    result = forge.append(primary_data, ctx1, payload_data, ctx2)

    if result.is_valid_polyglot:
        out_path = args.output or f"polyglot_{ctx1_name}_{ctx2_name}.bin"
        Path(out_path).write_bytes(result.data)
        print(f"\n  {C.GREEN}{'█' * 40}{C.RESET}")
        print(f"  {C.GREEN}{C.BOLD}  POLYGLOT FORGED{C.RESET}")
        print(f"  {C.GREEN}{'█' * 40}{C.RESET}")
        print(f"\n  Output: {out_path} ({filesize(len(result.data))})")
        for ctx_name, vt in result.validations.items():
            status = f"{C.GREEN}VALID{C.RESET}" if vt.valid else f"{C.RED}INVALID{C.RESET}"
            print(f"    {ctx_name}: {status}  coverage={bar(vt.coverage)}")
    else:
        print(f"\n  {fail('Polyglot construction failed')}")
        for ctx_name, vt in result.validations.items():
            print(f"    {ctx_name}: valid={vt.valid} coverage={vt.coverage:.1%}")
        if result.errors:
            for e in result.errors:
                print(f"    {C.RED}{e}{C.RESET}")


def cmd_inject(args):
    """Inject payload into file's residue."""
    file_data = Path(args.file).read_bytes()
    world = make_world()

    if os.path.exists(args.payload):
        payload = Path(args.payload).read_bytes()
    else:
        # Treat as hex string
        try:
            payload = bytes.fromhex(args.payload.replace(" ", ""))
        except ValueError:
            payload = args.payload.encode("utf-8")

    print(header(f"INJECT: {filesize(len(payload))} into {args.file}"))

    identities = world.identify(file_data)
    if not identities:
        print(fail("Cannot identify file format"))
        return

    ctx_name = identities[0][0]
    ctx = world.get_context(ctx_name)
    print(f"  Format: {C.BOLD}{ctx_name}{C.RESET}")

    forge = PolyglotForge()
    result = forge.inject_into_residue(file_data, ctx, payload)

    if result.success:
        out_path = args.output or f"injected_{Path(args.file).name}"
        Path(out_path).write_bytes(result.data)
        print(ok(f"Injection successful — format still valid"))
        print(f"  Output: {out_path}")
        for m in result.mutations:
            print(f"    {C.DIM}{m['description']}{C.RESET}")
    else:
        print(fail("Injection failed"))
        for e in result.errors:
            print(f"    {C.RED}{e}{C.RESET}")


def cmd_strip(args):
    """Destroy format identity (Veriduct-style)."""
    data = Path(args.file).read_bytes()
    world = make_world()

    print(header(f"STRIP: {args.file}"))

    identities = world.identify(data)
    if not identities:
        print(fail("Cannot identify file format"))
        return

    ctx_name = identities[0][0]
    ctx = world.get_context(ctx_name)
    print(f"  Format: {C.BOLD}{ctx_name}{C.RESET}")

    forge = StripForge()
    result = forge.strip_headers(data, ctx)

    if result.success:
        out_path = args.output or f"stripped_{Path(args.file).name}"
        Path(out_path).write_bytes(result.data)
        print(ok(f"Format identity destroyed"))
        print(f"  Output: {out_path}")
        print(f"  Fields zeroed: {len(result.mutations)}")
        for m in result.mutations[:10]:
            print(f"    {C.DIM}{m['description']}{C.RESET}")

        # Verify it's broken
        recheck = ctx.satisfies(result.data)
        print(f"\n  Re-check as {ctx_name}: {'VALID' if recheck.valid else 'DESTROYED'}")
    else:
        print(fail("Strip failed"))
        for e in result.errors:
            print(f"    {C.RED}{e}{C.RESET}")


def cmd_wrap(args):
    """Wrap bytes in a format container."""
    data = Path(args.file).read_bytes()
    forge = WrapForge()
    fmt = args.format.lower()

    print(header(f"WRAP: {args.file} → {fmt.upper()}"))

    if fmt == "png":
        width = args.width or 16
        result = forge.wrap_as_png(data, width=width)
    elif fmt == "zip":
        filename = args.filename or Path(args.file).name
        result = forge.wrap_as_zip(data, filename=filename)
    else:
        print(fail(f"Unknown format: {fmt} (supported: png, zip)"))
        return

    if result.success:
        ext = f".{fmt}"
        out_path = args.output or f"wrapped_{Path(args.file).stem}{ext}"
        Path(out_path).write_bytes(result.data)
        print(ok(result.description))
        print(f"  Output: {out_path} ({filesize(len(result.data))})")
    else:
        print(fail("Wrap failed"))


def cmd_run(args):
    """Execute a BIRL program."""
    source = Path(args.program).read_text()
    world = make_world()
    runtime = Runtime(world)

    print(header(f"RUN: {args.program}"))

    if args.verbose:
        print(f"{C.DIM}{source}{C.RESET}")

    result = runtime.run(source)

    if result.success:
        print(ok(f"Program completed — {len(result.provenance)} steps"))
    else:
        print(fail(f"Program failed"))
        for e in result.errors:
            print(f"    {C.RED}{e}{C.RESET}")

    # Show coordinates
    if result.coordinates:
        print(f"\n  {C.BOLD}Coordinates:{C.RESET}")
        for name, coord in result.coordinates.items():
            print(f"    {C.CYAN}{name}{C.RESET}: offset={coord.offset:#x} ctx={coord.context}")

    # Show artifacts
    for art in result.artifacts:
        atype = art.get("type", "?")
        if atype == "bytes" and art.get("written_to"):
            print(ok(f"Emitted: {art['written_to']} ({filesize(art['size'])})"))
        elif atype == "rop_chain":
            print(f"\n{art.get('hexdump', '')}")
        elif atype == "forge_result":
            fr = art.get("forge_result")
            if fr:
                print(f"  {C.DIM}Forge: {fr.description}{C.RESET}")
        elif atype == "residue_report":
            report = art.get("report")
            if report:
                print(f"  {C.DIM}{report}{C.RESET}")

    # Provenance
    if args.verbose:
        print(f"\n  {C.BOLD}Provenance:{C.RESET}")
        for entry in result.provenance:
            ctx = entry.get("active_context") or "-"
            print(f"    [{entry['step']:2d}] {entry['operation']:20s} ctx={ctx}")

    return 0 if result.success else 1


def cmd_path(args):
    """Find interpretation path between contexts."""
    world = make_world()

    strategy_map = {
        "zero_copy": Strategy.ZERO_COPY,
        "robust": Strategy.ROBUST,
        "sanitization": Strategy.SANITIZATION,
        "fastest": Strategy.FASTEST,
        "balanced": Strategy.BALANCED,
    }
    strategy = strategy_map.get(args.strategy, Strategy.BALANCED)

    print(header(f"PATH: {args.source} → {args.target} [{args.strategy}]"))

    path = world.graph.find_path(args.source, args.target, strategy)

    if path is None:
        print(fail(f"No path found from {args.source} to {args.target}"))
        return

    route = [path[0].source] + [e.target for e in path]
    total = world.graph.path_total_weight(path)

    print(f"\n  {C.BOLD}Route:{C.RESET} {f' {C.CYAN}→{C.RESET} '.join(route)}")
    print(f"  Hops: {len(path)}")
    print(f"  Mutation: {total.mutation.name}")
    print(f"  Fidelity: {total.fidelity:.2f}")
    print(f"  Stability: {total.stability:.2f}")
    print(f"  Cost: {total.cost:.2f}")

    for i, edge in enumerate(path):
        mut = f"{C.RED}REWRITE{C.RESET}" if edge.weight.mutation.value else f"{C.GREEN}VIEW{C.RESET}"
        print(f"\n    [{i+1}] {edge.source} → {edge.target}  {mut}")
        print(f"        {C.DIM}{edge.description}{C.RESET}")
        print(f"        F={edge.weight.fidelity:.2f}  S={edge.weight.stability:.2f}  C={edge.weight.cost:.1f}")

    # Show all strategies for comparison
    if args.compare:
        print(f"\n  {C.BOLD}All strategies:{C.RESET}")
        for sname, strat in strategy_map.items():
            p = world.graph.find_path(args.source, args.target, strat)
            if p:
                r = [p[0].source] + [e.target for e in p]
                tw = world.graph.path_total_weight(p)
                print(f"    {sname:15s}: {' → '.join(r):30s}  cost={tw.cost:.1f}  mut={tw.mutation.name}")


# ============================================================================
# CLI setup
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="birl",
        description="BIRL — Byte Interpretation Rewriting Language",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        examples:
          birl identify malware.exe
          birl residue document.pdf
          birl gadgets signed_binary.dll
          birl polyglot cover.png payload.zip -o stego.png
          birl inject firmware.bin DEADBEEF -o modified.bin
          birl strip malware.exe -o stripped.bin
          birl wrap shellcode.bin --as zip -o delivery.zip
          birl run exploit_chain.birl -v
          birl path PE ZIP --strategy sanitization --compare
        """),
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--minimal", action="store_true", help="Use minimal parsers instead of production")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # identify
    p = sub.add_parser("identify", aliases=["id"], help="Identify all contexts a file satisfies")
    p.add_argument("file", help="File to identify")

    # residue
    p = sub.add_parser("residue", aliases=["res"], help="Show unclaimed byte regions")
    p.add_argument("file", help="File to analyze")
    p.add_argument("-v", "--verbose", action="store_true", help="Show hex preview of residue")

    # gadgets
    p = sub.add_parser("gadgets", aliases=["gad"], help="Find ROP gadgets")
    p.add_argument("file", help="Binary to analyze")
    p.add_argument("-o", "--output", help="Save gadgets to JSON file")
    p.add_argument("-n", "--limit", type=int, default=10, help="Max gadgets per category to display")

    # polyglot
    p = sub.add_parser("polyglot", aliases=["poly"], help="Fuse two files into a polyglot")
    p.add_argument("file1", help="Primary file (format preserved)")
    p.add_argument("file2", help="Payload file (appended)")
    p.add_argument("-o", "--output", help="Output file path")

    # inject
    p = sub.add_parser("inject", help="Inject payload into residue")
    p.add_argument("file", help="Target file")
    p.add_argument("payload", help="Payload: file path, hex string, or text")
    p.add_argument("-o", "--output", help="Output file path")

    # strip
    p = sub.add_parser("strip", help="Destroy format identity (Veriduct)")
    p.add_argument("file", help="File to strip")
    p.add_argument("-o", "--output", help="Output file path")

    # wrap
    p = sub.add_parser("wrap", help="Wrap bytes in a format container")
    p.add_argument("file", help="Raw bytes to wrap")
    p.add_argument("--as", dest="format", required=True, choices=["png", "zip"], help="Target format")
    p.add_argument("-o", "--output", help="Output file path")
    p.add_argument("--width", type=int, help="PNG width (default: 16)")
    p.add_argument("--filename", help="Filename inside ZIP")

    # run
    p = sub.add_parser("run", help="Execute a BIRL program")
    p.add_argument("program", help="Path to .birl program file")
    p.add_argument("-v", "--verbose", action="store_true", help="Show source and provenance")

    # path
    p = sub.add_parser("path", help="Find interpretation path between contexts")
    p.add_argument("source", help="Source context (e.g., PE)")
    p.add_argument("target", help="Target context (e.g., ZIP)")
    p.add_argument("--strategy", default="balanced",
                   choices=["zero_copy", "robust", "sanitization", "fastest", "balanced"])
    p.add_argument("--compare", action="store_true", help="Compare all strategies")

    args = parser.parse_args()

    if args.no_color:
        C.off()

    if not args.command:
        parser.print_help()
        return

    # Dispatch
    commands = {
        "identify": cmd_identify, "id": cmd_identify,
        "residue": cmd_residue, "res": cmd_residue,
        "gadgets": cmd_gadgets, "gad": cmd_gadgets,
        "polyglot": cmd_polyglot, "poly": cmd_polyglot,
        "inject": cmd_inject,
        "strip": cmd_strip,
        "wrap": cmd_wrap,
        "run": cmd_run,
        "path": cmd_path,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            handler(args)
        except FileNotFoundError as e:
            print(fail(f"File not found: {e}"))
            sys.exit(1)
        except Exception as e:
            print(fail(f"Error: {e}"))
            if args.command == "run":
                sys.exit(1)
            raise
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
