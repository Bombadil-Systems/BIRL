"""
BIRL Standard Edge Library

Pre-defined edges (transitions) between common contexts.
These represent the known interpretation boundaries that
Veriduct, Beauty, and OIS-ROP exploit.

Edge types:
- Isomorphic: No bytes change, pure reinterpretation
- Structural: Zoom in/out within a format (e.g., PE → section)  
- Semantic: Bytes must mutate (e.g., fix checksums, align pointers)
- Offset: OIS-style — identity exists at specific offsets in source
"""

from birl.graph import (
    InterpretationGraph,
    EdgeInfo,
    EdgeWeight,
    MutationType,
)


def register_standard_edges(graph: InterpretationGraph) -> None:
    """Register the standard library of transitions.
    
    These are the 'known roads' through interpretation space.
    Phase 3 will add the ability to discover new edges automatically.
    """

    # ==================================================================
    # RAW ↔ Everything (The universal hub)
    # ==================================================================
    # Everything can become Raw (drop all interpretation)
    for ctx_name in graph.nodes:
        if ctx_name == "Raw":
            continue

        # Context → Raw: Drop interpretation (always valid, lossless)
        graph.register_edge(EdgeInfo(
            source=ctx_name,
            target="Raw",
            weight=EdgeWeight(
                mutation=MutationType.VIEW_ONLY,
                fidelity=0.0,  # Structure is lost (we keep bytes, lose meaning)
                stability=1.0,
                cost=0.1,
            ),
            edge_type="structural",
            description=f"Drop {ctx_name} interpretation → raw bytes",
        ))

        # Raw → Context: Apply interpretation (validity depends on bytes)
        graph.register_edge(EdgeInfo(
            source="Raw",
            target=ctx_name,
            weight=EdgeWeight(
                mutation=MutationType.VIEW_ONLY,
                fidelity=1.0,  # If valid, full structure is gained
                stability=1.0,
                cost=1.0,
            ),
            edge_type="structural",
            description=f"Attempt to interpret raw bytes as {ctx_name}",
        ))

    # ==================================================================
    # PE Internal Structure
    # ==================================================================
    if "PE" in graph.nodes and "x86_64" in graph.nodes:
        # PE → x86_64: Interpret .text section as code
        graph.register_edge(EdgeInfo(
            source="PE",
            target="x86_64",
            weight=EdgeWeight(
                mutation=MutationType.VIEW_ONLY,
                fidelity=0.3,  # Lose PE structure, gain instruction semantics
                stability=0.95,
                cost=1.0,
            ),
            edge_type="structural",
            description="PE .text section → x86_64 instructions (gadget hunting)",
        ))

    # ==================================================================
    # ELF Internal Structure
    # ==================================================================
    if "ELF" in graph.nodes and "x86_64" in graph.nodes:
        graph.register_edge(EdgeInfo(
            source="ELF",
            target="x86_64",
            weight=EdgeWeight(
                mutation=MutationType.VIEW_ONLY,
                fidelity=0.3,
                stability=0.95,
                cost=1.0,
            ),
            edge_type="structural",
            description="ELF .text section → x86_64 instructions",
        ))

    # ==================================================================
    # Cross-Format (Polyglot Construction)
    # ==================================================================
    if "PE" in graph.nodes and "ZIP" in graph.nodes:
        # PE → ZIP: PE files can have ZIP appended (SFX archives)
        graph.register_edge(EdgeInfo(
            source="PE",
            target="ZIP",
            weight=EdgeWeight(
                mutation=MutationType.REWRITING,
                fidelity=0.8,  # PE structure preserved, ZIP appended
                stability=0.7,  # Depends on parser behavior
                cost=5.0,
            ),
            edge_type="semantic",
            description="Append ZIP to PE (polyglot SFX construction)",
        ))

    if "PNG" in graph.nodes and "ZIP" in graph.nodes:
        # PNG → ZIP: Classic polyglot — ZIP EOCD after IEND
        graph.register_edge(EdgeInfo(
            source="PNG",
            target="ZIP",
            weight=EdgeWeight(
                mutation=MutationType.REWRITING,
                fidelity=0.9,  # PNG fully intact, ZIP appended
                stability=0.85,
                cost=3.0,
            ),
            edge_type="semantic",
            description="PNG+ZIP polyglot (ZIP after IEND chunk)",
        ))

    # ==================================================================
    # Format Destruction (Veriduct Path)
    # ==================================================================
    if "PE" in graph.nodes:
        graph.register_edge(EdgeInfo(
            source="PE",
            target="Raw",
            weight=EdgeWeight(
                mutation=MutationType.REWRITING,
                fidelity=0.0,  # All format identity stripped
                stability=1.0,
                cost=2.0,
            ),
            edge_type="semantic",
            description="Veriduct-style format destruction: strip PE identity",
        ))

    if "ELF" in graph.nodes:
        graph.register_edge(EdgeInfo(
            source="ELF",
            target="Raw",
            weight=EdgeWeight(
                mutation=MutationType.REWRITING,
                fidelity=0.0,
                stability=1.0,
                cost=2.0,
            ),
            edge_type="semantic",
            description="Veriduct-style format destruction: strip ELF identity",
        ))

    # ==================================================================
    # Text ↔ Binary Boundaries
    # ==================================================================
    if "UTF8" in graph.nodes and "x86_64" in graph.nodes:
        # UTF8 → x86_64: Alphanumeric shellcode territory
        graph.register_edge(EdgeInfo(
            source="UTF8",
            target="x86_64",
            weight=EdgeWeight(
                mutation=MutationType.VIEW_ONLY,
                fidelity=0.1,  # Almost all structure lost
                stability=0.5,  # Only works for specific byte patterns
                cost=8.0,      # Expensive to find valid paths
            ),
            edge_type="offset",
            description="UTF-8 text as x86 code (alphanumeric shellcode)",
        ))

    # ==================================================================
    # OIS-ROP Path (Offset edges)
    # ==================================================================
    if "x86_64" in graph.nodes:
        # x86_64 → x86_64: Gadget chaining (same context, different offsets)
        graph.register_edge(EdgeInfo(
            source="x86_64",
            target="x86_64",
            weight=EdgeWeight(
                mutation=MutationType.VIEW_ONLY,
                fidelity=0.1,   # Individual gadgets, not full functions
                stability=0.85, # Offset-dependent, version-sensitive
                cost=2.0,
            ),
            edge_type="offset",
            description="ROP gadget chaining within x86 code space",
        ))
