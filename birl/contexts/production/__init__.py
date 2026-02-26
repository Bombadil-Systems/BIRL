"""
BIRL Production Contexts

These wrap real-world parsers (pefile, Capstone, Kaitai Struct)
as BIRL Contexts with full coverage tracking. Unlike the minimal
built-in contexts, these handle real-world binaries with the same
fidelity as industry tools.
"""

from birl.contexts.production.pe_production import PEProductionContext
from birl.contexts.production.x86_production import x86ProductionContext
from birl.contexts.production.png_production import PNGProductionContext
from birl.contexts.production.zip_production import ZIPProductionContext
from birl.contexts.production.elf_production import ELFProductionContext

__all__ = [
    "PEProductionContext",
    "x86ProductionContext",
    "PNGProductionContext",
    "ZIPProductionContext",
    "ELFProductionContext",
]
