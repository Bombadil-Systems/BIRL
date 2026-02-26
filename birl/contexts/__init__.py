"""
BIRL Built-in Contexts

Each context is a parser that maps bytes to structured identity
with coverage metrics.
"""

from birl.contexts.pe import PE_Context
from birl.contexts.elf import ELF_Context
from birl.contexts.zip import ZIP_Context
from birl.contexts.png import PNG_Context
from birl.contexts.utf8 import UTF8_Context
from birl.contexts.x86 import x86_Context

__all__ = [
    "PE_Context",
    "ELF_Context", 
    "ZIP_Context",
    "PNG_Context",
    "UTF8_Context",
    "x86_Context",
]
