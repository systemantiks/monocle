"""monocle — a monocle for stripped binaries.

Scriptable static analysis (string<->code xrefs, import resolution, function
recovery, dangerous-call triage) over capstone + pyelftools, tuned for AArch64
protocol-parser bug hunting.
"""
from .core import Binary, DANGEROUS

__version__ = "0.1.0"
__all__ = ["Binary", "DANGEROUS"]
