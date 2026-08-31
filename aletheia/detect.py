"""Aletheia packer / protector detection - static triage.

Given a parsed PE, decide whether it looks packed or protected and, when the
fingerprints are unambiguous, name the protector. This is the *static* front-end
of the analyzer: it never runs the sample. It combines cheap, robust signals
(section entropy, R/W/X, import elision, an entry point outside the code section,
virtual-vs-raw inflation) with a small database of known section-name signatures.

Nothing here is proof - a clean high-entropy section can be legitimately
compressed data. The verdict carries a confidence and the exact signals that fed
it, so a human (or the dynamic layer) makes the call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .pe import PEInfo

# Known protectors keyed by characteristic section names (lower-cased match).
_SECTION_SIGS = {
    "UPX": ["upx0", "upx1", "upx2", "upx!"],
    "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
    "Themida/WinLicense": [".themida", ".winlice", ".winlicen", ".taz"],
    "Enigma Protector": [".enigma1", ".enigma2"],
    "ASPack": [".aspack", ".adata"],
    "Petite": [".petite"],
    "MPRESS": [".mpress1", ".mpress2"],
    "PECompact": ["pec1", "pec2"],
    "MEW": ["mew"],
    "FSG": ["fsg!"],
    "Obsidium": [".obsidium"],
    "Lethe": [],   # detected by container magic, not a section name
}
# Section names a normal MSVC/GCC/clang binary uses; anything else is a mild flag.
_NORMAL_NAMES = {
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".bss", ".tls",
    ".idata", ".edata", ".xdata", ".00cfg", ".gfids", ".didat", ".debug",
    ".voltbl", ".sxdata", ".textbss", ".cormeta",
    "fothk", "_rdata", "protdata", ".retplne", ".giats", ".gehcont", "cpadinfo", "malloc_h",
}


@dataclass
class Verdict:
    packed: bool
    confidence: float                 # 0.0 .. 1.0
    likely_packer: Optional[str]
    signals: List[str] = field(default_factory=list)

    def summary(self) -> str:
        head = (f"PACKED (confidence {self.confidence:.0%})" if self.packed
                else f"likely clean (confidence {1 - self.confidence:.0%})")
        if self.likely_packer:
            head += f" - {self.likely_packer}"
        return head


def _classify_by_section_names(names: List[str]) -> Optional[str]:
    low = [n.lower() for n in names]
    for packer, sigs in _SECTION_SIGS.items():
        if any(sig in low for sig in sigs):
            return packer
    return None


def analyze(pe: PEInfo, raw: Optional[bytes] = None) -> Verdict:
    """Score a parsed PE. `raw` (the file bytes) enables magic-based fingerprints."""
    signals: List[str] = []
    score = 0.0
    names = [s.name for s in pe.sections]

    packer = _classify_by_section_names(names)
    if packer:
        signals.append(f"known {packer} section name present")
        score += 0.9

    # Lethe (this author's own protector) leaves its container magic.
    if raw and b"LETHE01" in raw:
        packer = packer or "Lethe"
        signals.append("Lethe container magic (LETHE01) present")
        score += 0.9

    if pe.is_dotnet:
        signals.append(".NET/CLR image (managed - native packing heuristics N/A)")

    # High-entropy code/data: the classic compressed-or-encrypted tell.
    high = [s for s in pe.sections if s.raw_size >= 512 and s.entropy >= 7.2]
    if high:
        worst = max(high, key=lambda s: s.entropy)
        signals.append(f"{len(high)} high-entropy section(s) "
                       f"(max {worst.entropy:.2f} bits/byte in '{worst.name}')")
        score += 0.4

    # A section that is both writable AND executable - a strong self-modifying /
    # unpacking tell and an outright red flag for a normal compiler output.
    rwx = [s for s in pe.sections if s.writable and s.executable]
    if rwx:
        signals.append("writable+executable section(s): "
                       + ", ".join(s.name for s in rwx))
        score += 0.5

    # Entry point outside a conventional code section.
    if pe.entry_section and pe.entry_section.lower() not in (".text", ".textbss"):
        signals.append(f"entry point in '{pe.entry_section}', not .text")
        score += 0.3
    elif pe.entry_rva and not pe.entry_section:
        signals.append("entry point maps to no section (out of bounds)")
        score += 0.4

    # Import elision: a real program links dozens of functions; a stub loader
    # that resolves imports itself ships with almost none.
    if pe.import_func_count == 0 and not pe.is_dotnet:
        signals.append("no import table (imports fully elided/resolved at runtime)")
        score += 0.5
    elif 0 < pe.import_func_count <= 8:
        signals.append(f"very few imports ({pe.import_func_count} functions "
                       f"from {len(pe.import_dlls)} DLL(s)) - possible elision")
        score += 0.35

    # Virtual size >> raw size: space reserved for the unpacked image.
    inflated = [s for s in pe.sections
                if s.executable and s.raw_size and s.vsize > 4 * s.raw_size]
    if inflated:
        signals.append("code section virtual size >> raw size "
                       "(room reserved for unpacking)")
        score += 0.2

    # Unusual (non-standard) section names.
    weird = [n for n in names if n.lower() not in _NORMAL_NAMES
             and not any(n.lower() in sigs for sigs in _SECTION_SIGS.values())]
    if weird and not packer:
        signals.append("non-standard section name(s): " + ", ".join(weird[:6]))
        score += 0.15

    confidence = min(score, 1.0)
    return Verdict(packed=confidence >= 0.5, confidence=confidence,
                   likely_packer=packer, signals=signals)
