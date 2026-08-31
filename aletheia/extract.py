"""Static artifact extraction for Aletheia's triage layer.

Pulls the human-meaningful artifacts out of a PE *without running it*, rounding
out ``pe.py`` (structure) and ``disasm.py`` (code): printable strings (ASCII and
Windows' UTF-16LE wide form), the resource directory (manifests, version info,
icons -- and the embedded-PE hiding spot malware loves), and a sliding-window
entropy map that localizes packed/encrypted regions instead of just scoring the
whole file. ``extract_all`` bundles the lot into one triage picture.

House style: pure ``struct``/stdlib (``re`` for the string buckets), dataclasses,
fails closed on hostile input (garbage resource trees yield ``[]``, not a crash),
never executes the sample. Entropy and the section table are REUSED from
``aletheia.pe`` -- not reimplemented.

Two deliberate notes:

* ``interesting_strings`` buckets are **heuristics** -- cheap regexes to surface
  likely URLs / IPs / paths / registry keys / DLL names for a human. They will
  produce the occasional false positive (a ``1.2.3.4`` version string reads as an
  IPv4) and miss anything obfuscated. Triage convenience, not ground truth.
* ``PEInfo`` does not expose the optional header's data directories, so the
  resource walker reads data-directory index 2 straight from the header here
  (a ~15-line duplication of pe.py's offset math, kept local so ``pe.py`` stays
  untouched). Leaf ``OffsetToData`` values are RVAs and are translated to file
  offsets through pe.py's section table.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .pe import PEInfo, Section, _rva_to_off, parse_bytes, shannon_entropy

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_RES_DIR_INDEX = 2             # IMAGE_DIRECTORY_ENTRY_RESOURCE
_MAX_RES_LEAVES = 4096         # total data entries we will ever emit
_MAX_DIR_ENTRIES = 1024        # entries in one resource directory node
_MAX_RES_NAME_CHARS = 256      # clamp on a named entry's UTF-16 name
_HIGH_ENTROPY = 7.0            # bits/byte; default "looks encrypted/compressed"

# Well-known resource type IDs (winuser.h RT_*). Anything else prints as "#<id>".
_RT_NAMES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG",
    6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT", 9: "RT_ACCELERATOR",
    10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY", 20: "RT_VXD", 21: "RT_ANICURSOR", 22: "RT_ANIICON",
    23: "RT_HTML", 24: "RT_MANIFEST",
}


# ===========================================================================
# 1. strings
# ===========================================================================
@dataclass
class FoundString:
    """One printable run: file ``offset``, ``encoding`` ("ascii" | "utf-16le"),
    decoded ``text``. ``byte_len`` is the span the run occupies in the file."""
    offset: int
    encoding: str
    text: str

    @property
    def byte_len(self) -> int:
        return len(self.text) * (2 if self.encoding == "utf-16le" else 1)


def extract_strings(data: bytes, min_len: int = 4) -> List[FoundString]:
    """Find printable-character runs of length >= ``min_len`` in ``data``.

    Two forms are scanned, both single-pass (regex over bytes -- linear):

    * **ASCII**: runs of bytes in 0x20..0x7E.
    * **UTF-16LE**: runs of (printable byte, 0x00) pairs -- the common Windows
      wide-string layout. Both byte alignments are found naturally (a run may
      start at any offset), and each match is maximal, so a sub-run of an
      already-reported wide string is never reported again.

    De-dup of the interleaving: inside a wide run every other byte is 0x00, so
    the ASCII scanner can only see 1-char fragments there -- but with a small
    ``min_len`` those would spam the output as spurious ASCII hits. Any ASCII
    run whose byte range is *fully contained* in a wide run's byte range is
    therefore dropped (a single merge-walk; both lists are offset-sorted).
    Partial overlap at a boundary (real ASCII text butting up against a wide
    string) keeps both. Result is offset-ordered.
    """
    if not data:
        return []
    min_len = max(min_len, 1)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)

    wide = [FoundString(m.start(), "utf-16le", m.group()[::2].decode("ascii"))
            for m in wide_re.finditer(data)]
    spans = [(w.offset, w.offset + w.byte_len) for w in wide]  # disjoint, sorted

    out: List[FoundString] = list(wide)
    k = 0
    for m in ascii_re.finditer(data):
        s, e = m.start(), m.end()
        while k < len(spans) and spans[k][1] <= s:
            k += 1
        if k < len(spans) and spans[k][0] <= s and e <= spans[k][1]:
            continue                       # ASCII fragment inside a wide run
        out.append(FoundString(s, "ascii", m.group().decode("ascii")))
    out.sort(key=lambda f: (f.offset, f.encoding))
    return out


_RE_URL = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PATH = re.compile(r"[A-Za-z]:\\[^\"'<>|*?\x00-\x1f]{2,}")
_RE_REG = re.compile(r"\bHK(?:EY_[A-Za-z_]+|LM|CU|CR|CC|U)\\[^\"'<>|\s]+")
_RE_DLL = re.compile(r"\b[\w.\-]+\.dll\b", re.IGNORECASE)


def interesting_strings(strings: Iterable[FoundString]) -> Dict[str, List[str]]:
    """Bucket extracted strings by cheap triage regexes (HEURISTIC -- see module
    docstring): ``urls``, ``ipv4`` (octets validated <= 255; dotted versions can
    still false-positive), ``paths`` (drive-letter form), ``registry`` (HKLM /
    HKCU / HKEY_* roots), ``dlls``. All five keys are always present; values are
    order-preserving de-duplicated match texts."""
    buckets: Dict[str, List[str]] = {
        "urls": [], "ipv4": [], "paths": [], "registry": [], "dlls": []}
    for s in strings:
        text = s.text if isinstance(s, FoundString) else str(s)
        for m in _RE_URL.finditer(text):
            buckets["urls"].append(m.group())
        for m in _RE_IPV4.finditer(text):
            if all(int(o) <= 255 for o in m.group().split(".")):
                buckets["ipv4"].append(m.group())
        for m in _RE_PATH.finditer(text):
            buckets["paths"].append(m.group().rstrip(" ."))
        for m in _RE_REG.finditer(text):
            buckets["registry"].append(m.group())
        for m in _RE_DLL.finditer(text):
            buckets["dlls"].append(m.group())
    return {k: list(dict.fromkeys(v)) for k, v in buckets.items()}


# ===========================================================================
# 2. resources
# ===========================================================================
@dataclass
class ResourceEntry:
    """One resource leaf. ``type``/``name`` come from the Type and Name/ID tree
    levels ("RT_MANIFEST", "#101", or the literal name string), ``lang`` from
    the Language level. ``rva``/``size`` are the leaf data entry as declared;
    ``offset`` is the RVA translated to a file offset (None if it maps to no
    section raw data -- kept anyway as triage signal)."""
    type: str
    name: str
    lang: int
    rva: int
    size: int
    offset: Optional[int]


def _data_dir_rva(data: bytes, index: int) -> int:
    """Data-directory ``index``'s RVA read straight from the optional header
    (PEInfo does not carry the directories). 0 on anything malformed."""
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return 0
        opt = e_lfanew + 4 + 20
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic == _PE32PLUS_MAGIC:
            num_off, dd_off = opt + 108, opt + 112
        elif magic == _PE32_MAGIC:
            num_off, dd_off = opt + 92, opt + 96
        else:
            return 0
        (num_dd,) = struct.unpack_from("<I", data, num_off)
        if index >= num_dd:
            return 0
        (rva,) = struct.unpack_from("<I", data, dd_off + 8 * index)
        return rva
    except struct.error:
        return 0


def _res_entry_name(data: bytes, base: int,
                    name_field: int) -> Tuple[Optional[int], str]:
    """Resolve one directory entry's Name field -> ``(id, label)``.

    High bit set: offset (from the resource base) to an IMAGE_RESOURCE_DIR_STRING_U
    (WORD length + UTF-16LE chars) -> ``(None, "<name>")``. Clear: an integer ID
    -> ``(id, "#<id>")``."""
    if name_field & 0x80000000:
        pos = base + (name_field & 0x7FFFFFFF)
        if pos + 2 > len(data):
            return None, "?"
        (ln,) = struct.unpack_from("<H", data, pos)
        ln = min(ln, _MAX_RES_NAME_CHARS)
        raw = data[pos + 2:pos + 2 + 2 * ln]
        return None, raw.decode("utf-16le", "replace")
    return name_field, "#%d" % name_field


def _walk_res_dir(data: bytes, sections: List[Section], base: int, rel: int,
                  level: int, path: Tuple[Tuple[Optional[int], str], ...],
                  out: List[ResourceEntry], seen: set) -> None:
    """Walk one IMAGE_RESOURCE_DIRECTORY node (Type -> Name/ID -> Language).

    All bounds-checked; a node that runs past EOF, exceeds the per-directory
    entry cap, sits deeper than the 3 standard levels, or revisits an offset
    (cycle) is silently skipped -- fail closed, keep what was already found."""
    pos = base + rel
    if pos + 16 > len(data) or len(out) >= _MAX_RES_LEAVES:
        return
    num_named, num_id = struct.unpack_from("<HH", data, pos + 12)
    total = num_named + num_id
    if total > _MAX_DIR_ENTRIES:
        return
    for k in range(total):
        if len(out) >= _MAX_RES_LEAVES:
            return
        epos = pos + 16 + 8 * k
        if epos + 8 > len(data):
            return
        name_field, off_field = struct.unpack_from("<II", data, epos)
        rid, label = _res_entry_name(data, base, name_field)
        here = path + ((rid, label),)
        if off_field & 0x80000000:                     # subdirectory
            sub = off_field & 0x7FFFFFFF
            if level >= 2 or sub in seen:              # too deep / cycle
                continue
            seen.add(sub)
            _walk_res_dir(data, sections, base, sub, level + 1, here, out, seen)
        else:                                          # IMAGE_RESOURCE_DATA_ENTRY
            dpos = base + off_field
            if dpos + 16 > len(data):
                continue
            drva, dsize, _codepage, _rsvd = struct.unpack_from("<IIII", data, dpos)
            tid, tlabel = here[0]
            type_name = tlabel if tid is None else _RT_NAMES.get(tid, "#%d" % tid)
            name = here[1][1] if len(here) >= 2 else "?"
            lang = 0
            if len(here) >= 3 and here[2][0] is not None:
                lang = here[2][0]
            out.append(ResourceEntry(
                type=type_name, name=name, lang=lang, rva=drva, size=dsize,
                offset=_rva_to_off(sections, drva)))


def extract_resources(data: bytes) -> List[ResourceEntry]:
    """Walk the PE resource directory (data-directory index 2) down to its data
    leaves. Returns ``[]`` for a non-PE, a PE without resources, or a garbage
    tree (fail closed -- bounded entries/depth, cycle-guarded)."""
    try:
        pe = parse_bytes(data)
        if not pe.ok:
            return []
        rsrc_rva = _data_dir_rva(data, _RES_DIR_INDEX)
        if not rsrc_rva:
            return []
        base = _rva_to_off(pe.sections, rsrc_rva)
        if base is None:
            return []
        out: List[ResourceEntry] = []
        _walk_res_dir(data, pe.sections, base, 0, 0, (), out, {0})
        return out
    except Exception:            # noqa: BLE001 - hostile input must yield [], not a crash
        return []


# ===========================================================================
# 3. entropy map
# ===========================================================================
def entropy_map(data: bytes, window: int = 256,
                step: Optional[int] = None) -> List[Tuple[int, float]]:
    """Sliding-window Shannon entropy over the whole file: ``(offset, bits/byte)``
    per window (reuses ``pe.shannon_entropy``). ``step`` defaults to ``window``
    (non-overlapping tiling). A short final tail is still sampled; its entropy is
    inherently capped by its length, so it cannot fake a high-entropy hit."""
    if not data or window <= 0:
        return []
    if step is None or step <= 0:
        step = window
    return [(off, shannon_entropy(data[off:off + window]))
            for off in range(0, len(data), step)]


def section_entropy(pe: PEInfo) -> List[Tuple[str, float]]:
    """Per-section ``(name, entropy)`` -- straight from pe.py's parsed values."""
    return [(s.name, s.entropy) for s in pe.sections]


def high_entropy_spans(emap: List[Tuple[int, float]], threshold: float = _HIGH_ENTROPY,
                       window: Optional[int] = None) -> List[Tuple[int, int]]:
    """Merge contiguous windows with entropy >= ``threshold`` into ``(start, end)``
    byte spans -- the "where is the packed blob" localizer. Each window's extent
    is taken as ``window`` if given, else inferred from the map's sample step
    (exact for the default non-overlapping ``entropy_map`` output)."""
    if not emap:
        return []
    extent = window
    if extent is None:
        extent = emap[1][0] - emap[0][0] if len(emap) > 1 else 1
        if extent <= 0:
            extent = 1
    spans: List[Tuple[int, int]] = []
    start: Optional[int] = None
    end = 0
    for off, ent in emap:
        if ent < threshold:
            continue
        if start is None:
            start, end = off, off + extent
        elif off <= end:
            end = off + extent
        else:
            spans.append((start, end))
            start, end = off, off + extent
    if start is not None:
        spans.append((start, end))
    return spans


# ===========================================================================
# 4. roll-up
# ===========================================================================
@dataclass
class ExtractResult:
    """The combined static-triage picture ``extract_all`` returns. ``ok=False``
    (with ``error``) means the file was unreadable or not a PE -- every list is
    then empty (fail closed)."""
    ok: bool
    error: str = ""
    strings: List[FoundString] = field(default_factory=list)
    interesting: Dict[str, List[str]] = field(default_factory=dict)
    resources: List[ResourceEntry] = field(default_factory=list)
    entropy_spans: List[Tuple[int, int]] = field(default_factory=list)
    section_entropy: List[Tuple[str, float]] = field(default_factory=list)


def extract_all(path: str, min_len: int = 4, window: int = 256,
                entropy_threshold: float = _HIGH_ENTROPY) -> ExtractResult:
    """Read ``path`` once, parse it once (pe.py), and run every extractor over
    the same bytes. Never executes the sample."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return ExtractResult(ok=False, error=f"cannot read: {exc}")
    pe = parse_bytes(data)
    if not pe.ok:
        return ExtractResult(ok=False, error=pe.error)
    strings = extract_strings(data, min_len=min_len)
    return ExtractResult(
        ok=True,
        strings=strings,
        interesting=interesting_strings(strings),
        resources=extract_resources(data),
        entropy_spans=high_entropy_spans(entropy_map(data, window=window),
                                         threshold=entropy_threshold,
                                         window=window),
        section_entropy=section_entropy(pe))
