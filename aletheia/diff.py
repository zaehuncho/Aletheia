"""Binary diff mode for Aletheia -- pair equivalent functions across two projects
(a *before* and an *after*) and report the structural + pseudocode differences.

This is the patch-analysis / vulnerability-research deliverable: given two
:class:`~aletheia.project.Project` snapshots of the same program (e.g. an
unpatched build and its security update), it answers "which functions changed,
how big is the change, and -- on demand -- what does the changed pseudocode look
like line-by-line?".

--------------------------------------------------------------------------------
Function pairing -- four strategies, in the order they FIRE
--------------------------------------------------------------------------------
Each strategy only considers functions still unmatched after the previous ones;
every pair is one-to-one.

1. NAME MATCH (``matched_on='name'``, score 1.0). Same function *name* in both
   projects. Covers user labels and the analyzer's own ``sub_<addr>`` / signature
   names. Cheapest and highest-confidence, so it runs first. When a name is
   shared by several functions on a side (rare -- ``sub_`` names are unique per
   address), the sorted starts are zipped positionally (deterministic).

2. SIGNATURE MATCH (``matched_on='signature'``, score 1.0). Same
   :func:`aletheia.signatures.identify_in_pe` id in both. This catches a library
   function an analyst *renamed differently* in the two projects: the FLIRT-style
   id is recomputed from the bytes, so it is immune to the user's label. Requires
   both project files to be readable + parseable; if not, it is skipped and a
   warning is recorded (the pairing simply falls through to structure).

3. HASH MATCH (``matched_on='hash'``, score 1.0). Byte-identical functions.
   :class:`~aletheia.project.Function` does NOT persist raw bytes, so -- honoring
   the spec's "requires per-function bytes; skip if it doesn't" -- the bytes are
   *reconstructed from the project's binary on disk* over ``[start, end)`` when
   that file is available and parseable, and this strategy is SKIPPED (with a
   warning) when it is not. This is what detects a byte-identical function that
   merely MOVED (its address, hence its ``sub_`` name, changed) -- exactly the
   case name/signature miss.

4. STRUCTURE MATCH (``matched_on='structure'``, score < 1.0 in general). The
   fallback. Each remaining function is reduced to the 3-tuple
   ``(block_count, xref_in_degree, xref_out_degree)``; candidate pairs are scored
   ``1 - hamming(tuple_a, tuple_b) / 3`` (3 = the feature width) and greedily
   assigned highest-score-first. A pair is accepted only when it beats
   :data:`STRUCTURE_MIN_SCORE` (i.e. at least one feature agrees); a total
   mismatch is left to surface as add/remove rather than forced into a bogus pair.

   **Documented false-positive.** Structure matching is coarse: two *different*
   functions that happen to share the same block count and in/out xref degrees
   score 1.0 and WILL be paired -- e.g. two distinct 3-block leaf helpers each
   called from one site and calling one callee. The pair is then wrong, but the
   damage is bounded and visible: :func:`diff_projects` still computes the
   ``size_delta`` and (with ``decompile=True``) the pseudocode diff for that pair,
   so the analyst SEES the bodies do not correspond and can discard it. The
   mitigation is to prefer the earlier, exact strategies (name/signature/hash)
   and to treat a low-score structural pair as a hint, not a fact.

Unmatched functions surface as ``added`` (only in B) or ``removed`` (only in A).

--------------------------------------------------------------------------------
Classification (unchanged vs modified) and the pseudocode diff
--------------------------------------------------------------------------------
For every matched pair the ``size_delta`` and ``block_count_delta`` are always
computed. With ``decompile=True`` and BOTH sides decompilable, a unified diff of
the pseudocode is produced with :func:`difflib.unified_diff` (the whole diffing
engine -- stdlib only). ``pseudocode_diff`` is then:

* ``None``  -- not computed (``decompile=False``) or one side could not decompile
  (honest "unavailable"; we do NOT pretend an absent side means "no change");
* ``""``    -- computed, both decompiled, sources identical;
* a string  -- computed, sources differ (starts with the ``---``/``+++`` header).

A pair is **unchanged** when its identity key matches (byte hash when the binary
is available, else the ``(size, blocks, in, out)`` structural key), OR when the
pseudocode was decompiled to an identical body with an equal block count. A
non-empty pseudocode diff always forces **modified** (a real body change outranks
a coincidental structural identity). Everything else is **modified**.

--------------------------------------------------------------------------------
Determinism
--------------------------------------------------------------------------------
Same inputs -> same :class:`ProjectDiff`. Every grouping is resolved by sorted
address, candidate structural pairs are ordered by ``(-score, a_start, b_start)``,
and the final function list is ordered by ``(kind, -|size_delta|, address)``.

Stdlib only. Existing modules are imported, never modified.
"""
from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from aletheia import pe as pe_mod, signatures
from aletheia.decompile import DecompiledFunction, decompile_function
from aletheia.ir import lift_function
from aletheia.project import Function, Project

# --- tunables (documented) --------------------------------------------------
#: number of features in the structural fingerprint (block_count, in, out).
_STRUCTURE_FEATURE_WIDTH = 3
#: a structural pair is accepted only when it scores strictly above this; 0.0
#: means "at least one of the three features must agree" -- a pair with every
#: feature different is left to surface as add/remove instead of a bogus match.
STRUCTURE_MIN_SCORE = 0.0
#: pseudocode diffs are truncated to this many lines each in :func:`render`.
_PSEUDO_TRUNCATE_LINES = 50
#: how many hex chars of the binary sha256 to show in the report header.
_SHA_HEAD = 12
#: how many modified functions the report lists.
_RENDER_TOP_MODIFIED = 20

_KIND_RANK = {"modified": 0, "added": 1, "removed": 2, "unchanged": 3}


# ===========================================================================
# public data model
# ===========================================================================
@dataclass
class PairScore:
    a_start: int              # function start EA in project A
    b_start: int              # function start EA in project B
    score: float              # pairing confidence in [0.0, 1.0]; 1.0 = certain
    matched_on: str           # "name" | "signature" | "hash" | "structure"


@dataclass
class FunctionDiff:
    kind: str                 # "unchanged" | "modified" | "added" | "removed"
    a_start: Optional[int]
    b_start: Optional[int]
    a_name: str
    b_name: str
    size_delta: int           # b_size - a_size (missing side counts as 0)
    block_count_delta: int    # len(b.blocks) - len(a.blocks)
    pseudocode_diff: Optional[str]  # unified diff (see module docstring)
    score: float
    # additive: which pairing strategy produced this pair ("name" | "signature"
    # | "hash" | "structure"); "" for added/removed. Lets render() label the tag.
    matched_on: str = ""


@dataclass
class ProjectDiff:
    a_path: str
    b_path: str
    functions: List[FunctionDiff]   # ordered by kind then |size_delta| desc
    summary: Dict[str, int]         # {"unchanged", "modified", "added", "removed"}
    warnings: List[str] = field(default_factory=list)


# ===========================================================================
# raw-bytes reader (reconstructs per-function bytes from the binary on disk)
# ===========================================================================
class _ByteReader:
    """Maps a function's ``[start, end)`` virtual range to file bytes, mirroring
    the reader in :func:`aletheia.signatures.identify_in_pe`. ``ok`` is False when
    the project's binary is missing/unreadable/not a PE -- callers then fall back
    to a structural key and skip hash matching."""

    def __init__(self, project: "Project") -> None:
        self.ok = False
        self._data = b""
        self._image_base = 0
        self._sections: list = []
        try:
            with open(project.path, "rb") as fh:
                self._data = fh.read()
            info = pe_mod.parse_bytes(self._data)
            if info.ok:
                self._image_base = info.image_base
                self._sections = info.sections
                self.ok = True
        except Exception:                     # noqa: BLE001 -- missing == not ok
            self.ok = False

    def func_bytes(self, fn: "Function") -> Optional[bytes]:
        if not self.ok:
            return None
        rva = fn.start - self._image_base
        size = fn.end - fn.start
        if rva < 0 or size <= 0:
            return None
        for s in self._sections:
            if not s.raw_size or not s.contains_rva(rva):
                continue
            off = rva - s.vaddr
            if off >= s.raw_size:             # virtual-only padding: no bytes
                return None
            start = s.raw_ptr + off
            return self._data[start:start + min(size, s.raw_size - off)]
        return None


def _identity_key(reader: _ByteReader, fn: "Function"):
    """A comparable key for "are these the same function body?". Prefers a byte
    hash (when the binary is available); otherwise a coarse structural key. The
    two kinds never compare equal, which is the conservative outcome when only one
    side has bytes."""
    if reader.ok:
        b = reader.func_bytes(fn)
        if b is not None:
            return ("bytes", hashlib.sha256(b).hexdigest())
    return ("struct", fn.size, len(fn.basic_blocks),
            len(fn.xrefs_to), len(fn.xrefs_from))


# ===========================================================================
# pairing
# ===========================================================================
def _group_by(keyfn, starts, funcs) -> Dict[object, List[int]]:
    out: Dict[object, List[int]] = {}
    for s in starts:
        out.setdefault(keyfn(funcs[s]), []).append(s)
    return out


def _zip_shared(a_groups, b_groups, matched_a, matched_b, score, tag, out):
    """Positionally zip the still-unmatched members of every key shared by both
    sides, recording a :class:`PairScore` for each and marking them matched."""
    for key in sorted(a_groups.keys() & b_groups.keys(),
                      key=lambda k: (str(type(k)), repr(k))):
        a_list = [s for s in sorted(a_groups[key]) if s not in matched_a]
        b_list = [s for s in sorted(b_groups[key]) if s not in matched_b]
        for sa, sb in zip(a_list, b_list):
            out.append(PairScore(a_start=sa, b_start=sb, score=score,
                                 matched_on=tag))
            matched_a.add(sa)
            matched_b.add(sb)


def _feature(fn: "Function") -> Tuple[int, int, int]:
    return (len(fn.basic_blocks), len(fn.xrefs_to), len(fn.xrefs_from))


def _structure_score(fa: Tuple[int, int, int], fb: Tuple[int, int, int]) -> float:
    hamming = sum(1 for x, y in zip(fa, fb) if x != y)
    return 1.0 - hamming / _STRUCTURE_FEATURE_WIDTH


def _sig_map(project: "Project", side: str, warnings: List[str]) -> Dict[int, str]:
    try:
        return signatures.identify_in_pe(project.path, signatures.DEMO_SIGDB)
    except Exception as exc:                  # noqa: BLE001
        warnings.append(f"signature identification unavailable for {side} "
                        f"({project.path!r}): {exc!r}")
        return {}


def _pair(a: "Project", b: "Project"):
    """Core pairing shared by :func:`pair_functions` and :func:`diff_projects`.
    Returns ``(pairs, warnings, reader_a, reader_b)``."""
    warnings: List[str] = []
    pairs: List[PairScore] = []
    matched_a: set = set()
    matched_b: set = set()
    a_starts = sorted(a.functions)
    b_starts = sorted(b.functions)

    # 1. NAME -------------------------------------------------------------
    _zip_shared(_group_by(lambda f: f.name, a_starts, a.functions),
                _group_by(lambda f: f.name, b_starts, b.functions),
                matched_a, matched_b, 1.0, "name", pairs)

    # 2. SIGNATURE --------------------------------------------------------
    a_sig = _sig_map(a, "A", warnings)
    b_sig = _sig_map(b, "B", warnings)
    if a_sig and b_sig:
        a_groups = {}
        for addr, name in a_sig.items():
            if addr in a.functions and addr not in matched_a:
                a_groups.setdefault(name, []).append(addr)
        b_groups = {}
        for addr, name in b_sig.items():
            if addr in b.functions and addr not in matched_b:
                b_groups.setdefault(name, []).append(addr)
        _zip_shared(a_groups, b_groups, matched_a, matched_b, 1.0,
                    "signature", pairs)

    # 3. HASH (reconstructed per-function bytes) --------------------------
    reader_a = _ByteReader(a)
    reader_b = _ByteReader(b)
    if reader_a.ok and reader_b.ok:
        def hashes(reader, starts, funcs, matched):
            g: Dict[str, List[int]] = {}
            for s in starts:
                if s in matched:
                    continue
                raw = reader.func_bytes(funcs[s])
                if raw is None:               # unmapped -> fail closed, no key
                    continue
                g.setdefault(hashlib.sha256(raw).hexdigest(), []).append(s)
            return g
        _zip_shared(hashes(reader_a, a_starts, a.functions, matched_a),
                    hashes(reader_b, b_starts, b.functions, matched_b),
                    matched_a, matched_b, 1.0, "hash", pairs)
    else:
        warnings.append("hash matching skipped: raw function bytes are "
                        "unavailable for one or both projects (no readable PE)")

    # 4. STRUCTURE (greedy, highest score first) --------------------------
    a_un = [s for s in a_starts if s not in matched_a]
    b_un = [s for s in b_starts if s not in matched_b]
    cands: List[Tuple[float, int, int]] = []
    for sa in a_un:
        fa = _feature(a.functions[sa])
        for sb in b_un:
            score = _structure_score(fa, _feature(b.functions[sb]))
            if score > STRUCTURE_MIN_SCORE:
                cands.append((score, sa, sb))
    cands.sort(key=lambda c: (-c[0], c[1], c[2]))
    for score, sa, sb in cands:
        if sa in matched_a or sb in matched_b:
            continue
        pairs.append(PairScore(a_start=sa, b_start=sb, score=score,
                               matched_on="structure"))
        matched_a.add(sa)
        matched_b.add(sb)

    pairs.sort(key=lambda p: (p.a_start, p.b_start))
    return pairs, warnings, reader_a, reader_b


def pair_functions(a: "Project", b: "Project") -> List[PairScore]:
    """Match functions between two projects (name -> signature -> hash ->
    structure; see the module docstring). Returns one :class:`PairScore` per
    matched pair, sorted by ``(a_start, b_start)``. Unmatched functions do not
    appear here -- :func:`diff_projects` surfaces them as added/removed."""
    pairs, _warnings, _ra, _rb = _pair(a, b)
    return pairs


# ===========================================================================
# pseudocode
# ===========================================================================
def _decompiled_source(project: "Project", fn: "Function") -> Optional[str]:
    """The decompiled C-ish source for one project function, or ``None``.

    An instance-level ``pseudocode`` slot (a ``str`` or a
    :class:`~aletheia.decompile.DecompiledFunction`) is honored first -- it lets a
    caller inject/cache a decompilation without re-running the pipeline. Otherwise
    the real ``disasm -> lift -> decompile_function`` pipeline runs over the
    project's own in-memory disasm (or a fresh ``disasm_pe`` of its binary). Any
    failure (no capstone, unmapped, missing file) returns ``None``."""
    cached = getattr(fn, "pseudocode", None)
    if isinstance(cached, str):
        return cached
    if isinstance(cached, DecompiledFunction):
        return cached.source
    try:
        dis = getattr(project, "_disasm", None)
        if dis is None:
            from aletheia.disasm import disasm_pe
            dis = disasm_pe(project.path)
        ir_fn = lift_function(fn.start, dis.blocks, dis.instructions)
        if not ir_fn.blocks:
            return None
        return decompile_function(ir_fn, name=fn.name).source
    except Exception:                         # noqa: BLE001
        return None


def _unified(a_src: str, b_src: str, a_name: str, b_name: str) -> str:
    """Unified diff of two pseudocode strings; ``""`` when identical."""
    diff = difflib.unified_diff(
        a_src.splitlines(), b_src.splitlines(),
        fromfile=a_name, tofile=b_name, n=3, lineterm="")
    return "\n".join(diff)


# ===========================================================================
# diff
# ===========================================================================
def _classify(key_equal: bool, block_count_delta: int,
              pc: Optional[str]) -> str:
    if pc:                                    # non-empty diff -> body changed
        return "modified"
    if key_equal:                             # byte/struct identity
        return "unchanged"
    if pc == "" and block_count_delta == 0:   # decompiled identical + same blocks
        return "unchanged"
    return "modified"


def diff_projects(a: "Project", b: "Project",
                  decompile: bool = False) -> "ProjectDiff":
    """Pair the two projects, then per pair compute ``size_delta`` /
    ``block_count_delta`` (always) and -- with ``decompile=True`` and both sides
    decompilable -- a unified pseudocode diff. Pairs are classified
    unchanged/modified; functions present on only one side are added/removed.
    See the module docstring for the exact classification rule."""
    pairs, warnings, reader_a, reader_b = _pair(a, b)
    warnings = list(warnings)
    matched_a = {p.a_start for p in pairs}
    matched_b = {p.b_start for p in pairs}
    funcs: List[FunctionDiff] = []
    missing_decompile = 0

    for p in pairs:
        af = a.functions[p.a_start]
        bf = b.functions[p.b_start]
        size_delta = bf.size - af.size
        bcd = len(bf.basic_blocks) - len(af.basic_blocks)
        pc: Optional[str] = None
        if decompile:
            sa = _decompiled_source(a, af)
            sb = _decompiled_source(b, bf)
            if sa is not None and sb is not None:
                pc = _unified(sa, sb, af.name, bf.name)
            else:
                missing_decompile += 1
        key_equal = (_identity_key(reader_a, af) == _identity_key(reader_b, bf))
        funcs.append(FunctionDiff(
            kind=_classify(key_equal, bcd, pc),
            a_start=p.a_start, b_start=p.b_start,
            a_name=af.name, b_name=bf.name,
            size_delta=size_delta, block_count_delta=bcd,
            pseudocode_diff=pc, score=p.score, matched_on=p.matched_on))

    for sb in sorted(set(b.functions) - matched_b):
        bf = b.functions[sb]
        funcs.append(FunctionDiff(
            kind="added", a_start=None, b_start=sb, a_name="", b_name=bf.name,
            size_delta=bf.size, block_count_delta=len(bf.basic_blocks),
            pseudocode_diff=None, score=0.0))

    for sa in sorted(set(a.functions) - matched_a):
        af = a.functions[sa]
        funcs.append(FunctionDiff(
            kind="removed", a_start=sa, b_start=None, a_name=af.name, b_name="",
            size_delta=-af.size, block_count_delta=-len(af.basic_blocks),
            pseudocode_diff=None, score=0.0))

    if missing_decompile:
        warnings.append(f"{missing_decompile} matched pair(s) could not be "
                        f"decompiled on one or both sides (no pseudocode diff)")

    funcs.sort(key=lambda f: (
        _KIND_RANK.get(f.kind, 9), -abs(f.size_delta),
        f.a_start if f.a_start is not None else
        (f.b_start if f.b_start is not None else 0)))

    summary = {k: 0 for k in ("unchanged", "modified", "added", "removed")}
    for f in funcs:
        summary[f.kind] = summary.get(f.kind, 0) + 1

    return ProjectDiff(a_path=a.path, b_path=b.path, functions=funcs,
                       summary=summary, warnings=warnings)


# ===========================================================================
# rendering
# ===========================================================================
def _sha_head(project: "Project") -> str:
    if project.binary_sha256:
        return project.binary_sha256[:_SHA_HEAD]
    try:
        h = hashlib.sha256()
        with open(project.path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()[:_SHA_HEAD]
    except OSError:
        return "unknown"


def _truncate(text: str, limit: int) -> List[str]:
    lines = text.splitlines()
    if len(lines) <= limit:
        return lines
    return lines[:limit] + ["... (truncated) ..."]


def render(diff: "ProjectDiff", a: Optional["Project"] = None,
           b: Optional["Project"] = None) -> str:
    """Render a text report (see the module docstring for the section layout).
    ``a``/``b`` are optional -- passed, their sha256 heads appear in the header;
    otherwise the header shows ``unknown`` unless the paths are still readable."""
    a_head = _sha_head(a) if a is not None else _sha_head_from_path(diff.a_path)
    b_head = _sha_head(b) if b is not None else _sha_head_from_path(diff.b_path)

    out: List[str] = []
    out.append("# Aletheia binary diff")
    out.append(f"A: {diff.a_path}  ({a_head})")
    out.append(f"B: {diff.b_path}  ({b_head})")
    out.append("")
    out.append("## Summary")
    s = diff.summary
    out.append("unchanged: {unchanged}   modified: {modified}   "
               "added: {added}   removed: {removed}".format(
                   unchanged=s.get("unchanged", 0), modified=s.get("modified", 0),
                   added=s.get("added", 0), removed=s.get("removed", 0)))
    out.append("")

    modified = [f for f in diff.functions if f.kind == "modified"]
    out.append(f"## Modified functions (top {_RENDER_TOP_MODIFIED} by |size_delta|)")
    for f in modified[:_RENDER_TOP_MODIFIED]:
        ea = f.b_start if f.b_start is not None else f.a_start
        name = f.b_name or f.a_name
        matched_on = _matched_tag(f)
        out.append(f"- {ea:#x} ({name}) size {f.size_delta:+d} "
                   f"blocks {f.block_count_delta:+d} [{matched_on}]")
        if f.pseudocode_diff:
            for ln in _truncate(f.pseudocode_diff, _PSEUDO_TRUNCATE_LINES):
                out.append(f"    {ln}")
    if not modified:
        out.append("- (none)")
    out.append("")

    added = [f for f in diff.functions if f.kind == "added"]
    out.append("## Added")
    for f in added:
        out.append(f"- {f.b_start:#x} ({f.b_name}) size {f.size_delta:+d} "
                   f"blocks {f.block_count_delta:+d}")
    if not added:
        out.append("- (none)")
    out.append("")

    removed = [f for f in diff.functions if f.kind == "removed"]
    out.append("## Removed")
    for f in removed:
        out.append(f"- {f.a_start:#x} ({f.a_name}) size {f.size_delta:+d} "
                   f"blocks {f.block_count_delta:+d}")
    if not removed:
        out.append("- (none)")
    out.append("")

    out.append("## Warnings")
    if diff.warnings:
        for w in diff.warnings:
            out.append(f"- {w}")
    else:
        out.append("- (none)")
    return "\n".join(out)


def _matched_tag(f: "FunctionDiff") -> str:
    # the real pairing strategy; fall back to a score-derived hint if absent.
    if f.matched_on:
        return f.matched_on
    return "exact" if f.score >= 1.0 else "structure"


def _sha_head_from_path(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()[:_SHA_HEAD]
    except OSError:
        return "unknown"


__all__ = [
    "PairScore", "FunctionDiff", "ProjectDiff",
    "pair_functions", "diff_projects", "render",
    "STRUCTURE_MIN_SCORE",
]
