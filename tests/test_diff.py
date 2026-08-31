"""Tests for aletheia.diff: the binary diff mode (function pairing + structural /
pseudocode differences across two projects).

Stdlib only. Projects are hand-assembled in memory -- a :class:`Project` with a
directly-populated ``functions`` dict -- so these tests need neither capstone nor
a real PE on disk. Because no binary is present, the *signature* and *hash*
pairing strategies degrade to no-ops (a warning is recorded) and pairing falls
through to name/structure; the identity check uses the structural key. That is
exactly the "no readable binary" fallback path the module documents.
"""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.diff import (  # noqa: E402
    FunctionDiff, PairScore, ProjectDiff,
    diff_projects, pair_functions, render,
)
from aletheia.project import Function, Project  # noqa: E402

BASE = 0x140000000


# ---------------------------------------------------------------------------
# in-memory synthetic project builders
# ---------------------------------------------------------------------------
def _fn(start, size, name, blocks=1, xin=0, xout=0, source="disasm"):
    """A Function with `blocks` basic blocks and xin/xout xref degrees. Only the
    LENGTHS of the block/xref lists feed the structural key, so the exact filler
    addresses are irrelevant."""
    return Function(
        start=start, end=start + size, name=name,
        basic_blocks=[start + 0x10 * i for i in range(blocks)],
        xrefs_to=[BASE + 0x9000 + i for i in range(xin)],
        xrefs_from=[BASE + 0xA000 + i for i in range(xout)],
        size=size, source=source)


def _proj(path, funcs):
    p = Project(path)
    for f in funcs:
        p.functions[f.start] = f
    return p


# three functions: entry, mid, leaf
def _base_funcs():
    return [
        _fn(BASE + 0x1000, 0x10, "entry", blocks=2, xin=0, xout=1, source="entry"),
        _fn(BASE + 0x1010, 0x0E, "sub_140001010", blocks=2, xin=1, xout=1),
        _fn(BASE + 0x1020, 0x06, "sub_140001020", blocks=1, xin=1, xout=0),
    ]


def _p1(path="/nonexistent/a.exe"):
    return _proj(path, _base_funcs())


# ===========================================================================
# identical projects
# ===========================================================================
def test_identical_projects_all_unchanged():
    p = _p1()
    d = diff_projects(p, p)
    assert d.summary == {"unchanged": 3, "modified": 0, "added": 0, "removed": 0}
    assert all(f.kind == "unchanged" for f in d.functions)
    # every function paired with itself
    assert all(f.a_start == f.b_start for f in d.functions)


# ===========================================================================
# one renamed function -> still paired, still unchanged (bytes/struct identical)
# ===========================================================================
def test_one_renamed_function_is_unchanged():
    p1 = _p1()
    p2 = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()))
    # rename the leaf: same structure, only the label changes
    p2.functions[BASE + 0x1020].name = "decrypt_blob"

    d = diff_projects(p1, p2)
    assert d.summary["modified"] == 0
    assert d.summary["added"] == 0 and d.summary["removed"] == 0
    assert d.summary["unchanged"] == 3

    leaf = next(f for f in d.functions if f.a_start == BASE + 0x1020)
    assert leaf.kind == "unchanged"
    assert leaf.a_name == "sub_140001020" and leaf.b_name == "decrypt_blob"
    # no file on disk -> signature no-ops -> paired by structure
    assert leaf.matched_on == "structure"


# ===========================================================================
# one truly modified function -> modified, size grew
# ===========================================================================
def test_one_modified_function_grows():
    p1 = _p1()
    p2 = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()))
    # bump the mid function's end by 0x20 bytes (simulate an added block of code)
    mid = p2.functions[BASE + 0x1010]
    mid.end += 0x20
    mid.size += 0x20

    d = diff_projects(p1, p2)
    assert d.summary["modified"] == 1
    assert d.summary["added"] == 0 and d.summary["removed"] == 0

    changed = next(f for f in d.functions if f.kind == "modified")
    assert changed.a_start == BASE + 0x1010 and changed.b_start == BASE + 0x1010
    assert changed.size_delta == 0x20 and changed.size_delta > 0
    assert changed.matched_on == "name"     # same name on both sides


# ===========================================================================
# one added / one removed
# ===========================================================================
def test_one_added_function():
    p1 = _p1()
    extra = _fn(BASE + 0x1040, 0x30, "brand_new", blocks=3, xin=0, xout=2)
    p2 = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()) + [extra])

    d = diff_projects(p1, p2)
    assert d.summary["added"] == 1
    assert d.summary["removed"] == 0
    added = next(f for f in d.functions if f.kind == "added")
    assert added.a_start is None and added.b_start == BASE + 0x1040
    assert added.b_name == "brand_new"
    assert added.size_delta == 0x30       # b_size - (missing a == 0)


def test_one_removed_function():
    p1 = _p1()
    extra = _fn(BASE + 0x1040, 0x30, "brand_new", blocks=3, xin=0, xout=2)
    p_more = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()) + [extra])

    # diff in the opposite direction: the extra function is now REMOVED
    d = diff_projects(p_more, p1)
    assert d.summary["removed"] == 1
    assert d.summary["added"] == 0
    removed = next(f for f in d.functions if f.kind == "removed")
    assert removed.a_start == BASE + 0x1040 and removed.b_start is None
    assert removed.size_delta == -0x30


# ===========================================================================
# pseudocode diff surfaces a body change
# ===========================================================================
def test_pseudocode_diff_surfaces():
    src_a = ("int target(void) {\n"
             "    int x = 1;\n"
             "    return x;\n"
             "}")
    src_b = ("int target(void) {\n"
             "    int x = 2;\n"
             "    int y = 3;\n"
             "    return x + y;\n"
             "}")
    fa = _fn(BASE + 0x2000, 0x40, "target", blocks=1)
    fb = _fn(BASE + 0x2000, 0x40, "target", blocks=1)
    # inject decompiled sources without re-running the real pipeline
    fa.pseudocode = src_a
    fb.pseudocode = src_b
    p1 = _proj("/nonexistent/a.exe", [fa])
    p2 = _proj("/nonexistent/b.exe", [fb])

    d = diff_projects(p1, p2, decompile=True)
    changed = next(f for f in d.functions if f.b_start == BASE + 0x2000)
    # identical structure but different body -> the diff forces "modified"
    assert changed.kind == "modified"
    pc = changed.pseudocode_diff
    assert pc and isinstance(pc, str)
    assert "@@" in pc                       # a valid unified-diff hunk header
    body_minus = [l for l in pc.splitlines()
                  if l.startswith("-") and not l.startswith("---")]
    body_plus = [l for l in pc.splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
    assert body_minus and body_plus         # both removed and added lines present


def test_pseudocode_identical_is_unchanged():
    src = "int f(void) {\n    return 0;\n}"
    fa = _fn(BASE + 0x2000, 0x40, "f", blocks=1)
    fb = _fn(BASE + 0x2000, 0x40, "f", blocks=1)
    fa.pseudocode = src
    fb.pseudocode = src
    d = diff_projects(_proj("/x/a", [fa]), _proj("/x/b", [fb]), decompile=True)
    f = d.functions[0]
    assert f.pseudocode_diff == ""          # computed, identical
    assert f.kind == "unchanged"


# ===========================================================================
# pair_functions surface
# ===========================================================================
def test_pair_functions_name_and_structure():
    p1 = _p1()
    p2 = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()))
    p2.functions[BASE + 0x1020].name = "renamed"

    pairs = pair_functions(p1, p2)
    assert all(isinstance(p, PairScore) for p in pairs)
    assert len(pairs) == 3
    by_tag = {p.a_start: p.matched_on for p in pairs}
    assert by_tag[BASE + 0x1000] == "name"
    assert by_tag[BASE + 0x1010] == "name"
    assert by_tag[BASE + 0x1020] == "structure"   # renamed -> structural pair
    # deterministic ordering by (a_start, b_start)
    assert pairs == sorted(pairs, key=lambda p: (p.a_start, p.b_start))


# ===========================================================================
# rendering
# ===========================================================================
def test_render_has_sections_and_summary():
    p1 = _p1()
    p2 = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()))
    p2.functions[BASE + 0x1010].end += 0x20
    p2.functions[BASE + 0x1010].size += 0x20
    d = diff_projects(p1, p2)

    out = render(d)
    assert "# Aletheia binary diff" in out
    assert "## Summary" in out
    assert "## Modified functions" in out
    assert "## Added" in out
    assert "## Removed" in out
    assert "## Warnings" in out
    assert "unchanged:" in out and "modified:" in out
    # the modified function is listed with its signed size delta and tag
    assert "size +32" in out                # 0x20 == 32
    assert "[name]" in out


def test_render_includes_pseudocode_diff():
    fa = _fn(BASE + 0x2000, 0x40, "target", blocks=1)
    fb = _fn(BASE + 0x2000, 0x40, "target", blocks=1)
    fa.pseudocode = "int target(void) {\n    return 1;\n}"
    fb.pseudocode = "int target(void) {\n    return 2;\n}"
    d = diff_projects(_proj("/x/a", [fa]), _proj("/x/b", [fb]), decompile=True)
    out = render(d)
    assert "target" in out
    assert "@@" in out                      # the unified-diff hunk is rendered


# ===========================================================================
# determinism
# ===========================================================================
def test_diff_is_deterministic():
    p1 = _p1()
    p2 = _proj("/nonexistent/b.exe", copy.deepcopy(_base_funcs()))
    p2.functions[BASE + 0x1020].name = "renamed"
    p2.functions[BASE + 0x1010].end += 0x10
    p2.functions[BASE + 0x1010].size += 0x10

    d1 = diff_projects(p1, p2)
    d2 = diff_projects(p1, p2)
    assert d1 == d2
    assert render(d1) == render(d2)
