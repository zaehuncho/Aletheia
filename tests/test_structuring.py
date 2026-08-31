"""Tests for control-flow structuring (aletheia.structuring).

Like test_dataflow, almost everything is built *by hand* -- tiny IR whose CFG
shape has a known-on-paper structured form -- so the loop/if/switch recovery is
pinned without capstone. Only the end-to-end smoke lifts real bytes and
``importorskip``s capstone locally.

Block starts are small integer EAs; only the graph shape matters. A ``BR`` block
carries a synthetic condition Value and its ``then_ea`` / ``else_ea`` (taken /
fallthrough) plus a matching ``succs`` list ``[then_ea, else_ea]`` (the order the
disassembler emits). A ``JMP`` block has one succ; a ``RET`` block has none.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag  # noqa: E402
from aletheia.dataflow import dominators  # noqa: E402
from aletheia.structuring import (  # noqa: E402
    NodeKind, SNode, StructuredFunction, structure, is_loop_header,
    natural_loops, post_order, immediate_post_dominators,
)


# ---------------------------------------------------------------------------
# IR constructors
# ---------------------------------------------------------------------------
def _reg(name, size=64):
    return Value(VTag.REG, name=name, size=size)


def _imm(v, size=64):
    return Value(VTag.IMM, imm=v, size=size)


def _br(ea, then_ea, else_ea, token="ne"):
    cond = Value(VTag.TEMP, name=f"cc_{token}", size=8)
    return IRInsn(ea, Op.BR, dst=None, args=(cond, _reg("ZF", 8)),
                  then_ea=then_ea, else_ea=else_ea)


def _jmp(ea, target):
    return IRInsn(ea, Op.JMP, args=(_imm(target),))


def _ijmp(ea, reg="rax"):
    """Indirect (register-target) jmp -- a switch dispatch."""
    return IRInsn(ea, Op.JMP, args=(_reg(reg),))


def _cmp(ea, reg, imm):
    """cmp <reg>, <imm> -- the compare that feeds a cmp-chain / range-check BR."""
    return IRInsn(ea, Op.CMP, dst=None, args=(_reg(reg), _imm(imm)))


def _mem(base=None, index=None, scale=1, disp=0, size=64):
    return Value(VTag.MEM, size=size, base=base, index=index, scale=scale, disp=disp)


def _load_tab(ea, dst_reg, index_reg, scale=8, disp=0x400000):
    """load <dst>, [<index>*scale + disp] -- the jump-table target load."""
    return IRInsn(ea, Op.LOAD, dst=_reg(dst_reg),
                  args=(_mem(index=_reg(index_reg), scale=scale, disp=disp),))


def _ret(ea):
    return IRInsn(ea, Op.RET, args=())


def _fn(blocks, entry):
    """blocks: list of (start, insns, succs)."""
    b = {start: IRBlock(start=start, insns=list(insns), succs=list(succs))
         for start, insns, succs in blocks}
    return IRFunction(start=entry, blocks=b, entry=entry)


def _find(node, kind):
    """Every SNode of ``kind`` in the tree rooted at ``node`` (pre-order)."""
    found = []

    def rec(n):
        if n is None:
            return
        if n.kind == kind:
            found.append(n)
        for c in n.children:
            rec(c)
        for attr in (n.then_branch, n.else_branch, n.body, n.default):
            rec(attr)
        for _v, cb in n.cases:
            rec(cb)

    rec(node)
    return found


# ===========================================================================
# natural_loops
# ===========================================================================
def test_natural_loops_simple():
    #   A(0) -> B(1) ; B -> C(2) and B -> D(3, exit) ; C -> B (back-edge)
    fn = _fn([
        (0, [_jmp(0, 1)], [1]),
        (1, [_br(1, 2, 3)], [2, 3]),
        (2, [_jmp(2, 1)], [1]),
        (3, [_ret(3)], []),
    ], entry=0)
    idom = dominators(fn)
    loops = natural_loops(fn, idom)
    assert set(loops) == {1}                       # single header: B
    assert loops[1] == {1, 2}                       # body {B, C}
    # the exit edge B -> D leaves the body
    assert 3 in fn.blocks[1].succs and 3 not in loops[1]
    assert is_loop_header(fn, 1, idom)
    assert not is_loop_header(fn, 0, idom)


def test_natural_loops_nested():
    #   outer header H1(0), inner header H2(1); inner body {1,2}; outer {0,1,2,3}
    fn = _fn([
        (0, [_br(0, 1, 4)], [1, 4]),
        (1, [_br(1, 2, 3)], [2, 3]),
        (2, [_jmp(2, 1)], [1]),        # inner back-edge -> H2
        (3, [_jmp(3, 0)], [0]),        # outer back-edge -> H1
        (4, [_ret(4)], []),
    ], entry=0)
    idom = dominators(fn)
    loops = natural_loops(fn, idom)
    assert set(loops) == {0, 1}
    assert loops[1] == {1, 2}
    assert loops[0] == {0, 1, 2, 3}
    assert is_loop_header(fn, 0, idom) and is_loop_header(fn, 1, idom)


# ===========================================================================
# post_order
# ===========================================================================
def test_post_order_entry_is_last():
    fn = _fn([
        (0, [_br(0, 1, 2)], [1, 2]),
        (1, [_jmp(1, 3)], [3]),
        (2, [_jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    po = post_order(fn)
    assert set(po) == {0, 1, 2, 3}
    assert po[-1] == 0                              # entry finished last
    # a leaf comes before its predecessors in post-order
    assert po.index(3) < po.index(1) and po.index(3) < po.index(2)


def test_post_order_empty():
    fn = IRFunction(start=0xdead, blocks={}, entry=0xdead)
    assert post_order(fn) == []


# ===========================================================================
# post-dominators
# ===========================================================================
def test_immediate_post_dominators_diamond():
    #   A(0) -> B(1),C(2) -> D(3): D post-dominates everything above it
    fn = _fn([
        (0, [_br(0, 1, 2)], [1, 2]),
        (1, [_jmp(1, 3)], [3]),
        (2, [_jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    ipdom = immediate_post_dominators(fn)
    assert ipdom[0] == 3 and ipdom[1] == 3 and ipdom[2] == 3


# ===========================================================================
# IF-THEN-ELSE (diamond)
# ===========================================================================
def test_if_then_else_diamond():
    fn = _fn([
        (0, [_br(0, 1, 2)], [1, 2]),   # then=B(1), else=C(2)
        (1, [_jmp(1, 3)], [3]),
        (2, [_jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0 and sf.unreachable == []
    root = sf.body
    assert root.kind == NodeKind.SEQ
    iff = root.children[0]
    assert iff.kind == NodeKind.IF
    assert iff.then_branch.kind == NodeKind.BLOCK and iff.then_branch.block.start == 1
    assert iff.else_branch.kind == NodeKind.BLOCK and iff.else_branch.block.start == 2
    # the follow block D is sequenced after the IF
    blocks = [c for c in root.children if c.kind == NodeKind.BLOCK]
    assert any(b.block.start == 3 for b in blocks)
    # cond is the terminating BR insn
    assert iff.cond.op == Op.BR


# ===========================================================================
# IF-THEN (no else)
# ===========================================================================
def test_if_then_no_else():
    fn = _fn([
        (0, [_br(0, 1, 3)], [1, 3]),   # then=B(1), else=merge D(3)
        (1, [_jmp(1, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0
    root = sf.body
    iff = _find(root, NodeKind.IF)[0]
    assert iff.then_branch is not None and iff.then_branch.block.start == 1
    assert iff.else_branch is None                  # no else arm
    assert any(b.block.start == 3 for b in _find(root, NodeKind.BLOCK))


# ===========================================================================
# WHILE (pre-test)
# ===========================================================================
def test_while_pretest():
    fn = _fn([
        (0, [_br(0, 1, 2)], [1, 2]),   # header: taken=body(1), else=exit(2)
        (1, [_jmp(1, 0)], [0]),        # body loops back to header
        (2, [_ret(2)], []),
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0
    whiles = _find(sf.body, NodeKind.WHILE)
    assert len(whiles) == 1
    w = whiles[0]
    assert w.cond.op == Op.BR and w.ea == 0
    # body is (or contains) the single body block B(1)
    body_blocks = _find(w.body, NodeKind.BLOCK)
    assert any(b.block.start == 1 for b in body_blocks)
    # the exit block follows the loop
    assert any(b.block.start == 2 for b in _find(sf.body, NodeKind.BLOCK))


# ===========================================================================
# DO-WHILE (post-test)
# ===========================================================================
def test_do_while_posttest():
    #   header H(0) does NOT end in BR; the latch B(1) does.
    fn = _fn([
        (0, [_jmp(0, 1)], [1]),
        (1, [_br(1, 0, 2)], [0, 2]),   # latch: back-edge to 0, exit to 2
        (2, [_ret(2)], []),
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0
    dws = _find(sf.body, NodeKind.DO_WHILE)
    assert len(dws) == 1
    dw = dws[0]
    assert dw.cond is not None and dw.cond.op == Op.BR
    # both loop blocks appear in the body
    starts = {b.block.start for b in _find(dw.body, NodeKind.BLOCK)}
    assert {0, 1} <= starts


# ===========================================================================
# nested WHILE inside WHILE
# ===========================================================================
def test_nested_while_loops():
    fn = _fn([
        (0, [_br(0, 1, 4)], [1, 4]),   # outer header
        (1, [_br(1, 2, 3)], [2, 3]),   # inner header
        (2, [_jmp(2, 1)], [1]),        # inner back-edge
        (3, [_jmp(3, 0)], [0]),        # outer back-edge (latch)
        (4, [_ret(4)], []),
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0
    outer = _find(sf.body, NodeKind.WHILE)
    # there is an outer WHILE whose body contains an inner WHILE
    assert any(_find(w.body, NodeKind.WHILE) for w in outer)
    top = [w for w in outer if _find(w.body, NodeKind.WHILE)][0]
    assert top.ea == 0
    inner = _find(top.body, NodeKind.WHILE)[0]
    assert inner.ea == 1


# ===========================================================================
# BREAK inside a loop
# ===========================================================================
def test_break_inside_loop():
    #   header(0, WHILE) ; body(1) branches to K(2, break->follow 4) or C(3, latch)
    fn = _fn([
        (0, [_br(0, 1, 4)], [1, 4]),   # header; follow = 4
        (1, [_br(1, 2, 3)], [2, 3]),   # if X -> K(2) else -> C(3)
        (2, [_jmp(2, 4)], [4]),        # K: jumps out of the loop (break)
        (3, [_jmp(3, 0)], [0]),        # C: latch back to header
        (4, [_ret(4)], []),
    ], entry=0)
    sf = structure(fn)
    w = _find(sf.body, NodeKind.WHILE)[0]
    breaks = _find(w.body, NodeKind.BREAK)
    assert len(breaks) >= 1                         # a break appears in the loop body
    # and it did not degrade to gotos
    assert sf.goto_count == 0


# ===========================================================================
# SWITCH (best-effort; case values are synthetic ordinals)
# ===========================================================================
def test_switch_best_effort():
    #   indirect jmp (rax) with 3 resolved successors -> SWITCH with 3 cases
    fn = _fn([
        (0, [_ijmp(0, "rax")], [1, 2, 3]),
        (1, [_jmp(1, 4)], [4]),
        (2, [_jmp(2, 4)], [4]),
        (3, [_jmp(3, 4)], [4]),
        (4, [_ret(4)], []),
    ], entry=0)
    sf = structure(fn)
    sw = _find(sf.body, NodeKind.SWITCH)
    assert len(sw) == 1
    s = sw[0]
    assert s.scrutinee.tag == VTag.REG and s.scrutinee.name == "rax"
    assert len(s.cases) == 3
    case_starts = {cb.block.start for _v, cb in s.cases if cb.kind == NodeKind.BLOCK}
    assert case_starts == {1, 2, 3}
    # case values are the synthetic ordinals 0..2 (real jump-table values NOT recovered)
    assert [v for v, _ in s.cases] == [0, 1, 2]


# ===========================================================================
# SWITCH value recovery: CMP chain (real case values + default)
# ===========================================================================
def test_switch_cmp_chain_recovers_values():
    #   A(0):  cmp rdi,10 ; je B(1) ; else A1(2)
    #   A1(2): cmp rdi,20 ; je C(3) ; else D(4, default)
    #   B,C,D all jump to E(5, merge/ret)
    fn = _fn([
        (0, [_cmp(0, "rdi", 10), _br(0, 1, 2, "eq")], [1, 2]),
        (2, [_cmp(2, "rdi", 20), _br(2, 3, 4, "eq")], [3, 4]),
        (1, [_jmp(1, 5)], [5]),
        (3, [_jmp(3, 5)], [5]),
        (4, [_jmp(4, 5)], [5]),
        (5, [_ret(5)], []),
    ], entry=0)
    sf = structure(fn)
    sw = _find(sf.body, NodeKind.SWITCH)
    assert len(sw) == 1
    s = sw[0]
    # real case values 10 -> B(1), 20 -> C(3); default = D(4)
    case_map = [(v, cb.block.start) for v, cb in s.cases if cb.kind == NodeKind.BLOCK]
    assert case_map == [(10, 1), (20, 3)]
    assert s.default is not None and s.default.kind == NodeKind.BLOCK
    assert s.default.block.start == 4
    assert s.scrutinee.tag == VTag.REG and s.scrutinee.name == "rdi"
    assert sf.switch_recovery == {0: "cmp_chain"}
    assert sf.goto_count == 0


def test_switch_cmp_chain_needs_two_compares():
    #   a SINGLE equality compare is a plain if/else, NOT a switch
    fn = _fn([
        (0, [_cmp(0, "rdi", 10), _br(0, 1, 2, "eq")], [1, 2]),
        (1, [_jmp(1, 3)], [3]),
        (2, [_jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    sf = structure(fn)
    assert _find(sf.body, NodeKind.SWITCH) == []     # no switch
    assert _find(sf.body, NodeKind.IF)               # a plain IF instead
    assert sf.switch_recovery == {}


# ===========================================================================
# SWITCH value recovery: jump table (ordinal, but LABELED as a jump table)
# ===========================================================================
def test_switch_jump_table_labeled():
    #   load rax, [rdi*8 + table] ; jmp rax   -- 3 successors
    fn = _fn([
        (0, [_load_tab(0, "rax", "rdi", 8), _ijmp(0, "rax")], [1, 2, 3]),
        (1, [_jmp(1, 4)], [4]),
        (2, [_jmp(2, 4)], [4]),
        (3, [_jmp(3, 4)], [4]),
        (4, [_ret(4)], []),
    ], entry=0)
    sf = structure(fn)
    sw = _find(sf.body, NodeKind.SWITCH)
    assert len(sw) == 1
    s = sw[0]
    # ordinal case values -- which IS what a dense jump table means
    assert [v for v, _ in s.cases] == [0, 1, 2]
    case_starts = {cb.block.start for _v, cb in s.cases if cb.kind == NodeKind.BLOCK}
    assert case_starts == {1, 2, 3}
    # scrutinee is the table INDEX register (the real switch variable), not the temp
    assert s.scrutinee.tag == VTag.REG and s.scrutinee.name == "rdi"
    # ...but LABELED as a jump table so the caller knows the ordinals are meaningful
    assert sf.switch_recovery == {0: "jump_table"}


# ===========================================================================
# SWITCH value recovery: range check + jump table (combo, folded into one SWITCH)
# ===========================================================================
def test_switch_range_plus_table():
    #   A(0):  cmp rdi,3 ; ja default(5) ; else dispatcher(1)
    #   1:     load rax, [rdi*8 + table] ; jmp rax  -- cases 2,3,4
    fn = _fn([
        (0, [_cmp(0, "rdi", 3), _br(0, 5, 1, "a")], [5, 1]),
        (1, [_load_tab(1, "rax", "rdi", 8), _ijmp(1, "rax")], [2, 3, 4]),
        (2, [_jmp(2, 6)], [6]),
        (3, [_jmp(3, 6)], [6]),
        (4, [_jmp(4, 6)], [6]),
        (5, [_jmp(5, 6)], [6]),     # default (out-of-range) arm
        (6, [_ret(6)], []),
    ], entry=0)
    sf = structure(fn)
    sw = _find(sf.body, NodeKind.SWITCH)
    assert len(sw) == 1
    s = sw[0]
    case_map = [(v, cb.block.start) for v, cb in s.cases if cb.kind == NodeKind.BLOCK]
    assert case_map == [(0, 2), (1, 3), (2, 4)]          # ordinal table cases
    assert s.default is not None and s.default.block.start == 5   # out-of-range arm
    assert s.scrutinee.tag == VTag.REG and s.scrutinee.name == "rdi"
    assert sf.switch_recovery == {0: "range_plus_table"}
    assert sf.goto_count == 0 and sf.unreachable == []


# ===========================================================================
# SWITCH bail: indirect jmp with no table structure -> ordinals + "bail"
# ===========================================================================
def test_switch_bail_no_crash():
    fn = _fn([
        (0, [_ijmp(0, "rax")], [1, 2]),
        (1, [_jmp(1, 3)], [3]),
        (2, [_jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    sf = structure(fn)                              # must not raise
    sw = _find(sf.body, NodeKind.SWITCH)
    assert len(sw) == 1
    s = sw[0]
    assert [v for v, _ in s.cases] == [0, 1]        # ordinals kept
    assert s.default is None
    assert sf.switch_recovery == {0: "bail"}


# ===========================================================================
# Labelled multi-level break to an OUTER loop (was a GOTO fallback)
# ===========================================================================
def test_labeled_break_to_outer():
    #   outer WHILE header 0 (follow 5); inner WHILE header 1 (follow 4).
    #   inner body block 2 branches to K(3) which jumps to the OUTER follow (5):
    #   a multi-level break that must become `break L1;`, not a goto.
    fn = _fn([
        (0, [_br(0, 1, 5, "eq")], [1, 5]),     # outer header
        (1, [_br(1, 2, 4, "eq")], [2, 4]),     # inner header
        (2, [_br(2, 3, 6, "eq")], [3, 6]),     # inner body: K(3) or latch(6)
        (3, [_jmp(3, 5)], [5]),                # K: jump to OUTER follow -> break L1
        (6, [_jmp(6, 1)], [1]),                # inner latch
        (4, [_jmp(4, 0)], [0]),                # inner exit -> outer latch
        (5, [_ret(5)], []),                    # outer follow
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0                       # no goto fallback
    assert _find(sf.body, NodeKind.GOTO) == []
    assert sf.label_count == 1
    whiles = {w.ea: w for w in _find(sf.body, NodeKind.WHILE)}
    assert whiles[0].label == "L1"                  # outer loop labelled
    assert whiles[1].label == ""                    # inner loop unlabelled
    breaks = _find(sf.body, NodeKind.BREAK)
    assert any(b.target_label == "L1" for b in breaks)


# ===========================================================================
# Labelled multi-level continue to an OUTER loop
# ===========================================================================
def test_labeled_continue_to_outer():
    #   like above, but K(3) jumps back to the OUTER header (0): a multi-level
    #   continue that must become `continue L1;`.
    fn = _fn([
        (0, [_br(0, 1, 5, "eq")], [1, 5]),     # outer header
        (1, [_br(1, 2, 4, "eq")], [2, 4]),     # inner header
        (2, [_br(2, 3, 6, "eq")], [3, 6]),     # inner body: K(3) or latch(6)
        (3, [_jmp(3, 0)], [0]),                # K: jump to OUTER header -> continue L1
        (6, [_jmp(6, 1)], [1]),                # inner latch
        (4, [_jmp(4, 0)], [0]),                # inner exit -> outer latch
        (5, [_ret(5)], []),                    # outer follow
    ], entry=0)
    sf = structure(fn)
    assert sf.goto_count == 0
    assert _find(sf.body, NodeKind.GOTO) == []
    assert sf.label_count == 1
    whiles = {w.ea: w for w in _find(sf.body, NodeKind.WHILE)}
    assert whiles[0].label == "L1"
    conts = _find(sf.body, NodeKind.CONTINUE)
    assert any(c.target_label == "L1" for c in conts)


# ===========================================================================
# No labels are minted when an innermost break is enough
# ===========================================================================
def test_no_labels_when_unnecessary():
    #   a single (nested) loop whose only break targets the INNERMOST follow.
    fn = _fn([
        (0, [_br(0, 1, 4, "eq")], [1, 4]),     # header (follow 4)
        (1, [_br(1, 2, 3, "eq")], [2, 3]),     # if X -> break, else latch
        (2, [_jmp(2, 4)], [4]),                # break to innermost follow
        (3, [_jmp(3, 0)], [0]),                # latch
        (4, [_ret(4)], []),
    ], entry=0)
    sf = structure(fn)
    assert sf.label_count == 0
    for b in _find(sf.body, NodeKind.BREAK):
        assert b.target_label == ""             # plain, unlabelled break
    for w in _find(sf.body, NodeKind.WHILE):
        assert w.label == ""


# ===========================================================================
# irreducible flow -> GOTO fallback, no crash
# ===========================================================================
def test_irreducible_falls_back_to_goto():
    #   A(0) enters BOTH B(1) and C(2); B<->C cross-edges; neither dominates the
    #   other, so there is no natural loop -- an irreducible cycle.
    fn = _fn([
        (0, [_br(0, 1, 2)], [1, 2]),
        (1, [_br(1, 2, 3)], [2, 3]),   # B -> C, exit
        (2, [_br(2, 1, 3)], [1, 3]),   # C -> B, exit
        (3, [_ret(3)], []),
    ], entry=0)
    idom = dominators(fn)
    assert natural_loops(fn, idom) == {}            # genuinely irreducible
    sf = structure(fn)                              # must not raise
    assert sf.goto_count > 0
    assert isinstance(sf, StructuredFunction)


def test_structure_empty_function():
    fn = IRFunction(start=0xbeef, blocks={}, entry=0xbeef)
    sf = structure(fn)
    assert sf.goto_count == 0
    assert sf.body.kind == NodeKind.SEQ and sf.body.children == []


# ===========================================================================
# end-to-end smoke: lift + build_ssa + structure a real if/else (capstone-gated)
# ===========================================================================
def test_end_to_end_if_else_structures():
    pytest.importorskip("capstone")
    from aletheia.disasm import build_cfg, disassemble_linear
    from aletheia.ir import lift_function
    from aletheia.dataflow import build_ssa

    #   cmp edi, 1          83 FF 01
    #   jne  else (+.. )    75 07
    #   mov eax, 2          B8 02 00 00 00     ; then
    #   jmp  end            EB 05
    # else:
    #   mov eax, 3          B8 03 00 00 00     ; else
    # end:
    #   ret                 C3
    blob = bytes.fromhex("83FF01" "7507" "B802000000" "EB05" "B803000000" "C3")
    ins = disassemble_linear(blob, 0x1000)
    blocks = build_cfg(ins)
    by_ea = {i.address: i for i in ins}
    fn = lift_function(0x1000, blocks, by_ea)
    build_ssa(fn)

    sf = structure(fn)
    ifs = _find(sf.body, NodeKind.IF)
    assert ifs, "expected the if/else to structure into an IF node"
    iff = ifs[0]
    # both arms present (a real then and else), condition is the BR
    assert iff.then_branch is not None and iff.else_branch is not None
    assert iff.cond.op == Op.BR
    assert sf.goto_count == 0
