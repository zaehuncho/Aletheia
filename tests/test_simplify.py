"""Tests for the decompiler simplification passes (aletheia.simplify).

All IR is hand-built (stdlib only, no capstone, no real binary): the opaque /
flattening / MBA fixtures are tiny graphs whose right answers are worked out on
paper. EAs are small integers; only the shape and the op/operand structure
matter.

The simplify passes key on SSA *base* names and structural equality, so these
fixtures are written in a plain (already-single-assignment) style without running
build_ssa -- that is exactly the shape build_ssa produces for these straight-line
snippets, and it keeps the expected results legible.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag  # noqa: E402
from aletheia.dataflow import dead_code_eliminate  # noqa: E402
from aletheia.simplify import (  # noqa: E402
    SimplifyResult, simplify, opaque_predicate_pass, flattening_pass, mba_pass,
)


# ---------------------------------------------------------------------------
# small IR constructors
# ---------------------------------------------------------------------------
def _reg(name, size=64):
    return Value(VTag.REG, name=name, size=size)


def _temp(name, size=64):
    return Value(VTag.TEMP, name=name, size=size)


def _imm(v, size=64):
    return Value(VTag.IMM, imm=v, size=size)


def _flag(name):
    return Value(VTag.FLAG, name=name)


def _mem(base_name="rbx", size=64):
    return Value(VTag.MEM, size=size, base=_reg(base_name), scale=1)


def _cc(token):
    return _temp(f"cc_{token}", 8)


def _fn(blocks, entry):
    """blocks: list of (start, insns, succs)."""
    b = {start: IRBlock(start=start, insns=list(insns), succs=list(succs))
         for start, insns, succs in blocks}
    return IRFunction(start=entry, blocks=b, entry=entry)


# ===========================================================================
# Pass 1: opaque predicates
# ===========================================================================
def test_opaque_square_ge_zero_is_always_true():
    #   sq = rax * rax          IMUL
    #   cmp sq, 0
    #   br  ge  -> 100 / 200    (x*x >= 0 is always true)
    fn = _fn([(0, [
        IRInsn(0, Op.IMUL, dst=_temp("sq"), args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.CMP, dst=None, args=(_temp("sq"), _imm(0))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("ge"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    n = opaque_predicate_pass(fn)
    assert n == 1
    br = fn.blocks[0].insns[-1]
    assert br.op is Op.JMP
    assert br.args[0].tag is VTag.IMM and br.args[0].imm == 100
    assert fn.blocks[0].succs == [100]              # fallthrough edge deleted
    # idempotent: a second run finds nothing (it is now a JMP)
    assert opaque_predicate_pass(fn) == 0


def test_opaque_square_lt_zero_is_always_false():
    #   x*x < 0  -> never taken -> JMP else_ea
    fn = _fn([(0, [
        IRInsn(0, Op.IMUL, dst=_temp("sq"), args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.CMP, dst=None, args=(_temp("sq"), _imm(0))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("lt"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 1
    br = fn.blocks[0].insns[-1]
    assert br.op is Op.JMP and br.args[0].imm == 200
    assert fn.blocks[0].succs == [200]


def test_opaque_x_equals_x_is_always_true():
    #   cmp rax, rax
    #   br eq -> 100 / 200      (x == x always true)
    fn = _fn([(0, [
        IRInsn(0, Op.CMP, dst=None, args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("eq"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 1
    br = fn.blocks[0].insns[-1]
    assert br.op is Op.JMP and br.args[0].imm == 100
    assert fn.blocks[0].succs == [100]


def test_opaque_x_not_equal_x_is_always_false():
    fn = _fn([(0, [
        IRInsn(0, Op.CMP, dst=None, args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("ne"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 1
    br = fn.blocks[0].insns[-1]
    assert br.op is Op.JMP and br.args[0].imm == 200


def test_opaque_and_zero_eq_zero_is_always_true():
    #   t = rax & 0            (x & 0 == 0, nested behind arithmetic)
    #   cmp t, 0
    #   br eq -> 100 / 200
    fn = _fn([(0, [
        IRInsn(0, Op.AND, dst=_temp("t"), args=(_reg("rax"), _imm(0))),
        IRInsn(0, Op.CMP, dst=None, args=(_temp("t"), _imm(0))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("eq"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 1
    assert fn.blocks[0].insns[-1].op is Op.JMP
    assert fn.blocks[0].insns[-1].args[0].imm == 100


def test_opaque_sub_self_eq_zero_is_always_true():
    #   d = rax - rax          (x - x == 0)
    #   cmp d, 0 ; br eq
    fn = _fn([(0, [
        IRInsn(0, Op.SUB, dst=_temp("d"), args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.CMP, dst=None, args=(_temp("d"), _imm(0))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("eq"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 1
    assert fn.blocks[0].insns[-1].args[0].imm == 100


def test_not_opaque_x_greater_than_5_untouched():
    #   cmp rax, 5 ; br gt      (a real data-dependent branch: no rewrite)
    fn = _fn([(0, [
        IRInsn(0, Op.CMP, dst=None, args=(_reg("rax"), _imm(5))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("gt"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 0
    br = fn.blocks[0].insns[-1]
    assert br.op is Op.BR                             # untouched
    assert fn.blocks[0].succs == [100, 200]


def test_not_opaque_square_gt_zero_untouched():
    # x*x > 0 is NOT always true (x==0 breaks it) -- must not fire.
    fn = _fn([(0, [
        IRInsn(0, Op.IMUL, dst=_temp("sq"), args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.CMP, dst=None, args=(_temp("sq"), _imm(0))),
        IRInsn(0, Op.BR, dst=None, args=(_cc("gt"),), then_ea=100, else_ea=200),
    ], [100, 200])], entry=0)
    assert opaque_predicate_pass(fn) == 0
    assert fn.blocks[0].insns[-1].op is Op.BR


# ===========================================================================
# Pass 2: control-flow flattening reversal
# ===========================================================================
def _flattening_fixture():
    """E(0) -> D(10 dispatcher) -> {A(20), B(30), C(40)}.

    State table: 100->A, 200->B, 300->C. Chunks E/A/B each set state then jump
    back to the dispatcher (3 hops); C returns."""
    E = (0, [
        IRInsn(0, Op.STORE, dst=_mem("rbx"), args=(_reg("rax"),)),
        IRInsn(0, Op.ASSIGN, dst=_reg("state"), args=(_imm(100),)),
        IRInsn(0, Op.JMP, args=(_imm(10),)),
    ], [10])
    D = (10, [
        IRInsn(10, Op.CMP, dst=None, args=(_reg("state"), _imm(100))),
        IRInsn(10, Op.CMP, dst=None, args=(_reg("state"), _imm(200))),
        IRInsn(10, Op.CMP, dst=None, args=(_reg("state"), _imm(300))),
        IRInsn(10, Op.JMP, args=(_reg("state"),)),            # indirect dispatch
    ], [20, 30, 40])
    A = (20, [
        IRInsn(20, Op.STORE, dst=_mem("rbx"), args=(_reg("rcx"),)),
        IRInsn(20, Op.ASSIGN, dst=_reg("state"), args=(_imm(200),)),
        IRInsn(20, Op.JMP, args=(_imm(10),)),
    ], [10])
    B = (30, [
        IRInsn(30, Op.STORE, dst=_mem("rbx"), args=(_reg("rdx"),)),
        IRInsn(30, Op.ASSIGN, dst=_reg("state"), args=(_imm(300),)),
        IRInsn(30, Op.JMP, args=(_imm(10),)),
    ], [10])
    C = (40, [IRInsn(40, Op.RET, args=())], [])
    return _fn([E, D, A, B, C], entry=0)


def test_flattening_rewrites_three_hops():
    fn = _flattening_fixture()
    n = flattening_pass(fn)
    assert n == 3
    # every chunk terminator now points straight at its case target
    assert fn.blocks[0].insns[-1].op is Op.JMP and fn.blocks[0].insns[-1].args[0].imm == 20
    assert fn.blocks[20].insns[-1].args[0].imm == 30
    assert fn.blocks[30].insns[-1].args[0].imm == 40
    assert fn.blocks[0].succs == [20]
    assert fn.blocks[20].succs == [30]
    assert fn.blocks[30].succs == [40]
    # the dispatcher became unreachable and was pruned
    assert 10 not in fn.blocks
    assert set(fn.blocks) == {0, 20, 30, 40}
    # idempotent: no dispatcher left -> a second run rewrites nothing
    assert flattening_pass(fn) == 0


def test_flattening_state_writes_are_dce_removed_after():
    fn = _flattening_fixture()
    assert flattening_pass(fn) == 3
    # after the hops are direct and the dispatcher is gone, the state = K writes
    # are dead -- a follow-up DCE sweeps exactly those three.
    removed = dead_code_eliminate(fn)
    assert removed == 3
    for b in (0, 20, 30):
        assert not any(
            i.op is Op.ASSIGN and i.dst is not None and i.dst.name == "state"
            for i in fn.blocks[b].insns)
    # the real work (the STOREs) and control flow survive
    assert any(i.op is Op.STORE for i in fn.blocks[0].insns)
    assert fn.blocks[0].insns[-1].op is Op.JMP


def test_flattening_bails_on_memory_state():
    #   state kept in memory: chunk STOREs it, dispatcher LOADs then jmps.
    #   The state variable is not a register -> the pass must not fabricate.
    statep = Value(VTag.MEM, size=64, base=_reg("rbp"), disp=-8, scale=1)
    E = (0, [
        IRInsn(0, Op.STORE, dst=statep, args=(_imm(100),)),
        IRInsn(0, Op.JMP, args=(_imm(10),)),
    ], [10])
    D = (10, [
        IRInsn(10, Op.LOAD, dst=_temp("t"), args=(statep,)),
        IRInsn(10, Op.JMP, args=(_temp("t"),)),      # indirect through a LOADed value
    ], [20])
    X = (20, [IRInsn(20, Op.RET, args=())], [])
    fn = _fn([E, D, X], entry=0)

    # snapshot terminators to prove nothing moved
    before = {b: (fn.blocks[b].insns[-1].op, tuple(fn.blocks[b].succs))
              for b in fn.blocks}
    assert flattening_pass(fn) == 0
    after = {b: (fn.blocks[b].insns[-1].op, tuple(fn.blocks[b].succs))
             for b in fn.blocks}
    assert before == after
    assert set(fn.blocks) == {0, 10, 20}             # nothing pruned


# ===========================================================================
# Pass 3: MBA equivalences
# ===========================================================================
def test_mba_sum_of_xor_and_carry_collapses_to_add():
    #   t1 = rax ^ rbx
    #   t2 = rax & rbx
    #   t3 = t2 << 1            (2 * (rax & rbx))
    #   t4 = t1 + t3           == rax + rbx
    fn = _fn([(0, [
        IRInsn(0, Op.XOR, dst=_temp("t1"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.AND, dst=_temp("t2"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.SHL, dst=_temp("t3"), args=(_temp("t2"), _imm(1))),
        IRInsn(0, Op.ADD, dst=_temp("t4"), args=(_temp("t1"), _temp("t3"))),
        IRInsn(0, Op.STORE, dst=_mem("rdi"), args=(_temp("t4"),)),
    ], [])], entry=0)
    n = mba_pass(fn)
    assert n == 1
    t4 = fn.blocks[0].insns[3]
    assert t4.op is Op.ADD
    names = {a.name for a in t4.args}
    assert names == {"rax", "rbx"}
    # idempotent: the collapsed bare add matches no compound rule
    assert mba_pass(fn) == 0


def test_mba_double_via_add_form():
    #   same identity but 2*(x&y) rendered as (x&y) + (x&y)
    fn = _fn([(0, [
        IRInsn(0, Op.XOR, dst=_temp("t1"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.AND, dst=_temp("t2"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.ADD, dst=_temp("t3"), args=(_temp("t2"), _temp("t2"))),
        IRInsn(0, Op.ADD, dst=_temp("t4"), args=(_temp("t1"), _temp("t3"))),
        IRInsn(0, Op.STORE, dst=_mem("rdi"), args=(_temp("t4"),)),
    ], [])], entry=0)
    assert mba_pass(fn) == 1
    assert fn.blocks[0].insns[3].op is Op.ADD


def test_mba_xor_as_or_minus_and_collapses():
    #   t1 = rax | rbx ; t2 = rax & rbx ; t3 = t1 - t2  ==  rax ^ rbx
    fn = _fn([(0, [
        IRInsn(0, Op.OR, dst=_temp("t1"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.AND, dst=_temp("t2"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.SUB, dst=_temp("t3"), args=(_temp("t1"), _temp("t2"))),
        IRInsn(0, Op.STORE, dst=_mem("rdi"), args=(_temp("t3"),)),
    ], [])], entry=0)
    assert mba_pass(fn) == 1
    t3 = fn.blocks[0].insns[2]
    assert t3.op is Op.XOR
    assert {a.name for a in t3.args} == {"rax", "rbx"}


def test_mba_neg_from_not_plus_one():
    #   t1 = ~rax ; t2 = t1 + 1  ==  -rax
    fn = _fn([(0, [
        IRInsn(0, Op.NOT, dst=_temp("t1"), args=(_reg("rax"),)),
        IRInsn(0, Op.ADD, dst=_temp("t2"), args=(_temp("t1"), _imm(1))),
        IRInsn(0, Op.STORE, dst=_mem("rdi"), args=(_temp("t2"),)),
    ], [])], entry=0)
    assert mba_pass(fn) == 1
    t2 = fn.blocks[0].insns[1]
    assert t2.op is Op.NEG
    assert len(t2.args) == 1 and t2.args[0].name == "rax"


def test_mba_plain_add_is_not_rewritten():
    #   t = rax + rbx   (bare add of leaves -- no MBA structure)
    fn = _fn([(0, [
        IRInsn(0, Op.ADD, dst=_temp("t"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(0, Op.STORE, dst=_mem("rdi"), args=(_temp("t"),)),
    ], [])], entry=0)
    assert mba_pass(fn) == 0
    t = fn.blocks[0].insns[0]
    assert t.op is Op.ADD
    assert {a.name for a in t.args} == {"rax", "rbx"}


# ===========================================================================
# driver: fixpoint over a cascading fixture
# ===========================================================================
def test_simplify_runs_to_fixpoint_with_cascade():
    """A cascade: an opaque branch (iter 1) turns the entry block into a
    flattening chunk that the flattening pass can only undo on iter 2. Plus an
    independent MBA collapse. Asserts passes_run > 1 and every opportunity fires.

    Cx(0): sq = rax*rax ; cmp sq,0 ; state = 100 ; br ge -> D(10) / Z(50)
    D(10): dispatcher, table {100->A(20), 200->B(30)}
    A(20): an MBA add == rax+rbx ; ret
    B(30): ret ;  Z(50): ret
    """
    Cx = (0, [
        IRInsn(0, Op.IMUL, dst=_temp("sq"), args=(_reg("rax"), _reg("rax"))),
        IRInsn(0, Op.CMP, dst=None, args=(_temp("sq"), _imm(0))),
        IRInsn(0, Op.ASSIGN, dst=_reg("state"), args=(_imm(100),)),
        IRInsn(0, Op.BR, dst=None, args=(_cc("ge"),), then_ea=10, else_ea=50),
    ], [10, 50])
    D = (10, [
        IRInsn(10, Op.CMP, dst=None, args=(_reg("state"), _imm(100))),
        IRInsn(10, Op.CMP, dst=None, args=(_reg("state"), _imm(200))),
        IRInsn(10, Op.JMP, args=(_reg("state"),)),
    ], [20, 30])
    A = (20, [
        IRInsn(20, Op.XOR, dst=_temp("t1"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(20, Op.AND, dst=_temp("t2"), args=(_reg("rax"), _reg("rbx"))),
        IRInsn(20, Op.SHL, dst=_temp("t3"), args=(_temp("t2"), _imm(1))),
        IRInsn(20, Op.ADD, dst=_temp("t4"), args=(_temp("t1"), _temp("t3"))),
        IRInsn(20, Op.STORE, dst=_mem("rdi"), args=(_temp("t4"),)),
        IRInsn(20, Op.RET, args=()),
    ], [])
    B = (30, [IRInsn(30, Op.RET, args=())], [])
    Z = (50, [IRInsn(50, Op.RET, args=())], [])
    fn = _fn([Cx, D, A, B, Z], entry=0)

    res = simplify(fn)
    assert isinstance(res, SimplifyResult)
    assert res.passes_run > 1
    assert res.opaque_removed == 1
    assert res.flattening_undone == 1
    assert res.mba_rewrites == 1

    # opaque fired: the entry branch is now a plain jump
    assert fn.blocks[0].insns[-1].op is Op.JMP
    # flattening fired: entry jumps straight to case A(20); dispatcher pruned
    assert fn.blocks[0].insns[-1].args[0].imm == 20
    assert 10 not in fn.blocks
    # mba fired: the (x^y)+2*(x&y) add collapsed to a bare add of rax, rbx
    add = fn.blocks[20].insns[3]
    assert add.op is Op.ADD and {a.name for a in add.args} == {"rax", "rbx"}


def test_simplify_on_clean_ir_is_a_noop():
    #   nothing to simplify: passes_run stays 0, counts all zero
    fn = _fn([(0, [
        IRInsn(0, Op.ADD, dst=_reg("rax"), args=(_reg("rax"), _imm(1))),
        IRInsn(0, Op.RET, args=()),
    ], [])], entry=0)
    res = simplify(fn)
    assert res.passes_run == 0
    assert (res.opaque_removed, res.flattening_undone, res.mba_rewrites) == (0, 0, 0)
