"""Tests for SSA construction + data-flow passes (aletheia.dataflow).

Most tests build tiny IR *by hand* -- no capstone, no real binary -- so the
dominator/frontier/SSA/DCE/fold algorithms are pinned on graphs whose right
answers are worked out on paper (the classic diamond, straight-line blocks).
Only the end-to-end smoke lifts real bytes, and it ``importorskip``s capstone
locally so the rest of the file runs stdlib-only.

The hand-built IR uses small integer EAs as block starts; the exact values are
irrelevant, only the graph shape is.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# aletheia.ir imports capstone lazily, so these succeed without capstone; only the
# real-lift smoke test at the bottom needs it.
from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag  # noqa: E402
from aletheia import dataflow  # noqa: E402
from aletheia.dataflow import (  # noqa: E402
    MEM_SSA_OP_CODE, PHI_OP_CODE, UNTRACKED, MemSlot, build_ssa, collect_memory_slots,
    constant_fold, dead_code_eliminate, dominance_frontiers, dominators, is_phi,
    is_setslot, memory_ssa, ssa_base_name, ssa_version,
)


# ---------------------------------------------------------------------------
# small IR constructors
# ---------------------------------------------------------------------------
def _reg(name, size=64):
    return Value(VTag.REG, name=name, size=size)


def _imm(v, size=64):
    return Value(VTag.IMM, imm=v, size=size)


def _mem(base_name="rbx", size=64):
    return Value(VTag.MEM, size=size, base=_reg(base_name), scale=1)


def _fn(blocks, entry):
    """blocks: list of (start, insns, succs)."""
    b = {start: IRBlock(start=start, insns=list(insns), succs=list(succs))
         for start, insns, succs in blocks}
    return IRFunction(start=entry, blocks=b, entry=entry)


def _diamond():
    """A(0) -> B(1), C(2) -> D(3). Blocks empty unless a test fills them."""
    return _fn([
        (0, [], [1, 2]),
        (1, [], [3]),
        (2, [], [3]),
        (3, [], []),
    ], entry=0)


# ===========================================================================
# ssa_base_name / ssa_version round-trips
# ===========================================================================
def test_ssa_name_helpers_roundtrip():
    assert ssa_base_name("rax#7") == "rax"
    assert ssa_version("rax#7") == 7
    assert ssa_base_name("rcx") == "rcx"
    assert ssa_version("rcx") == -1
    # version 0 (live-in) round-trips
    assert ssa_base_name("rbx#0") == "rbx" and ssa_version("rbx#0") == 0
    # accepts a Value too, per the module's helper contract
    v = Value(VTag.REG, name="rdx#3", size=64)
    assert ssa_base_name(v) == "rdx" and ssa_version(v) == 3
    # a non-numeric '#' is not a version suffix
    assert ssa_base_name("cc_ne") == "cc_ne" and ssa_version("cc_ne") == -1


# ===========================================================================
# dominators
# ===========================================================================
def test_dominators_on_diamond():
    idom = dominators(_diamond())
    assert idom[0] == 0            # entry dominates itself
    assert idom[1] == 0           # B's idom is A
    assert idom[2] == 0           # C's idom is A
    assert idom[3] == 0           # D's idom is the common dominator A


def test_dominators_on_straight_chain():
    # 0 -> 1 -> 2 : each block's idom is its unique predecessor
    fn = _fn([(0, [], [1]), (1, [], [2]), (2, [], [])], entry=0)
    idom = dominators(fn)
    assert idom == {0: 0, 1: 0, 2: 1}


def test_dominators_with_loop_backedge():
    # 0 -> 1 -> 2 -> 1 (back-edge) ; 2 -> 3
    fn = _fn([(0, [], [1]), (1, [], [2]), (2, [], [1, 3]), (3, [], [])], entry=0)
    idom = dominators(fn)
    assert idom[0] == 0 and idom[1] == 0 and idom[2] == 1 and idom[3] == 2


# ===========================================================================
# dominance frontiers
# ===========================================================================
def test_dominance_frontiers_on_diamond():
    fn = _diamond()
    df = dominance_frontiers(fn, dominators(fn))
    assert df[1] == {3}           # DF(B) = {D}
    assert df[2] == {3}           # DF(C) = {D}
    assert df[0] == set()         # DF(A) = {}
    assert df[3] == set()         # DF(D) = {}


def test_dominance_frontiers_on_loop():
    # the loop header (1) is in its own dominance frontier via the back-edge
    fn = _fn([(0, [], [1]), (1, [], [2]), (2, [], [1, 3]), (3, [], [])], entry=0)
    df = dominance_frontiers(fn, dominators(fn))
    assert df[1] == {1}
    assert df[2] == {1}
    assert df[3] == set()


# ===========================================================================
# SSA renaming -- straight-line block
# ===========================================================================
def test_ssa_straightline_versions_point_at_dominating_def():
    #   rax = 1            ASSIGN rax#1 = 1
    #   rax = rax + 2      ADD    rax#2 = (rax#1, 2)
    #   [rbx] = rax        STORE  [rbx#0] = rax#2
    fn = _fn([(0, [
        IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(1),)),
        IRInsn(0, Op.ADD, dst=_reg("rax"), args=(_reg("rax"), _imm(2))),
        IRInsn(0, Op.STORE, dst=_mem("rbx"), args=(_reg("rax"),)),
    ], [])], entry=0)
    build_ssa(fn)
    a1, add, st = fn.blocks[0].insns

    assert a1.dst.name == "rax#1"
    # the ADD reads the dominating def rax#1 and defines a fresh rax#2
    assert add.args[0].name == "rax#1"
    assert ssa_base_name(add.args[0].name) == "rax" and ssa_version(add.args[0].name) == 1
    assert add.dst.name == "rax#2"
    # the store reads the latest def rax#2; its address reg is live-in rbx#0
    assert st.args[0].name == "rax#2"
    assert st.dst.tag is VTag.MEM and st.dst.base.name == "rbx#0"
    # no phis in a single block
    assert not any(is_phi(i) for i in fn.blocks[0].insns)


# ===========================================================================
# phi placement -- diamond
# ===========================================================================
def test_phi_placed_at_join_with_two_args():
    # rax defined in B and C, read in D -> one phi at the top of D with 2 args.
    fn = _diamond()
    fn.blocks[1].insns = [IRInsn(1, Op.ASSIGN, dst=_reg("rax"), args=(_imm(10),))]
    fn.blocks[2].insns = [IRInsn(2, Op.ASSIGN, dst=_reg("rax"), args=(_imm(20),))]
    # D reads rax (making it live-in at the join) then stores it out
    fn.blocks[3].insns = [IRInsn(3, Op.STORE, dst=_mem("rdi"), args=(_reg("rax"),))]

    build_ssa(fn)

    b_def = fn.blocks[1].insns[-1].dst        # rax#? defined in B
    c_def = fn.blocks[2].insns[-1].dst        # rax#? defined in C
    dblk = fn.blocks[3].insns

    phis = [i for i in dblk if is_phi(i)]
    assert len(phis) == 1                     # exactly one phi (pruned SSA)
    phi = phis[0]
    assert phi is dblk[0]                     # at the very top of the block
    assert ssa_base_name(phi.dst.name) == "rax"
    assert len(phi.args) == 2
    # args align to sorted predecessors [B=1, C=2]
    assert phi.args[0].name == b_def.name
    assert phi.args[1].name == c_def.name
    # the store now consumes the phi's result, not a raw B/C def
    store = [i for i in dblk if i.op is Op.STORE][0]
    assert store.args[0].name == phi.dst.name


def test_phi_pruned_when_not_live():
    # rax defined in B and C but never read at the join -> no phi (pruned SSA).
    fn = _diamond()
    fn.blocks[1].insns = [IRInsn(1, Op.ASSIGN, dst=_reg("rax"), args=(_imm(10),))]
    fn.blocks[2].insns = [IRInsn(2, Op.ASSIGN, dst=_reg("rax"), args=(_imm(20),))]
    fn.blocks[3].insns = []                   # D reads nothing
    build_ssa(fn)
    assert not any(is_phi(i) for i in fn.blocks[3].insns)


# ===========================================================================
# dead-code elimination
# ===========================================================================
def test_dce_removes_dead_assign():
    #   rax = 1
    #   rax = 2
    #   [rbx] = rax     -> the first assign is dead after SSA
    fn = _fn([(0, [
        IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(1),)),
        IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(2),)),
        IRInsn(0, Op.STORE, dst=_mem("rbx"), args=(_reg("rax"),)),
    ], [])], entry=0)
    build_ssa(fn)
    removed = dead_code_eliminate(fn)
    assert removed == 1
    insns = fn.blocks[0].insns
    assert len(insns) == 2
    # the surviving assign is the one feeding the store (value 2)
    assign = [i for i in insns if i.op is Op.ASSIGN][0]
    assert assign.args[0].imm == 2
    assert not any(i.args and i.args[0].imm == 1 for i in insns if i.op is Op.ASSIGN)


def test_dce_keeps_def_used_by_store():
    #   rax = 5
    #   [rbx] = rax     -> the assign is live (feeds the store)
    fn = _fn([(0, [
        IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(5),)),
        IRInsn(0, Op.STORE, dst=_mem("rbx"), args=(_reg("rax"),)),
    ], [])], entry=0)
    build_ssa(fn)
    removed = dead_code_eliminate(fn)
    assert removed == 0
    assert len(fn.blocks[0].insns) == 2
    assert any(i.op is Op.ASSIGN and i.args[0].imm == 5 for i in fn.blocks[0].insns)


def test_dce_drops_unused_load_chain():
    #   t = [rbx]       (dead: never used)
    #   ret             (root)
    fn = _fn([(0, [
        IRInsn(0, Op.LOAD, dst=Value(VTag.TEMP, name="t0", size=64), args=(_mem("rbx"),)),
        IRInsn(0, Op.RET, args=()),
    ], [])], entry=0)
    build_ssa(fn)
    removed = dead_code_eliminate(fn)
    assert removed == 1
    assert [i.op for i in fn.blocks[0].insns] == [Op.RET]


# ===========================================================================
# constant folding + copy propagation
# ===========================================================================
def _one_block(insns):
    return _fn([(0, list(insns), [])], entry=0)


def test_constant_fold_add():
    #   t = ADD 3, 4    ->    t = ASSIGN 7
    dst = Value(VTag.TEMP, name="t1", size=32)
    fn = _one_block([IRInsn(0, Op.ADD, dst=dst, args=(_imm(3, 32), _imm(4, 32)))])
    n = constant_fold(fn)
    assert n == 1
    insn = fn.blocks[0].insns[0]
    assert insn.op is Op.ASSIGN
    assert insn.args[0].tag is VTag.IMM and insn.args[0].imm == 7


def test_constant_fold_add_wraps_at_width_32():
    #   ADD 0xFFFFFFFF, 1 at width 32  ->  ASSIGN 0
    dst = Value(VTag.TEMP, name="t1", size=32)
    fn = _one_block([IRInsn(0, Op.ADD, dst=dst,
                            args=(_imm(0xFFFFFFFF, 32), _imm(1, 32)))])
    assert constant_fold(fn) == 1
    insn = fn.blocks[0].insns[0]
    assert insn.op is Op.ASSIGN and insn.args[0].imm == 0


def test_constant_fold_and_or_xor_shl_shr_neg_not_trunc_zxt():
    def fold_one(op, args, size=32):
        dst = Value(VTag.TEMP, name="t", size=size)
        fn = _one_block([IRInsn(0, op, dst=dst, args=tuple(args))])
        constant_fold(fn)
        i = fn.blocks[0].insns[0]
        assert i.op is Op.ASSIGN, f"{op} did not fold"
        return i.args[0].imm

    assert fold_one(Op.AND, (_imm(0b1100, 32), _imm(0b1010, 32))) == 0b1000
    assert fold_one(Op.OR, (_imm(0b1100, 32), _imm(0b1010, 32))) == 0b1110
    assert fold_one(Op.XOR, (_imm(0b1100, 32), _imm(0b1010, 32))) == 0b0110
    assert fold_one(Op.SUB, (_imm(10, 32), _imm(3, 32))) == 7
    assert fold_one(Op.SHL, (_imm(1, 32), _imm(4, 32))) == 16
    assert fold_one(Op.SHR, (_imm(0x80, 32), _imm(3, 32))) == 0x10
    assert fold_one(Op.NOT, (_imm(0, 32),)) == 0xFFFFFFFF
    assert fold_one(Op.NEG, (_imm(1, 32),)) == 0xFFFFFFFF
    assert fold_one(Op.TRUNC, (_imm(0x1_2345, 16),), size=16) == 0x2345
    assert fold_one(Op.ZXT, (_imm(0xFF, 8),), size=64) == 0xFF


def test_copy_propagation_then_fold_to_fixpoint():
    #   t1 = IMM 5
    #   t2 = ADD t1, t1     ->  after fold+propagate: t1 = IMM 5 ; t2 = IMM 10
    t1 = Value(VTag.TEMP, name="t1", size=32)
    t2 = Value(VTag.TEMP, name="t2", size=32)
    fn = _one_block([
        IRInsn(0, Op.ASSIGN, dst=t1, args=(_imm(5, 32),)),
        IRInsn(0, Op.ADD, dst=t2, args=(t1, t1)),
    ])
    n = constant_fold(fn)
    assert n >= 1
    a1, a2 = fn.blocks[0].insns
    # the source constant assign is left in place (DCE's job to remove, not fold's)
    assert a1.op is Op.ASSIGN and a1.args[0].imm == 5
    # the ADD is fully folded through the propagated copies
    assert a2.op is Op.ASSIGN and a2.args[0].tag is VTag.IMM and a2.args[0].imm == 10


def test_fold_skips_memory_and_reg_operands():
    #   ADD [rbx], 4   must NOT fold (a MEM operand is not a constant)
    dst = Value(VTag.TEMP, name="t", size=64)
    fn = _one_block([IRInsn(0, Op.ADD, dst=dst, args=(_mem("rbx"), _imm(4)))])
    assert constant_fold(fn) == 0
    assert fn.blocks[0].insns[0].op is Op.ADD


def test_cross_block_copy_propagation_via_ssa():
    #   B: rax = 7          (0 -> 1)
    #   C: [rdi] = rax + 0  reads rax across the edge; SSA makes propagation sound
    fn = _fn([
        (0, [IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(7),))], [1]),
        (1, [IRInsn(1, Op.ADD, dst=_reg("rax"), args=(_reg("rax"), _imm(0)))], []),
    ], entry=0)
    build_ssa(fn)
    constant_fold(fn)
    # the ADD in block 1 folded to ASSIGN 7 using the constant defined in block 0
    add_blk = fn.blocks[1].insns
    folded = [i for i in add_blk if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "rax"]
    assert folded and folded[0].args[0].tag is VTag.IMM and folded[0].args[0].imm == 7


# ===========================================================================
# phi opcode representation
# ===========================================================================
def test_phi_opcode_is_int_sentinel_not_enum_member():
    assert PHI_OP_CODE == 100
    assert PHI_OP_CODE not in [m.value for m in Op]      # not a real Op
    phi = IRInsn(0, PHI_OP_CODE, dst=_reg("rax"), args=())
    assert is_phi(phi)
    # a real op is never mistaken for a phi
    assert not is_phi(IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(1),)))


# ===========================================================================
# end-to-end smoke over a real lifted block (capstone-gated)
# ===========================================================================
def test_end_to_end_lifted_block_folds():
    pytest.importorskip("capstone")
    from aletheia.disasm import build_cfg, disassemble_linear
    from aletheia.ir import lift_block

    #   mov eax, 5     B8 05 00 00 00
    #   add eax, 3     83 C0 03
    blob = bytes.fromhex("B805000000" "83C003")
    ins = disassemble_linear(blob, 0x1000)
    blocks = build_cfg(ins)
    assert len(blocks) == 1
    irb = lift_block(blocks[0], ins)
    fn = IRFunction(start=0x1000, blocks={0x1000: irb}, entry=0x1000)

    build_ssa(fn)
    constant_fold(fn)

    # eax canonicalises to rax; the add should fold to ASSIGN rax#? = IMM 8
    folded = [i for i in fn.blocks[0x1000].insns
              if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "rax"
              and i.args and i.args[0].tag is VTag.IMM and i.args[0].imm == 8]
    assert folded, "expected the lifted add to fold to IMM 8"


def test_build_ssa_on_empty_function_is_noop():
    fn = IRFunction(start=0xdead, blocks={}, entry=0xdead)
    assert build_ssa(fn) is fn
    assert dominators(fn) == {}


# ===========================================================================
# memory SSA (stack-slot precise) -- collect_memory_slots + memory_ssa
# ===========================================================================
def _smem(base="rsp", disp=-8, size=64):
    """A MEM operand ``[base + disp]`` (no index)."""
    return Value(VTag.MEM, size=size, base=_reg(base), scale=1, disp=disp)


def _store(base, disp, val, size=64):
    return IRInsn(0, Op.STORE, dst=_smem(base, disp, size), args=(val,))


def _load(dst_name, base, disp, size=64):
    return IRInsn(0, Op.LOAD, dst=_reg(dst_name), args=(_smem(base, disp, size),))


def test_memory_ssa_stack_slot_round_trip():
    # store rax at [rsp-8]; load rbx from [rsp-8]  -> the load is substituted by rax.
    fn = _fn([(0, [
        _store("rsp", -8, _reg("rax")),
        _load("rbx", "rsp", -8),
    ], [])], entry=0)
    build_ssa(fn)
    n = memory_ssa(fn)
    assert n == 1
    insns = fn.blocks[0].insns
    # the LOAD is gone; it is now ASSIGN rbx#? = rax#? (no MEM operand left)
    assert not any(i.op is Op.LOAD for i in insns)
    asg = [i for i in insns if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "rbx"][0]
    assert asg.args[0].tag is VTag.REG and ssa_base_name(asg.args[0]) == "rax"
    # a virtual SETSLOT marker was injected for the store's slot def
    setslots = [i for i in insns if is_setslot(i)]
    assert len(setslots) == 1
    assert setslots[0].op == MEM_SSA_OP_CODE
    assert ssa_base_name(setslots[0].dst) == "slot_rsp_-8_64"
    # the real STORE is retained (its memory side effect is real)
    assert any(i.op is Op.STORE for i in insns)


def test_memory_ssa_idempotent():
    fn = _fn([(0, [_store("rsp", -8, _reg("rax")), _load("rbx", "rsp", -8)], [])],
             entry=0)
    build_ssa(fn)
    assert memory_ssa(fn) == 1
    # second run: the load is already substituted and the SETSLOT guard trips
    assert memory_ssa(fn) == 0


def test_memory_ssa_cross_block_store_to_load():
    # A stores rax at [rsp-8], jumps to B; B loads [rsp-8] into rbx.
    fn = _fn([
        (0, [_store("rsp", -8, _reg("rax"))], [1]),
        (1, [_load("rbx", "rsp", -8)], []),
    ], entry=0)
    build_ssa(fn)
    assert memory_ssa(fn) == 1
    b1 = fn.blocks[1].insns
    assert not any(i.op is Op.LOAD for i in b1)
    asg = [i for i in b1 if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "rbx"][0]
    assert ssa_base_name(asg.args[0]) == "rax"


def test_memory_ssa_two_stores_at_merge_make_a_phi():
    # B stores 10, C stores 20, D (merge) loads -> D reads a phi over {10, 20}.
    fn = _diamond()
    fn.blocks[1].insns = [_store("rsp", -8, _imm(10))]
    fn.blocks[2].insns = [_store("rsp", -8, _imm(20))]
    fn.blocks[3].insns = [_load("rbx", "rsp", -8)]
    build_ssa(fn)
    assert memory_ssa(fn) == 1
    d = fn.blocks[3].insns
    phis = [i for i in d if is_phi(i)]
    assert len(phis) == 1
    phi = phis[0]
    assert phi is d[0]                                  # at the very top of D
    assert ssa_base_name(phi.dst) == "slot_rsp_-8_64"
    assert len(phi.args) == 2
    # args align to sorted predecessors [B=1, C=2]: the stored values 10 then 20
    assert phi.args[0].tag is VTag.IMM and phi.args[0].imm == 10
    assert phi.args[1].tag is VTag.IMM and phi.args[1].imm == 20
    # the load now consumes the phi's slot result
    asg = [i for i in d if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "rbx"][0]
    assert asg.args[0].name == phi.dst.name


def test_memory_ssa_killing_store_uses_latest_value():
    # store 10 at [rsp-8]; store 20 at [rsp-8]; load -> load reads 20, not 10.
    fn = _fn([(0, [
        _store("rsp", -8, _imm(10)),
        _store("rsp", -8, _imm(20)),
        _load("rbx", "rsp", -8),
    ], [])], entry=0)
    build_ssa(fn)
    assert memory_ssa(fn) == 1
    asg = [i for i in fn.blocks[0].insns
           if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "rbx"][0]
    assert asg.args[0].tag is VTag.IMM and asg.args[0].imm == 20


def test_memory_ssa_heap_slot_not_substituted():
    # store rax at [rcx+0]; load rbx from [rcx+0] -> NOT connected (rcx isn't a
    # tracked frame base); count 0 and the load survives.
    fn = _fn([(0, [
        _store("rcx", 0, _reg("rax")),
        _load("rbx", "rcx", 0),
    ], [])], entry=0)
    build_ssa(fn)
    assert memory_ssa(fn) == 0
    assert any(i.op is Op.LOAD for i in fn.blocks[0].insns)
    slots = collect_memory_slots(fn)
    assert slots.get("slot_rcx_0_64") is UNTRACKED


def test_memory_ssa_framing_sanity_bails_rsp_keeps_rbp():
    # rsp is reassigned mid-body (mov rsp, rdx) -> rsp bails, but rbp stays intact.
    fn = _fn([(0, [
        _store("rsp", -8, _reg("rax")),
        _load("rcx", "rsp", -8),
        IRInsn(0, Op.ASSIGN, dst=_reg("rsp"), args=(_reg("rdx"),)),  # reassign rsp
        _store("rsp", -8, _reg("rax")),
        _load("rsi", "rsp", -8),
        _store("rbp", -16, _reg("r8")),                             # rbp untouched
        _load("r9", "rbp", -16),
    ], [])], entry=0)
    build_ssa(fn)
    # only the rbp round-trip is connected; both rsp loads are left alone.
    assert memory_ssa(fn) == 1
    insns = fn.blocks[0].insns
    assert len([i for i in insns if i.op is Op.LOAD]) == 2          # both rsp loads
    asg = [i for i in insns if i.op is Op.ASSIGN and ssa_base_name(i.dst) == "r9"][0]
    assert ssa_base_name(asg.args[0]) == "r8"
    slots = collect_memory_slots(fn)
    assert slots.get("slot_rbp_-16_64") == MemSlot("rbp", -16, 64)
    assert slots.get("slot_rsp_-8_64") is UNTRACKED


def test_collect_memory_slots_shape():
    # two tracked stack slots + one heap operand -> exactly the expected keys.
    fn = _fn([(0, [
        _store("rsp", -8, _reg("rax")),
        _load("rbx", "rbp", -16, size=32),
        _store("rcx", 0, _reg("rax")),      # heap
    ], [])], entry=0)
    build_ssa(fn)
    slots = collect_memory_slots(fn)
    assert slots["slot_rsp_-8_64"] == MemSlot("rsp", -8, 64)
    assert slots["slot_rbp_-16_32"] == MemSlot("rbp", -16, 32)
    assert slots["slot_rcx_0_64"] is UNTRACKED
    assert set(slots) == {"slot_rsp_-8_64", "slot_rbp_-16_32", "slot_rcx_0_64"}
