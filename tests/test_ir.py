"""Tests for the x64 -> IR lifter (aletheia.ir).

Correctness rides on tiny, hand-assembled byte blobs -- no live process, no real
binary needed. Each blob is decoded by the real disassembler
(``disassemble_linear``) and then lifted; the tests pin the *shape* of the emitted
IR: which ops appear, in what order, and the tag/name/size of the Values they
carry. A best-effort ``lift_function`` smoke over a system exe is skipped (never
failed) if the environment can't oblige.

All require capstone (``importorskip``); the module itself imports without it.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("capstone")

from aletheia.disasm import (  # noqa: E402
    build_cfg, disasm_pe, disassemble_linear,
)
from aletheia.ir import (  # noqa: E402
    IRBlock, IRFunction, Op, VTag, lift_block, lift_function, lift_instruction,
)

BASE = 0x1000


def _lift_one(hexs, base=BASE, arch_bits=64):
    """Decode a single-instruction blob and return its list of IRInsn."""
    ins = disassemble_linear(bytes.fromhex(hexs), base)
    assert len(ins) == 1, f"expected one instruction, decoded {len(ins)}"
    return lift_instruction(ins[0], arch_bits)


def _flag_dsts(ir):
    return {o.dst.name for o in ir if o.op is Op.SETFLAG}


# ===========================================================================
# data movement
# ===========================================================================
def test_mov_reg_reg_is_single_assign():
    # 48 89 c3   mov rbx, rax
    ir = _lift_one("4889c3")
    assert len(ir) == 1
    op = ir[0]
    assert op.op is Op.ASSIGN
    assert op.dst.tag is VTag.REG and op.dst.name == "rbx" and op.dst.size == 64
    assert len(op.args) == 1
    src = op.args[0]
    assert src.tag is VTag.REG and src.name == "rax" and src.size == 64


def test_subregister_write_canonicalises_to_parent_gpr():
    # b0 01   mov al, 1  -> write the low byte of RAX (name rax, size 8)
    ir = _lift_one("b001")
    assert len(ir) == 1
    op = ir[0]
    assert op.op is Op.ASSIGN
    assert op.dst.name == "rax" and op.dst.size == 8
    assert op.args[0].tag is VTag.IMM and op.args[0].imm == 1


def test_mov_load_and_store_are_explicit():
    # 48 8b 03   mov rax, [rbx]   -> LOAD
    ld = _lift_one("488b03")
    assert len(ld) == 1 and ld[0].op is Op.LOAD
    assert ld[0].dst.name == "rax"
    assert ld[0].args[0].tag is VTag.MEM and ld[0].args[0].base.name == "rbx"
    # 48 89 03   mov [rbx], rax   -> STORE
    st = _lift_one("488903")
    assert len(st) == 1 and st[0].op is Op.STORE
    assert st[0].dst.tag is VTag.MEM and st[0].dst.base.name == "rbx"
    assert st[0].args[0].name == "rax"


def test_movzx_movsx_use_zxt_sxt():
    # 48 0f b6 c3   movzx rax, bl
    zx = _lift_one("480fb6c3")
    assert len(zx) == 1 and zx[0].op is Op.ZXT
    assert zx[0].dst.name == "rax" and zx[0].dst.size == 64
    assert zx[0].args[0].name == "rbx" and zx[0].args[0].size == 8
    # 48 0f be c3   movsx rax, bl
    sx = _lift_one("480fbec3")
    assert len(sx) == 1 and sx[0].op is Op.SXT
    # 48 63 c3      movsxd rax, ebx
    sxd = _lift_one("4863c3")
    assert len(sxd) == 1 and sxd[0].op is Op.SXT
    assert sxd[0].args[0].name == "rbx" and sxd[0].args[0].size == 32


def test_lea_is_address_compute_not_load():
    # 48 8d 04 33   lea rax, [rbx+rsi]
    ir = _lift_one("488d0433")
    assert len(ir) == 1
    op = ir[0]
    assert op.op is Op.ASSIGN                    # NOT a LOAD
    assert not any(o.op is Op.LOAD for o in ir)
    src = op.args[0]
    assert src.tag is VTag.MEM                   # the address expression itself
    assert src.base.name == "rbx" and src.index.name == "rsi"


def test_push_is_sub_rsp_then_store():
    # 50   push rax
    ir = _lift_one("50")
    assert [o.op for o in ir] == [Op.SUB, Op.STORE]
    sub, store = ir
    assert sub.dst.name == "rsp"
    assert sub.args[0].name == "rsp" and sub.args[1].tag is VTag.IMM and sub.args[1].imm == 8
    # push has NO flag effect -> the rsp arithmetic carries no SETFLAG
    assert not any(o.op is Op.SETFLAG for o in ir)
    assert store.dst.tag is VTag.MEM and store.dst.base.name == "rsp"
    assert store.args[0].name == "rax"


def test_pop_is_load_then_add_rsp():
    # 58   pop rax
    ir = _lift_one("58")
    assert [o.op for o in ir] == [Op.LOAD, Op.ADD]
    load, add = ir
    assert load.dst.name == "rax"
    assert load.args[0].tag is VTag.MEM and load.args[0].base.name == "rsp"
    assert add.dst.name == "rsp" and add.args[1].imm == 8
    assert not any(o.op is Op.SETFLAG for o in ir)


def test_xchg_reg_reg_swaps_via_temp():
    # 48 87 c3   xchg rbx, rax
    ir = _lift_one("4887c3")
    # tmp = rbx ; rbx = rax ; rax = tmp
    assert [o.op for o in ir] == [Op.ASSIGN, Op.ASSIGN, Op.ASSIGN]
    t = ir[0].dst
    assert t.tag is VTag.TEMP
    assert ir[0].args[0].name == "rbx"
    assert ir[1].dst.name == "rbx" and ir[1].args[0].name == "rax"
    assert ir[2].dst.name == "rax" and ir[2].args[0] == t


# ===========================================================================
# arithmetic + flag effects
# ===========================================================================
def test_add_emits_op_then_flag_effects():
    # 48 01 d8   add rax, rbx
    ir = _lift_one("4801d8")
    assert ir[0].op is Op.ADD
    assert ir[0].dst.name == "rax"
    assert [a.name for a in ir[0].args] == ["rax", "rbx"]   # read of rax is explicit
    # flag writes are explicit and cover at least ZF/SF/CF/OF
    assert {"ZF", "SF", "CF", "OF"} <= _flag_dsts(ir)
    # every SETFLAG dst is a FLAG value
    assert all(o.dst.tag is VTag.FLAG for o in ir if o.op is Op.SETFLAG)


def test_adc_reads_carry_in_explicitly():
    # 48 11 d8   adc rax, rbx  -> ADD with an explicit CF read appended
    ir = _lift_one("4811d8")
    assert ir[0].op is Op.ADD
    assert any(a.tag is VTag.FLAG and a.name == "CF" for a in ir[0].args)
    assert {"ZF", "SF", "CF", "OF"} <= _flag_dsts(ir)


def test_inc_sets_flags_but_not_cf():
    # 48 ff c0   inc rax
    ir = _lift_one("48ffc0")
    assert ir[0].op is Op.ADD and ir[0].args[1].imm == 1
    fl = _flag_dsts(ir)
    assert {"OF", "SF", "ZF", "PF"} <= fl
    assert "CF" not in fl                         # inc/dec leave CF unaffected


def test_and_is_logic_flags():
    # 48 21 d8   and rax, rbx
    ir = _lift_one("4821d8")
    assert ir[0].op is Op.AND
    assert {"ZF", "SF", "CF", "OF"} <= _flag_dsts(ir)


def test_neg_is_unary_with_arith_flags():
    # 48 f7 d8   neg rax
    ir = _lift_one("48f7d8")
    assert ir[0].op is Op.NEG and ir[0].args[0].name == "rax"
    assert {"ZF", "SF", "CF", "OF"} <= _flag_dsts(ir)


def test_not_touches_no_flags():
    # 48 f7 d0   not rax
    ir = _lift_one("48f7d0")
    assert ir[0].op is Op.NOT
    assert not any(o.op is Op.SETFLAG for o in ir)


def test_shl_by_imm_sets_shift_flags():
    # 48 c1 e0 04   shl rax, 4
    ir = _lift_one("48c1e004")
    assert ir[0].op is Op.SHL and ir[0].args[1].imm == 4
    assert {"CF", "OF", "SF", "ZF"} <= _flag_dsts(ir)


def test_imul_two_operand_low_half_only():
    # 48 0f af c3   imul rax, rbx
    ir = _lift_one("480fafc3")
    muls = [o for o in ir if o.op is Op.IMUL]
    assert len(muls) == 1 and muls[0].dst.name == "rax"
    assert {"CF", "OF"} <= _flag_dsts(ir)


def test_imul_one_operand_writes_rax_and_rdx():
    # 48 f7 eb   imul rbx   -> rdx:rax = rax * rbx
    ir = _lift_one("48f7eb")
    dsts = [o.dst.name for o in ir if o.op is Op.IMUL]
    assert dsts == ["rax", "rdx"]


def test_div_writes_quotient_and_remainder_no_flags():
    # 48 f7 f3   div rbx   -> rax=quot, rdx=rem, flags undefined (none emitted)
    ir = _lift_one("48f7f3")
    dsts = [o.dst.name for o in ir if o.op is Op.DIV]
    assert dsts == ["rax", "rdx"]
    assert not any(o.op is Op.SETFLAG for o in ir)


# ===========================================================================
# cmp / test / bt (flag-only)
# ===========================================================================
def test_cmp_is_flags_only_no_dst():
    # 48 39 d8   cmp rax, rbx
    ir = _lift_one("4839d8")
    cmp = ir[0]
    assert cmp.op is Op.CMP and cmp.dst is None
    assert [a.name for a in cmp.args] == ["rax", "rbx"]
    assert {"ZF", "SF", "CF", "OF"} <= _flag_dsts(ir)


def test_test_is_flags_only():
    # 48 85 c3   test rax, rbx
    ir = _lift_one("4885c3")
    assert ir[0].op is Op.TEST and ir[0].dst is None
    assert {"ZF", "SF", "CF", "OF"} <= _flag_dsts(ir)


def test_bt_sets_only_cf():
    # 48 0f a3 d8   bt rax, rbx
    ir = _lift_one("480fa3d8")
    assert _flag_dsts(ir) == {"CF"}


# ===========================================================================
# control flow
# ===========================================================================
def test_jcc_becomes_br_with_flag_condition():
    # 74 05   je +5   (short, at BASE: end=BASE+2, target=BASE+7)
    ins = disassemble_linear(bytes.fromhex("7405"), BASE)[0]
    ir = lift_instruction(ins)
    assert len(ir) == 1
    br = ir[0]
    assert br.op is Op.BR and br.dst is None
    # ZF-based condition, taken target and fallthrough recorded
    assert any(a.tag is VTag.FLAG and a.name == "ZF" for a in br.args)
    assert br.then_ea == ins.target == BASE + 7
    assert br.else_ea == ins.end == BASE + 2


def test_jne_condition_reads_zf():
    # 75 05   jne +5
    br = _lift_one("7505")[0]
    assert br.op is Op.BR
    assert any(a.tag is VTag.FLAG and a.name == "ZF" for a in br.args)
    assert br.args[0].tag is VTag.TEMP and br.args[0].name == "cc_ne"


def test_jg_condition_reads_zf_sf_of():
    # 7f 05   jg +5
    br = _lift_one("7f05")[0]
    flags = {a.name for a in br.args if a.tag is VTag.FLAG}
    assert flags == {"ZF", "SF", "OF"}


def test_jrcxz_compares_rcx_to_zero():
    # e3 05   jrcxz +5
    ins = disassemble_linear(bytes.fromhex("e305"), BASE)[0]
    br = lift_instruction(ins)[0]
    assert br.op is Op.BR
    assert any(a.tag is VTag.REG and a.name == "rcx" for a in br.args)
    assert br.then_ea == ins.target


def test_loop_decrements_rcx_then_branches():
    # e2 fe   loop -2
    ir = _lift_one("e2fe")
    assert ir[0].op is Op.SUB and ir[0].dst.name == "rcx"
    assert not any(o.op is Op.SETFLAG for o in ir)     # loop leaves flags alone
    assert ir[-1].op is Op.BR


def test_call_direct_has_imm_target():
    # e8 00 00 00 00   call rel32(0)  -> target = BASE+5
    ins = disassemble_linear(bytes.fromhex("e800000000"), BASE)[0]
    ir = lift_instruction(ins)
    assert len(ir) == 1 and ir[0].op is Op.CALL
    assert ir[0].args[0].tag is VTag.IMM and ir[0].args[0].imm == ins.target == BASE + 5


def test_call_indirect_has_reg_target():
    # ff d0   call rax
    ir = _lift_one("ffd0")
    assert len(ir) == 1 and ir[0].op is Op.CALL
    assert ir[0].args[0].tag is VTag.REG and ir[0].args[0].name == "rax"


def test_jmp_direct_and_indirect():
    # e9 00 00 00 00   jmp rel32
    jd = _lift_one("e900000000")[0]
    assert jd.op is Op.JMP and jd.args[0].tag is VTag.IMM
    # ff e0   jmp rax
    ji = _lift_one("ffe0")[0]
    assert ji.op is Op.JMP and ji.args[0].tag is VTag.REG and ji.args[0].name == "rax"


def test_ret_and_ret_imm():
    # c3   ret
    r = _lift_one("c3")[0]
    assert r.op is Op.RET and r.args == ()
    # c2 08 00   ret 8
    ri = _lift_one("c20800")[0]
    assert ri.op is Op.RET and ri.args[0].tag is VTag.IMM and ri.args[0].imm == 8


# ===========================================================================
# privileged / UNDEF safety
# ===========================================================================
def test_hlt_syscall_int():
    assert _lift_one("f4")[0].op is Op.HLT
    assert _lift_one("0f05")[0].op is Op.SYSCALL
    # cd 80   int 0x80
    i = _lift_one("cd80")[0]
    assert i.op is Op.INT and i.args[0].imm == 0x80
    # cc   int3
    assert _lift_one("cc")[0].op is Op.INT and _lift_one("cc")[0].args[0].imm == 3


def test_nop_is_nop():
    assert _lift_one("90")[0].op is Op.NOP


def test_sse_is_undef_with_text():
    # 0f 28 c1   movaps xmm0, xmm1  -> UNDEF carrying the mnemonic+operands
    u = _lift_one("0f28c1")[0]
    assert u.op is Op.UNDEF
    assert u.text == "movaps xmm0, xmm1"


def test_string_op_is_undef_documented_gap():
    # a4   movsb  -> UNDEF (documented string-op gap)
    u = _lift_one("a4")[0]
    assert u.op is Op.UNDEF
    assert "movsb" in u.text


# ===========================================================================
# block + function lifting
# ===========================================================================
def test_lift_block_end_to_end():
    # A straight-line block ending in a jmp:
    #   mov rbx, rax      48 89 c3
    #   add rax, rbx      48 01 d8
    #   xor ecx, ecx      31 c9
    #   jmp +0            eb 00
    blob = bytes.fromhex("4889c3" "4801d8" "31c9" "eb00")
    ins = disassemble_linear(blob, 0x2000)
    blocks = build_cfg(ins)
    assert len(blocks) == 1
    irb = lift_block(blocks[0], ins)
    assert isinstance(irb, IRBlock) and irb.start == 0x2000
    ops = [o.op for o in irb.insns]
    # first op of each source instruction, in order
    assert ops[0] is Op.ASSIGN                    # mov
    assert Op.ADD in ops and Op.XOR in ops        # add, xor
    assert ops[-1] is Op.JMP                       # terminator
    # flag effects from add + xor are present
    assert any(o.op is Op.SETFLAG for o in irb.insns)
    # every op is tagged with a source EA inside the block
    assert all(0x2000 <= o.ea < 0x2000 + len(blob) for o in irb.insns)


def test_lift_function_walks_cfg():
    #   test eax, eax     85 c0        @0x3000
    #   je   +2           74 02        @0x3002 -> taken 0x3006, fallthrough 0x3004
    #   inc  eax          ff c0        @0x3004
    #   ret               c3           @0x3006
    blob = bytes.fromhex("85c0" "7402" "ffc0" "c3")
    ins = disassemble_linear(blob, 0x3000)
    blocks = build_cfg(ins)
    by_ea = {i.address: i for i in ins}
    fn = lift_function(0x3000, blocks, by_ea)
    assert isinstance(fn, IRFunction)
    assert fn.entry == fn.start == 0x3000
    # all three blocks reachable from the entry are lifted
    assert set(fn.blocks) == {0x3000, 0x3004, 0x3006}
    # entry block ends in a BR into the two successors
    entry = fn.blocks[0x3000]
    assert entry.insns[-1].op is Op.BR
    assert set(entry.succs) == {0x3006, 0x3004}
    # the ret block terminates
    assert fn.blocks[0x3006].insns[-1].op is Op.RET
    assert fn.blocks[0x3006].succs == []


def test_lift_function_unknown_start_is_empty():
    fn = lift_function(0xdead, [], {})
    assert isinstance(fn, IRFunction) and fn.blocks == {}


# ===========================================================================
# real-EXE smoke (best-effort; skip if the environment can't oblige)
# ===========================================================================
def test_lift_real_pe_smoke():
    candidates = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "cmd.exe"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "notepad.exe"),
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        pytest.skip("no system exe available for the smoke test")

    from aletheia import pe
    info = pe.parse_bytes(open(path, "rb").read())
    if not info.ok or info.arch != "x64":
        pytest.skip(f"{path} is not a clean x64 PE for this smoke test")
    try:
        res = disasm_pe(path)
    except Exception as exc:                       # noqa: BLE001
        pytest.skip(f"disasm_pe smoke could not run cleanly: {exc}")

    # lift every reachable instruction: it must never raise, and yield >=1 op each
    total = 0
    for ins in res.instructions.values():
        ir = lift_instruction(ins)
        assert ir, f"empty lift for {ins}"
        total += len(ir)
    assert total >= len(res.instructions)

    # lift a function via the CFG walk. NOTE: the PE entry is not guaranteed to be
    # a CFG leader (nothing branches to it, so build_cfg may fold it mid-block); a
    # non-leader start correctly yields an empty IRFunction. Exercise the walk from
    # a real block leader that actually has successors, so >1 block is visited.
    multi = [b for b in res.blocks if b.successors]
    start = (multi[0] if multi else res.blocks[0]).start
    fn = lift_function(start, res.blocks, res.instructions)
    assert fn.entry == start
    assert start in fn.blocks and fn.blocks
    # a non-leader address lifts to an empty function rather than raising
    assert lift_function(res.entry - 0x1000000, res.blocks, res.instructions).blocks == {}
