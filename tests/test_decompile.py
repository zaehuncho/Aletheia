"""Tests for basic type recovery + the C-like pseudocode emitter
(aletheia.decompile).

Like the data-flow / structuring tests, almost everything is built *by hand* --
tiny IR / structured trees whose emitted shape is known on paper -- so the emitter
and type recovery are pinned without capstone. Only the end-to-end smoke lifts real
bytes and ``importorskip``s capstone locally.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag  # noqa: E402
from aletheia.structuring import (  # noqa: E402
    NodeKind, SNode, StructuredFunction, structure,
)
from aletheia.decompile import (  # noqa: E402
    TypeGuess, DecompiledFunction, recover_types, emit, decompile_function,
)


# ---------------------------------------------------------------------------
# IR constructors
# ---------------------------------------------------------------------------
def _reg(name, size=64):
    return Value(VTag.REG, name=name, size=size)


def _imm(v, size=8):
    return Value(VTag.IMM, imm=v, size=size)


def _temp(name, size=32):
    return Value(VTag.TEMP, name=name, size=size)


def _mem(base=None, index=None, scale=1, disp=0, size=32, seg=""):
    b = _reg(base) if base else None
    i = _reg(index) if index else None
    return Value(VTag.MEM, size=size, base=b, index=i, scale=scale, disp=disp, seg=seg)


def _br(ea, then_ea, else_ea, token="ne", flags=("ZF",)):
    cond = Value(VTag.TEMP, name=f"cc_{token}", size=8)
    reads = tuple(_reg(f, 8) for f in flags)
    return IRInsn(ea, Op.BR, dst=None, args=(cond,) + reads,
                  then_ea=then_ea, else_ea=else_ea)


def _cmp(ea, a, b):
    return IRInsn(ea, Op.CMP, dst=None, args=(a, b))


def _jmp(ea, target):
    return IRInsn(ea, Op.JMP, args=(_imm(target, 64),))


def _ijmp(ea, reg="rax"):
    return IRInsn(ea, Op.JMP, args=(_reg(reg),))


def _ret(ea):
    return IRInsn(ea, Op.RET, args=())


def _fn(blocks, entry):
    b = {start: IRBlock(start=start, insns=list(insns), succs=list(succs))
         for start, insns, succs in blocks}
    return IRFunction(start=entry, blocks=b, entry=entry)


def _empty_fn():
    return IRFunction(start=0, blocks={}, entry=0)


# ===========================================================================
# recover_types
# ===========================================================================
def test_recover_types_ptr_signed_and_unknown():
    # rax used as a memory base -> ptr; rcx/rdx compared with cc_lt -> signed int;
    # rbx only appears in a sign-agnostic ADD -> unknown.
    fn = _fn([
        (0, [
            IRInsn(0, Op.ADD, dst=_reg("rbx"), args=(_reg("rbx"), _imm(1, 64))),
            IRInsn(0, Op.LOAD, dst=_temp("t0_0", 32), args=(_mem(base="rax"),)),
            _cmp(0, _reg("rcx"), _reg("rdx")),
            _br(0, 1, 2, token="lt", flags=("SF", "OF")),
        ], []),
    ], entry=0)
    types = recover_types(fn)

    assert types["rax"] == TypeGuess(kind="ptr", width=64, is_signed=False)
    assert types["rcx"].kind == "int" and types["rcx"].is_signed
    assert types["rdx"].kind == "int" and types["rdx"].is_signed
    assert types["rbx"].kind == "unknown"


def test_recover_types_unsigned_from_shr():
    # a SHR operand and an unsigned compare both push unsigned.
    fn = _fn([
        (0, [
            IRInsn(0, Op.SHR, dst=_reg("rax"), args=(_reg("rax"), _imm(2, 8))),
            _cmp(0, _reg("rsi"), _reg("rdi")),
            _br(0, 1, 2, token="b", flags=("CF",)),
        ], []),
    ], entry=0)
    types = recover_types(fn)
    assert types["rax"].kind == "uint" and not types["rax"].is_signed
    assert types["rsi"].kind == "uint"
    assert types["rdi"].kind == "uint"


# ===========================================================================
# BLOCK emission: single arith + store
# ===========================================================================
def test_block_single_arith_and_store():
    # t0 = 1 + 2 ; *[rbx] = t0    (emit directly, so constant folding does NOT
    # collapse the arithmetic -- we want to see the infix expression).
    fn = _fn([
        (0, [
            IRInsn(0, Op.ADD, dst=_temp("t0", 32), args=(_imm(1, 8), _imm(2, 8))),
            IRInsn(0, Op.STORE, dst=_mem(base="rbx", size=32), args=(_temp("t0", 32),)),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="f")
    assert isinstance(dec, DecompiledFunction)
    assert "t0 = 1 + 2;" in dec.source
    assert "= t0;" in dec.source
    assert "*(uint32_t*)(rbx) = t0;" in dec.source
    assert dec.source.startswith("void f(void) {") or dec.source.startswith("uint")


# ===========================================================================
# IF / ELSE shape
# ===========================================================================
def test_if_then_else_shape():
    # header: cmp rax, rbx ; je then(1) else(2) ; diamond merges at 3.
    fn = _fn([
        (0, [_cmp(0, _reg("rax"), _reg("rbx")), _br(0, 1, 2, token="eq")], [1, 2]),
        (1, [IRInsn(1, Op.ASSIGN, dst=_reg("rcx"), args=(_imm(1, 8),)), _jmp(1, 3)], [3]),
        (2, [IRInsn(2, Op.ASSIGN, dst=_reg("rcx"), args=(_imm(2, 8),)), _jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="f")
    assert "if (rax == rbx) {" in dec.source
    assert "} else {" in dec.source
    # both arms produced their assignments
    assert "rcx = 1;" in dec.source
    assert "rcx = 2;" in dec.source


# ===========================================================================
# WHILE shape
# ===========================================================================
def test_while_shape():
    # pre-test loop: header tests, body loops back.
    fn = _fn([
        (0, [_cmp(0, _reg("rcx"), _imm(10, 8)),
             _br(0, 1, 2, token="lt", flags=("SF", "OF"))], [1, 2]),
        (1, [IRInsn(1, Op.ADD, dst=_reg("rcx"), args=(_reg("rcx"), _imm(1, 8))),
             _jmp(1, 0)], [0]),
        (2, [_ret(2)], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="f")
    assert "while (" in dec.source
    assert "rcx" in dec.source
    # body's increment shows up inside the loop
    assert "rcx = rcx + 1;" in dec.source


# ===========================================================================
# DO / WHILE shape
# ===========================================================================
def test_do_while_shape():
    # post-test loop: header (0) just enters; latch (1) tests and loops back.
    fn = _fn([
        (0, [_jmp(0, 1)], [1]),
        (1, [IRInsn(1, Op.ADD, dst=_reg("rcx"), args=(_reg("rcx"), _imm(1, 8))),
             _cmp(1, _reg("rcx"), _imm(10, 8)),
             _br(1, 0, 2, token="ne")], [0, 2]),
        (2, [_ret(2)], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="f")
    assert "do {" in dec.source
    assert "} while (" in dec.source
    assert "rcx != 10" in dec.source          # imm size 8 -> decimal


# ===========================================================================
# SWITCH shape (synthetic ordinals)
# ===========================================================================
def test_switch_shape():
    fn = _fn([
        (0, [_ijmp(0, "rax")], [1, 2]),
        (1, [IRInsn(1, Op.ASSIGN, dst=_reg("rbx"), args=(_imm(7, 8),)), _jmp(1, 3)], [3]),
        (2, [IRInsn(2, Op.ASSIGN, dst=_reg("rbx"), args=(_imm(8, 8),)), _jmp(2, 3)], [3]),
        (3, [_ret(3)], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="f")
    assert "switch (rax) {" in dec.source
    assert "case 0:" in dec.source
    assert "case 1:" in dec.source
    assert "break;" in dec.source
    # the leading comment notes case values are synthetic ordinals
    assert "synthetic ordinals" in dec.source


# ===========================================================================
# BREAK / CONTINUE / RETURN inside a loop
# ===========================================================================
def test_break_continue_return_render():
    body = SNode(NodeKind.SEQ, children=[
        SNode(NodeKind.BREAK),
        SNode(NodeKind.CONTINUE),
        SNode(NodeKind.RETURN),
    ])
    loop = SNode(NodeKind.WHILE, ea=0, block=None, cond=None, body=body)
    sf = StructuredFunction(entry=0, body=loop, unreachable=[], goto_count=0)
    dec = emit(sf, _empty_fn(), name="f")
    assert "break;" in dec.source
    assert "continue;" in dec.source
    assert "return;" in dec.source
    assert "while (" in dec.source


def test_return_with_value():
    ret = SNode(NodeKind.RETURN, return_value=_reg("rax"))
    sf = StructuredFunction(entry=0, body=ret, unreachable=[], goto_count=0)
    dec = emit(sf, _empty_fn(), name="f")
    assert "return rax;" in dec.source


# ===========================================================================
# GOTO with a label on the target
# ===========================================================================
def test_goto_emits_label_on_target():
    target = 0x1234
    blk = IRBlock(start=target,
                  insns=[IRInsn(target, Op.ASSIGN, dst=_reg("rax"), args=(_imm(5, 8),))],
                  succs=[])
    body = SNode(NodeKind.SEQ, children=[
        SNode(NodeKind.GOTO, goto_target=target),
        SNode(NodeKind.BLOCK, ea=target, block=blk),
    ])
    sf = StructuredFunction(entry=0, body=body, unreachable=[], goto_count=1)
    dec = emit(sf, _empty_fn(), name="f")
    assert "goto L1234;" in dec.source
    assert "L1234:" in dec.source
    # and the goto warning surfaced
    assert any("goto" in w.lower() for w in dec.warnings)


# ===========================================================================
# UNDEF passes through as a comment
# ===========================================================================
def test_undef_passthrough_comment():
    blk = IRBlock(start=0, insns=[IRInsn(0, Op.UNDEF, text="cpuid ")], succs=[])
    body = SNode(NodeKind.BLOCK, ea=0, block=blk)
    sf = StructuredFunction(entry=0, body=body, unreachable=[], goto_count=0)
    dec = emit(sf, _empty_fn(), name="f")
    assert "/* undef: cpuid" in dec.source


# ===========================================================================
# warnings populated on irreducible input (goto_count > 0)
# ===========================================================================
def test_warnings_on_gotos():
    body = SNode(NodeKind.SEQ, children=[SNode(NodeKind.RETURN)])
    sf = StructuredFunction(entry=0, body=body, unreachable=[], goto_count=3)
    dec = emit(sf, _empty_fn(), name="f")
    assert any("goto" in w.lower() for w in dec.warnings)
    # the ABI-signature caveat is always noted
    assert any("signature recovery" in w.lower() for w in dec.warnings)


def test_lea_renders_as_address():
    # ASSIGN dst = MEM(...) is a lea (effective address, no dereference).
    blk = IRBlock(start=0, insns=[
        IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_mem(base="rbx", disp=0x10, size=64),)),
    ], succs=[])
    sf = StructuredFunction(entry=0, body=SNode(NodeKind.BLOCK, ea=0, block=blk),
                            unreachable=[], goto_count=0)
    dec = emit(sf, _empty_fn(), name="f")
    assert "rax = rbx + 0x10; /* lea */" in dec.source


# ===========================================================================
# end-to-end smoke: lift + full pipeline on real bytes (capstone-gated)
# ===========================================================================
def test_end_to_end_if_else_capstone():
    pytest.importorskip("capstone")
    from aletheia.disasm import build_cfg, disassemble_linear
    from aletheia.ir import lift_function

    #   cmp edi, 1          83 FF 01
    #   jne  else           75 07
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

    dec = decompile_function(fn, name="tiny")
    assert isinstance(dec, DecompiledFunction)
    assert "if (" in dec.source
    assert "return" in dec.source
    assert isinstance(dec.types, dict)
    assert isinstance(dec.warnings, list)
    # decompile_function must not mutate the caller's IRFunction
    assert fn.entry == 0x1000


# ===========================================================================
# NEW: signature inference (#17)
# ===========================================================================
from aletheia.decompile import (  # noqa: E402
    Argument, FunctionSignature, recover_signature,
)


def test_signature_inference_two_reg_args_and_return():
    """Reads rcx and rdx before any def, writes rax to a non-zero value ->
    signature has args=[rcx, rdx], return_type != void."""
    fn = _fn([
        (0, [
            IRInsn(0, Op.ADD, dst=_reg("rax"),
                   args=(_reg("rcx"), _reg("rdx"))),
            _ret(0),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    sig = dec.signature
    assert sig is not None
    assert sig.calling_convention == "win64"
    assert len(sig.args) == 2
    assert sig.args[0].source == "rcx" and sig.args[0].name == "arg0"
    assert sig.args[1].source == "rdx" and sig.args[1].name == "arg1"
    assert sig.return_type.kind != "void"
    # header uses the recovered signature
    assert dec.source.splitlines()[0].startswith("uint64_t sub(")
    assert "arg0" in dec.source.splitlines()[0]
    assert "arg1" in dec.source.splitlines()[0]
    # mapping comment surfaces
    assert "/* args: arg0 = rcx, arg1 = rdx */" in dec.source


def test_signature_inference_no_args_void_return():
    """No arg-reg reads, no non-zero rax write -> void sub(void)."""
    fn = _fn([
        (0, [
            # xor eax, eax style: ASSIGN rax = 0 is the void idiom
            IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(0, 64),)),
            _ret(0),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    sig = dec.signature
    assert sig is not None
    assert sig.args == []
    assert sig.return_type.kind == "void"
    assert dec.source.splitlines()[0] == "void sub(void) {"


def test_signature_recover_module_function_direct():
    """recover_signature() is a public helper and works directly on an IRFunction."""
    fn = _fn([
        (0, [
            IRInsn(0, Op.ADD, dst=_reg("rax"),
                   args=(_reg("r8"), _reg("rcx"))),
            _ret(0),
        ], []),
    ], entry=0)
    types = recover_types(fn)
    sig = recover_signature(fn, types)
    # r8 is arg2, so we count 3 args (arg0=rcx, arg1=rdx unknown, arg2=r8)
    assert len(sig.args) == 3
    assert sig.args[0].source == "rcx"
    assert sig.args[2].source == "r8"
    # rax written non-zero -> non-void
    assert sig.return_type.kind != "void"


def test_signature_scratch_use_only_looks_like_no_args_documented_limit():
    """Documented limit: writing rcx BEFORE any read makes it look like scratch,
    not an arg. This test locks in that heuristic behaviour."""
    fn = _fn([
        (0, [
            # rcx written first, then read -> not an incoming arg
            IRInsn(0, Op.ASSIGN, dst=_reg("rcx"), args=(_imm(5, 64),)),
            IRInsn(0, Op.ADD, dst=_reg("rax"), args=(_reg("rcx"), _imm(1, 8))),
            _ret(0),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    assert dec.signature.args == []          # heuristic: no arg detected


# ===========================================================================
# NEW: struct recovery (#18)
# ===========================================================================
def test_struct_recovery_three_fields():
    """rcx accessed at [rcx+0], [rcx+8], [rcx+0x10] -> struct auto_1 with three
    fields; the accesses are rewritten to field references."""
    fn = _fn([
        (0, [
            IRInsn(0, Op.LOAD, dst=_reg("rax"),
                   args=(_mem(base="rcx", disp=0, size=64),)),
            IRInsn(0, Op.STORE, dst=_mem(base="rcx", disp=8, size=64),
                   args=(_reg("rdx"),)),
            IRInsn(0, Op.LOAD, dst=_reg("r8"),
                   args=(_mem(base="rcx", disp=0x10, size=32),)),
            _ret(0),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    assert "auto_1" in dec.recovered_structs
    fields = dec.recovered_structs["auto_1"]
    assert [d for d, _, _ in fields] == [0, 8, 0x10]
    assert [n for _, n, _ in fields] == ["field_0", "field_8", "field_10"]
    # struct declaration and rewritten accesses appear in the source
    assert ("struct auto_1 { uint64_t field_0; uint64_t field_8; "
            "uint32_t field_10; };") in dec.source
    assert "((struct auto_1*)rcx)->field_0" in dec.source
    assert "((struct auto_1*)rcx)->field_8 = rdx;" in dec.source
    assert "((struct auto_1*)rcx)->field_10" in dec.source
    # and the raw *(uintN_t*)(rcx + K) form is GONE for these disps
    assert "*(uint64_t*)(rcx)" not in dec.source
    assert "*(uint64_t*)(rcx + 0x8)" not in dec.source
    assert "*(uint32_t*)(rcx + 0x10)" not in dec.source


def test_struct_single_access_stays_raw():
    """Only ONE access through rcx -> NOT promoted; raw deref stays."""
    fn = _fn([
        (0, [
            IRInsn(0, Op.LOAD, dst=_reg("rax"),
                   args=(_mem(base="rcx", disp=0, size=64),)),
            _ret(0),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    assert dec.recovered_structs == {}
    assert "*(uint64_t*)(rcx)" in dec.source
    assert "struct auto_" not in dec.source


def test_struct_same_disp_twice_stays_raw():
    """Two accesses at the SAME disp = still one field only -> not a struct."""
    fn = _fn([
        (0, [
            IRInsn(0, Op.LOAD, dst=_reg("rax"),
                   args=(_mem(base="rcx", disp=0, size=64),)),
            IRInsn(0, Op.STORE, dst=_mem(base="rcx", disp=0, size=64),
                   args=(_reg("rdx"),)),
            _ret(0),
        ], []),
    ], entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    assert dec.recovered_structs == {}


# ===========================================================================
# NEW: labelled break / continue (goto-with-sibling-labels convention)
# ===========================================================================
def test_labelled_break_emits_goto_end_label():
    """SNode.target_label='L1' on a BREAK plus SNode.label='L1' on the WHILE
    render as `goto L1_end;` inside and `L1_end:;` after the loop."""
    inner_body = SNode(NodeKind.SEQ, children=[
        SNode(NodeKind.BREAK, target_label="L1"),
    ])
    inner = SNode(NodeKind.WHILE, ea=0, block=None, cond=None, body=inner_body)
    outer = SNode(NodeKind.WHILE, ea=0, block=None, cond=None,
                  body=SNode(NodeKind.SEQ, children=[inner]), label="L1")
    sf = StructuredFunction(entry=0, body=outer, unreachable=[], goto_count=0,
                            label_count=1)
    dec = emit(sf, _empty_fn(), name="f")
    assert "goto L1_end;" in dec.source
    assert "L1_end:;" in dec.source
    # the outer AND inner loops both emit a `while (` line
    assert dec.source.count("while (") >= 2
    # inner labelled break must NOT render as a plain break;
    lines = [ln.strip() for ln in dec.source.splitlines()]
    assert "goto L1_end;" in lines
    # the label-count warning surfaces
    assert any("labelled loop" in w for w in dec.warnings)


def test_labelled_continue_emits_goto_continue_label():
    """SNode.target_label='L1' on a CONTINUE plus SNode.label='L1' on the outer
    WHILE render as `goto L1_continue;` and a `L1_continue:;` at the loop head."""
    inner_body = SNode(NodeKind.SEQ, children=[
        SNode(NodeKind.CONTINUE, target_label="L1"),
    ])
    inner = SNode(NodeKind.WHILE, ea=0, block=None, cond=None, body=inner_body)
    outer = SNode(NodeKind.WHILE, ea=0, block=None, cond=None,
                  body=SNode(NodeKind.SEQ, children=[inner]), label="L1")
    sf = StructuredFunction(entry=0, body=outer, unreachable=[], goto_count=0,
                            label_count=1)
    dec = emit(sf, _empty_fn(), name="f")
    assert "goto L1_continue;" in dec.source
    assert "L1_continue:;" in dec.source
    # the continue label appears BEFORE the outer `while (` line
    src = dec.source
    assert src.index("L1_continue:;") < src.index("while (")


def test_labelled_do_while_continue_placed_before_condition():
    """For a labelled DO_WHILE, L1_continue: goes just before `} while (...)`
    so goto reaches the condition check (not the top of the body)."""
    body = SNode(NodeKind.SEQ, children=[
        SNode(NodeKind.WHILE, ea=0, block=None, cond=None,
              body=SNode(NodeKind.SEQ, children=[
                  SNode(NodeKind.CONTINUE, target_label="L1"),
              ])),
    ])
    outer = SNode(NodeKind.DO_WHILE, ea=0, block=None, cond=None,
                  body=body, label="L1")
    sf = StructuredFunction(entry=0, body=outer, unreachable=[], goto_count=0,
                            label_count=1)
    dec = emit(sf, _empty_fn(), name="f")
    src = dec.source
    assert "L1_continue:;" in src
    assert src.index("L1_continue:;") < src.index("} while (")


def test_plain_break_continue_unaffected_by_labels():
    """A plain (target_label='') BREAK/CONTINUE still renders as `break;` /
    `continue;` -- the new convention is opt-in via target_label."""
    body = SNode(NodeKind.SEQ, children=[
        SNode(NodeKind.BREAK),
        SNode(NodeKind.CONTINUE),
    ])
    loop = SNode(NodeKind.WHILE, ea=0, block=None, cond=None, body=body)
    sf = StructuredFunction(entry=0, body=loop, unreachable=[], goto_count=0)
    dec = emit(sf, _empty_fn(), name="f")
    assert "break;" in dec.source
    assert "continue;" in dec.source
    assert "goto L" not in dec.source


# ===========================================================================
# NEW: memory-SSA integration
# ===========================================================================
def test_memory_ssa_load_substitution_end_to_end():
    """Store to a stack slot, then load from it -> the load is rewritten to an
    ASSIGN reading the stored value; the raw LOAD form is gone from the source."""
    def _reg64(n):
        return Value(VTag.REG, name=n, size=64)

    def _imm64(v):
        return Value(VTag.IMM, imm=v, size=64)

    def _mem64(base, disp):
        return Value(VTag.MEM, size=64, base=_reg64(base), disp=disp)

    fn = _fn([
        (0, [
            IRInsn(0, Op.STORE, dst=_mem64("rsp", -8), args=(_imm64(42),)),
            IRInsn(0, Op.LOAD, dst=_reg64("rax"), args=(_mem64("rsp", -8),)),
            # keep rax live by storing it elsewhere so DCE cannot delete it
            IRInsn(0, Op.STORE, dst=_mem64("rsp", -16), args=(_reg64("rax"),)),
            _ret(0),
        ], []),
    ], entry=0)
    dec = decompile_function(fn, name="sub")
    # the load form (`= *(uint64_t*)(rsp - 0x8)` on the RHS) must be GONE:
    # substitution should have produced `rax = 0x2a;` (or its folded equivalent).
    assert "= *(uint64_t*)(rsp - 0x8)" not in dec.source
    # the STORE at [rsp-8] survives (memory side effect); it prints on the LHS
    assert "*(uint64_t*)(rsp - 0x8) =" in dec.source
    # SETSLOT (op 101) never leaks into the source
    assert "setslot" not in dec.source.lower()


def test_memory_ssa_setslot_op_never_emits_source():
    """An IRFunction with a virtual SETSLOT op (op == 101) must be silently
    skipped by the emitter -- not printed, not crashed on."""
    from aletheia.dataflow import MEM_SSA_OP_CODE

    def _reg64(n):
        return Value(VTag.REG, name=n, size=64)

    def _imm64(v):
        return Value(VTag.IMM, imm=v, size=64)

    blk = IRBlock(start=0, insns=[
        # Hand-injected SETSLOT: virtual op 101 with a synthetic slot dst.
        IRInsn(0, MEM_SSA_OP_CODE,
               dst=Value(VTag.TEMP, name="slot_rsp_-8_64#1", size=64),
               args=(_imm64(42),)),
        # A trailing real assignment so the block isn't empty.
        IRInsn(0, Op.ASSIGN, dst=_reg64("rax"), args=(_imm64(1),)),
    ], succs=[])
    fn = IRFunction(start=0, blocks={0: blk}, entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    # the SETSLOT is not rendered as any form of statement
    assert "slot_rsp_-8_64" not in dec.source
    assert "setslot" not in dec.source.lower()
    # the real ASSIGN still renders
    assert "rax = 0x1;" in dec.source or "rax = 1;" in dec.source


def test_memory_ssa_slot_phi_renders_as_comment():
    """A PHI whose base name starts with 'slot_' (a memory-SSA merge) renders
    as a /* ... */ comment, not as a C statement."""
    from aletheia.dataflow import PHI_OP_CODE
    slot_val_1 = Value(VTag.TEMP, name="slot_rsp_-8_64#1", size=64)
    slot_val_2 = Value(VTag.TEMP, name="slot_rsp_-8_64#2", size=64)
    slot_val_dst = Value(VTag.TEMP, name="slot_rsp_-8_64#3", size=64)
    phi = IRInsn(0, PHI_OP_CODE, dst=slot_val_dst,
                 args=(slot_val_1, slot_val_2))
    blk = IRBlock(start=0, insns=[phi, _ret(0)], succs=[])
    fn = IRFunction(start=0, blocks={0: blk}, entry=0)
    sf = structure(fn)
    dec = emit(sf, fn, name="sub")
    # rendered as a /* comment */, not a `= phi(...);` statement
    assert "/* slot_rsp_-8_64 = phi(" in dec.source
    # a regular (non-slot) ssa phi still renders as a source line
    reg_phi = IRInsn(0, PHI_OP_CODE, dst=_reg("rax"),
                     args=(_reg("rax"), _reg("rax")))
    blk2 = IRBlock(start=0, insns=[reg_phi, _ret(0)], succs=[])
    fn2 = IRFunction(start=0, blocks={0: blk2}, entry=0)
    dec2 = emit(structure(fn2), fn2, name="sub")
    assert "rax = phi(rax, rax);" in dec2.source

# ===========================================================================
# streaming variants -- emit_stream / decompile_function_stream
# ===========================================================================
def test_streaming_matches_full_source():
    """Streaming yields the same lines as eager emit()'s .source, joined."""
    from aletheia.decompile import decompile_function, decompile_function_stream
    from aletheia.ir import IRFunction, IRBlock, IRInsn, Op, Value, VTag
    def R(n, w=64): return Value(tag=VTag.REG, name=n, size=w)
    insns = [
        IRInsn(ea=0x1000, op=Op.ADD, dst=R("rax"), args=(R("rcx"), R("rdx"))),
        IRInsn(ea=0x1003, op=Op.RET, dst=None, args=()),
    ]
    fn = IRFunction(
        start=0x1000,
        blocks={0x1000: IRBlock(start=0x1000, insns=insns, succs=[])},
        entry=0x1000,
    )
    eager = decompile_function(fn, name="demo").source
    streamed = "\n".join(decompile_function_stream(fn, name="demo"))
    assert streamed == eager


def test_streaming_is_a_generator():
    """Streaming variants must be true generators for back-pressure."""
    import inspect
    from aletheia.decompile import decompile_function_stream
    from aletheia.ir import IRFunction, IRBlock, IRInsn, Op, Value, VTag
    def R(n, w=64): return Value(tag=VTag.REG, name=n, size=w)
    insns = [
        IRInsn(ea=0x1000, op=Op.ASSIGN, dst=R("rax"),
               args=(Value(tag=VTag.IMM, imm=1, size=64),)),
        IRInsn(ea=0x1004, op=Op.RET, dst=None, args=()),
    ]
    fn = IRFunction(
        start=0x1000,
        blocks={0x1000: IRBlock(start=0x1000, insns=insns, succs=[])},
        entry=0x1000,
    )
    gen = decompile_function_stream(fn, name="demo")
    assert inspect.isgenerator(gen)
    first = next(gen)
    assert isinstance(first, str) and first.strip()
