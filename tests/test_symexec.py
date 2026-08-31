"""Tests for the lightweight symbolic executor (aletheia.symexec).

Everything here is stdlib-only: the term-algebra tests are pure arithmetic and
the interpreter/reachability tests build tiny IR *by hand* (small integer EAs as
block starts), so no capstone and no real binary are involved.  Only the shape
of the CFG matters, and every "right answer" is worked out on paper.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# aletheia.ir imports capstone lazily, so this succeeds without capstone.
from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag  # noqa: E402
from aletheia import symexec  # noqa: E402
from aletheia.symexec import (  # noqa: E402
    Kind, Term, k, sym, add, sub, and_, or_, xor, mul, neg, not_,
    eq, ne, lt, gt, ltu, ite, simplify, is_unsat, SIMPLIFIER_RULES,
    SymState, initial_state, step, symexec_path,
    enumerate_paths, is_reachable, path_condition, analyze_reachability,
)


# ---------------------------------------------------------------------------
# small IR constructors
# ---------------------------------------------------------------------------
def _reg(name, size=64):
    return Value(VTag.REG, name=name, size=size)


def _imm(v, size=64):
    return Value(VTag.IMM, imm=v, size=size)


def _mem(disp=0, base=None, index=None, scale=1, size=64):
    b = _reg(base) if base else None
    ix = _reg(index) if index else None
    return Value(VTag.MEM, size=size, base=b, index=ix, scale=scale, disp=disp)


def _br(token, then_ea, else_ea, flags=("ZF",)):
    args = (Value(VTag.TEMP, name=f"cc_{token}", size=8),) + \
           tuple(Value(VTag.FLAG, name=f) for f in flags)
    return IRInsn(0, Op.BR, dst=None, args=args, then_ea=then_ea, else_ea=else_ea)


def _fn(blocks, entry):
    b = {start: IRBlock(start=start, insns=list(insns), succs=list(succs))
         for start, insns, succs in blocks}
    return IRFunction(start=entry, blocks=b, entry=entry)


# ===========================================================================
# term algebra: folding
# ===========================================================================
def test_const_fold_add():
    r = add(k(3), k(4))
    assert r.kind is Kind.CONST and r.imm == 7
    assert r == k(7)


def test_add_identity_keeps_symbol():
    r = add(sym("x"), k(0))
    assert r.kind is Kind.SYM and r.name == "x"


def test_xor_self_folds_to_zero_after_simplify():
    r = simplify(xor(sym("x"), sym("x")))
    assert r == k(0)
    assert r.kind is Kind.CONST and r.imm == 0


def test_commutative_canonicalisation():
    # add(a, b) and add(b, a) are structurally equal after canonicalisation.
    assert add(sym("a"), sym("b")) == add(sym("b"), sym("a"))
    assert mul(k(5), sym("q")) == mul(sym("q"), k(5))


def test_more_identities():
    assert and_(sym("x"), k(0)) == k(0)
    assert or_(sym("x"), k(0)).kind is Kind.SYM
    assert mul(sym("x"), k(1)).kind is Kind.SYM
    assert sub(sym("x"), sym("x")) == k(0)
    assert not_(not_(sym("x"))).kind is Kind.SYM
    assert neg(neg(sym("x"))).kind is Kind.SYM
    assert eq(sym("x"), sym("x")) == k(1, 1)
    assert ne(sym("x"), sym("x")) == k(0, 1)


# ===========================================================================
# term algebra: width wraparound
# ===========================================================================
def test_width_wraparound_32bit():
    r = add(k(0xFFFFFFFF, 32), k(1, 32))
    assert r == k(0, 32)
    assert r.kind is Kind.CONST and r.imm == 0 and r.width == 32


def test_width_wraparound_independent_of_64():
    # same numbers at 64-bit do NOT wrap
    assert add(k(0xFFFFFFFF, 64), k(1, 64)) == k(0x100000000, 64)


def test_signed_vs_unsigned_compare_fold():
    # 0xFFFFFFFF as signed 32-bit is -1: signed < 0, unsigned > 0
    assert lt(k(0xFFFFFFFF, 32), k(0, 32)) == k(1, 1)      # -1 <  0 signed
    assert ltu(k(0xFFFFFFFF, 32), k(0, 32)) == k(0, 1)     # big >= 0 unsigned


def test_ite_folds_on_constant_cond():
    assert ite(k(1), sym("t"), sym("f")).name == "t"
    assert ite(k(0), sym("t"), sym("f")).name == "f"
    assert ite(sym("c"), sym("v"), sym("v")).name == "v"


def test_simplifier_rule_count():
    # documented, shipped ruleset
    assert len(SIMPLIFIER_RULES) == 18


# ===========================================================================
# interpreter: straight-line
# ===========================================================================
def test_simple_straightline_add():
    # rax = arg0 + 5 ; ret        (arg0 == rcx)
    entry = 0x1000
    insns = [
        IRInsn(entry, Op.ADD, dst=_reg("rax"), args=(_reg("rcx"), _imm(5))),
        IRInsn(entry + 4, Op.RET, args=()),
    ]
    func = _fn([(entry, insns, [])], entry)
    st = symexec_path(func, [entry])
    assert st is not None
    assert st.regs["rax"] == add(sym("arg0"), k(5))


def test_memory_roundtrip_concrete_addr():
    # *[0x2000] = 0xDEAD ; rax = *[0x2000] ; ret
    entry = 0x1000
    insns = [
        IRInsn(entry, Op.STORE, dst=_mem(disp=0x2000), args=(_imm(0xDEAD),)),
        IRInsn(entry + 4, Op.LOAD, dst=_reg("rax"), args=(_mem(disp=0x2000),)),
        IRInsn(entry + 8, Op.RET, args=()),
    ]
    func = _fn([(entry, insns, [])], entry)
    st = symexec_path(func, [entry])
    assert st is not None
    assert st.regs["rax"] == k(0xDEAD)


def test_undef_havoc_replaces_dst():
    # rax = 0x1111 ; <undef> rax ; rbx = rax ; ret
    entry = 0x1000
    insns = [
        IRInsn(entry, Op.ASSIGN, dst=_reg("rax"), args=(_imm(0x1111),)),
        IRInsn(entry + 4, Op.UNDEF, dst=_reg("rax"), text="rdtsc"),
        IRInsn(entry + 6, Op.ASSIGN, dst=_reg("rbx"), args=(_reg("rax"),)),
        IRInsn(entry + 8, Op.RET, args=()),
    ]
    func = _fn([(entry, insns, [])], entry)
    st = symexec_path(func, [entry])
    assert st is not None
    # rax is a fresh symbol, no longer the old constant
    assert st.regs["rax"].kind is Kind.SYM
    assert st.regs["rax"] != k(0x1111)
    # the later read of rax sees the NEW symbol
    assert st.regs["rbx"] == st.regs["rax"]
    assert any("havoc" in w for w in st.warnings)


# ===========================================================================
# interpreter: cmp + jcc round-trip
# ===========================================================================
def test_cmp_jcc_roundtrip_records_equality():
    # cmp rax, 5 ; je L    (rax is live-in -> sym("rax0"))
    entry, L, F = 0x1000, 0x1100, 0x1200
    a_insns = [
        IRInsn(entry, Op.CMP, dst=None, args=(_reg("rax"), _imm(5))),
        _br("eq", then_ea=L, else_ea=F, flags=("ZF",)),
    ]
    func = _fn([
        (entry, a_insns, [L, F]),
        (L, [IRInsn(L, Op.RET, args=())], []),
        (F, [IRInsn(F, Op.RET, args=())], []),
    ], entry)
    st = symexec_path(func, [entry, L])          # take the je
    assert st is not None
    assert any(t == eq(sym("rax0"), k(5)) for t in st.path_cond)

    # the fall-through (else) side carries the negation
    st_else = symexec_path(func, [entry, F])
    assert st_else is not None
    assert any(t == ne(sym("rax0"), k(5)) for t in st_else.path_cond)


# ===========================================================================
# reachability: two-branch diamond
# ===========================================================================
def _diamond_on_arg0(match):
    # A: cmp arg0, <match> ; je B else C     B,C -> D
    A, B, C, D = 0x1000, 0x1100, 0x1200, 0x1300
    a_insns = [
        IRInsn(A, Op.CMP, dst=None, args=(_reg("rcx"), _imm(match))),
        _br("eq", then_ea=B, else_ea=C, flags=("ZF",)),
    ]
    return _fn([
        (A, a_insns, [B, C]),
        (B, [IRInsn(B, Op.JMP, args=(_imm(D),))], [D]),
        (C, [IRInsn(C, Op.JMP, args=(_imm(D),))], [D]),
        (D, [IRInsn(D, Op.RET, args=())], []),
    ], A), (A, B, C, D)


def test_two_branch_reachable_with_condition():
    func, (A, B, C, D) = _diamond_on_arg0(42)
    assert is_reachable(func, B) is True
    pc = path_condition(func, B)
    assert pc is not None
    assert any(t == eq(sym("arg0"), k(42)) for t in pc)

    # C is reachable too, under the negated condition
    assert is_reachable(func, C) is True
    pc_c = path_condition(func, C)
    assert any(t == ne(sym("arg0"), k(42)) for t in pc_c)

    # D (the merge) is reachable from either arm
    assert is_reachable(func, D) is True


def test_reachability_result_is_flagged_approximate():
    func, (A, B, C, D) = _diamond_on_arg0(7)
    r = analyze_reachability(func, B)
    assert r.reachable is True
    assert r.approximate is True
    assert r.path == [A, B]
    assert "over-approx" in r.note


# ===========================================================================
# reachability: unsatisfiable path (x == 5 then x == 6)
# ===========================================================================
def test_unsat_path_returns_none():
    # A: cmp rax,5 ; je B else E
    # B: cmp rax,6 ; je Csucc else E     (rax==5 already asserted; ==6 contradicts)
    A, B, Csucc, E = 0x1000, 0x1100, 0x1200, 0x1300
    a_insns = [
        IRInsn(A, Op.CMP, dst=None, args=(_reg("rax"), _imm(5))),
        _br("eq", then_ea=B, else_ea=E, flags=("ZF",)),
    ]
    b_insns = [
        IRInsn(B, Op.CMP, dst=None, args=(_reg("rax"), _imm(6))),
        _br("eq", then_ea=Csucc, else_ea=E, flags=("ZF",)),
    ]
    func = _fn([
        (A, a_insns, [B, E]),
        (B, b_insns, [Csucc, E]),
        (Csucc, [IRInsn(Csucc, Op.RET, args=())], []),
        (E, [IRInsn(E, Op.RET, args=())], []),
    ], A)

    # the contradictory path itself is infeasible
    assert symexec_path(func, [A, B, Csucc]) is None
    # and Csucc is the ONLY block behind that path -> unreachable
    assert is_reachable(func, Csucc) is False
    assert path_condition(func, Csucc) is None

    # sanity: B on its own (just rax==5) IS reachable
    assert is_reachable(func, B) is True


def test_consistent_equalities_stay_satisfiable():
    # x == 5 then x == 5 again is fine (not a contradiction)
    A, B, Csucc, E = 0x1000, 0x1100, 0x1200, 0x1300
    a_insns = [
        IRInsn(A, Op.CMP, dst=None, args=(_reg("rax"), _imm(5))),
        _br("eq", then_ea=B, else_ea=E, flags=("ZF",)),
    ]
    b_insns = [
        IRInsn(B, Op.CMP, dst=None, args=(_reg("rax"), _imm(5))),
        _br("eq", then_ea=Csucc, else_ea=E, flags=("ZF",)),
    ]
    func = _fn([
        (A, a_insns, [B, E]),
        (B, b_insns, [Csucc, E]),
        (Csucc, [IRInsn(Csucc, Op.RET, args=())], []),
        (E, [IRInsn(E, Op.RET, args=())], []),
    ], A)
    assert is_reachable(func, Csucc) is True


# ===========================================================================
# structural SAT honesty: infeasible symbolic conjunction is NOT solved
# ===========================================================================
def test_is_unsat_structural_only():
    # concretely false -> caught
    assert is_unsat(eq(k(5), k(6))) is True
    assert is_unsat(lt(k(3), k(2))) is True
    # symbolic, genuinely-unsatisfiable conjunction terms individually pass
    # (documented over-approximation: no real solver)
    assert is_unsat(gt(add(sym("x"), sym("y")), k(10))) is False
    assert is_unsat(lt(sym("x"), k(5))) is False


# ===========================================================================
# path enumeration + loop back-edge bound
# ===========================================================================
def test_enumerate_paths_diamond():
    func, (A, B, C, D) = _diamond_on_arg0(1)
    paths = enumerate_paths(func, D)
    assert [A, B, D] in paths
    assert [A, C, D] in paths
    assert len(paths) == 2


def test_enumerate_paths_loop_bounded():
    # self-looping header must terminate (one back-edge traversal cap)
    H, X = 0x1000, 0x1100
    func = _fn([
        (H, [_br("ne", then_ea=H, else_ea=X, flags=("ZF",))], [H, X]),
        (X, [IRInsn(X, Op.RET, args=())], []),
    ], H)
    paths = enumerate_paths(func, X, max_paths=16, max_depth=16)
    assert paths                                 # terminates and finds X
    assert all(p[-1] == X for p in paths)


def test_unreachable_target_no_paths():
    # a block that no edge leads to
    A, B, ISLAND = 0x1000, 0x1100, 0x9000
    func = _fn([
        (A, [IRInsn(A, Op.JMP, args=(_imm(B),))], [B]),
        (B, [IRInsn(B, Op.RET, args=())], []),
        (ISLAND, [IRInsn(ISLAND, Op.RET, args=())], []),
    ], A)
    assert enumerate_paths(func, ISLAND) == []
    assert is_reachable(func, ISLAND) is False


# ===========================================================================
# initial_state contract
# ===========================================================================
def test_initial_state_arg_mapping():
    func = _fn([(0x1000, [IRInsn(0x1000, Op.RET, args=())], [])], 0x1000)
    st = initial_state(func)
    assert st.regs["rcx"] == sym("arg0")
    assert st.regs["rdx"] == sym("arg1")
    assert st.regs["r8"] == sym("arg2")
    assert st.regs["r9"] == sym("arg3")


def test_initial_state_custom_arg_names():
    func = _fn([(0x1000, [IRInsn(0x1000, Op.RET, args=())], [])], 0x1000)
    st = initial_state(func, arg_names=["fd", "buf", "count"])
    assert st.regs["rcx"] == sym("fd")
    assert st.regs["rdx"] == sym("buf")
    assert st.regs["r8"] == sym("count")


def test_step_is_copy_semantics():
    # step must not mutate the input state
    st0 = SymState(regs={"rax": k(1)})
    insn = IRInsn(0, Op.ADD, dst=_reg("rax"), args=(_reg("rax"), _imm(2)))
    st1 = step(st0, insn)
    assert st0.regs["rax"] == k(1)               # unchanged
    assert st1.regs["rax"] == k(3)               # 1 + 2 folded
