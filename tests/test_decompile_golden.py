"""Golden-file regression tests for :mod:`aletheia.decompile`.

Every fixture is a small, hand-built :class:`~aletheia.ir.IRFunction` that
exercises one specific decompiler feature. The pytest runner sends the fixture
through :func:`aletheia.decompile.decompile_function` and compares the emitted
``.source`` byte-for-byte against a checked-in golden file
(``tests/goldens/decompile/<fixture>.golden.c``).

The point is a pre-Rust-rewrite lock: any change that alters the emitted output
has to be an *intentional* golden update (rerun with the env var below), not an
accidental drift. See ``tests/goldens/decompile/README.md`` for the regeneration
workflow.

Rules of the road (deliberately tight):

* Stdlib only; no capstone dependency (IR is hand-built).
* Every fixture must be **deterministic** across runs. If a fixture goes
  non-deterministic, mark it ``@pytest.mark.skip`` with an explanation rather
  than pretending to test something we cannot lock.
* The runner never modifies any file except the goldens under
  ``tests/goldens/decompile/`` (and only when ``ALETHEIA_UPDATE_GOLDENS=1``).
"""
from __future__ import annotations

import difflib
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.ir import (  # noqa: E402
    IRBlock, IRFunction, IRInsn, Op, Value, VTag,
)
from aletheia.decompile import decompile_function  # noqa: E402
from aletheia.simplify import opaque_predicate_pass  # noqa: E402


GOLDEN_DIR = pathlib.Path(__file__).parent / "goldens" / "decompile"
UPDATE_ENV = "ALETHEIA_UPDATE_GOLDENS"
UPDATE = os.environ.get(UPDATE_ENV) == "1"


# ---------------------------------------------------------------------------
# IR construction helpers (mirroring tests/test_decompile.py's style)
# ---------------------------------------------------------------------------
def _reg(name: str, size: int = 64) -> Value:
    return Value(VTag.REG, name=name, size=size)


def _imm(v: int, size: int = 64) -> Value:
    return Value(VTag.IMM, imm=v, size=size)


def _temp(name: str, size: int = 64) -> Value:
    return Value(VTag.TEMP, name=name, size=size)


def _mem(base=None, index=None, scale: int = 1, disp: int = 0,
         size: int = 64, seg: str = "") -> Value:
    b = _reg(base) if isinstance(base, str) else base
    i = _reg(index) if isinstance(index, str) else index
    return Value(VTag.MEM, size=size, base=b, index=i, scale=scale,
                 disp=disp, seg=seg)


def _br(ea: int, then_ea: int, else_ea: int, token: str = "ne",
        flags=("ZF",)) -> IRInsn:
    """A conditional-branch insn. `token` selects the jcc pseudo-name that the
    emitter turns into `==`, `!=`, `<`, etc. `flags` is the list of flag reads
    the branch depends on -- shape-only here (structuring keys on token)."""
    cond = Value(VTag.TEMP, name=f"cc_{token}", size=8)
    reads = tuple(_reg(f, 8) for f in flags)
    return IRInsn(ea, Op.BR, dst=None, args=(cond,) + reads,
                  then_ea=then_ea, else_ea=else_ea)


def _jmp(ea: int, target: int) -> IRInsn:
    return IRInsn(ea, Op.JMP, args=(_imm(target, 64),))


def _ret(ea: int) -> IRInsn:
    return IRInsn(ea, Op.RET, args=())


def _cmp(ea: int, a: Value, b: Value) -> IRInsn:
    return IRInsn(ea, Op.CMP, dst=None, args=(a, b))


def _fn(blocks, entry: int) -> IRFunction:
    """Build an IRFunction from a list of ``(start, [insns], [succs])`` tuples."""
    b = {start: IRBlock(start=start, insns=list(insns), succs=list(succs))
         for start, insns, succs in blocks}
    return IRFunction(start=entry, blocks=b, entry=entry)


# ---------------------------------------------------------------------------
# Fixture builders
#
# A word on liveness: dead_code_eliminate() runs BEFORE emission. A register
# def whose SSA name is never read on the way to a root op (STORE / RET / BR /
# CMP / ...) gets stripped. So fixtures that want their arithmetic to survive
# either (a) chain into a CMP / BR (control flow), or (b) end with a STORE that
# reads the produced register. Both patterns appear below and are exactly the
# same trick tests/test_decompile.py::test_memory_ssa_load_substitution_end_to_end
# uses to keep the load-result alive.
# ---------------------------------------------------------------------------

# -- Basic emission (4) ---------------------------------------------------
def build_assign_immediate() -> IRFunction:
    """rax = 42; store [rsp-8] = rax; ret -- exercises ASSIGN of an IMM."""
    return _fn([
        (0, [
            IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(42, 64),)),
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rax"),)),
            _ret(0),
        ], []),
    ], entry=0)


def build_arith_add() -> IRFunction:
    """rax = rbx + 5; store [rsp-8] = rax; ret -- exercises ADD infix."""
    return _fn([
        (0, [
            IRInsn(0, Op.ADD, dst=_reg("rax"),
                   args=(_reg("rbx"), _imm(5, 64))),
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rax"),)),
            _ret(0),
        ], []),
    ], entry=0)


def build_sub_and_return() -> IRFunction:
    """rax = rbx - rcx; store [rsp-8] = rax; ret -- exercises SUB + the sig
    inference (rcx is an ABI arg reg read before def)."""
    return _fn([
        (0, [
            IRInsn(0, Op.SUB, dst=_reg("rax"),
                   args=(_reg("rbx"), _reg("rcx"))),
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rax"),)),
            _ret(0),
        ], []),
    ], entry=0)


def build_nested_arith() -> IRFunction:
    """rax = (rbx - 3) + (rcx * 2). The IR is flat (three ops) -- the emitter
    prints one line per op and lets the reader compose them."""
    return _fn([
        (0, [
            IRInsn(0, Op.SUB, dst=_temp("t0", 64),
                   args=(_reg("rbx"), _imm(3, 64))),
            IRInsn(0, Op.IMUL, dst=_temp("t1", 64),
                   args=(_reg("rcx"), _imm(2, 64))),
            IRInsn(0, Op.ADD, dst=_reg("rax"),
                   args=(_temp("t0", 64), _temp("t1", 64))),
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rax"),)),
            _ret(0),
        ], []),
    ], entry=0)


# -- Control flow (3) -----------------------------------------------------
def build_if_only() -> IRFunction:
    """if (rax == 0) { rax = rax + 1; }; ret -- the else arm is empty (falls
    through), so structuring emits an IF with no `else`. A trailing STORE reads
    the merged rax so DCE keeps the ADD alive."""
    return _fn([
        (0, [_cmp(0, _reg("rax"), _imm(0, 64)),
             _br(0, then_ea=1, else_ea=2, token="eq")], [1, 2]),
        (1, [IRInsn(1, Op.ADD, dst=_reg("rax"),
                    args=(_reg("rax"), _imm(1, 64))),
             _jmp(1, 2)], [2]),
        (2, [IRInsn(2, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                    args=(_reg("rax"),)),
             _ret(2)], []),
    ], entry=0)


def build_if_else() -> IRFunction:
    """if (rax == rbx) { rcx = 1; } else { rcx = 2; }; store rcx; ret -- the
    diamond merges at block 3 with a STORE that keeps rcx live in both arms."""
    return _fn([
        (0, [_cmp(0, _reg("rax"), _reg("rbx")),
             _br(0, then_ea=1, else_ea=2, token="eq")], [1, 2]),
        (1, [IRInsn(1, Op.ASSIGN, dst=_reg("rcx"), args=(_imm(1, 64),)),
             _jmp(1, 3)], [3]),
        (2, [IRInsn(2, Op.ASSIGN, dst=_reg("rcx"), args=(_imm(2, 64),)),
             _jmp(2, 3)], [3]),
        (3, [IRInsn(3, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                    args=(_reg("rcx"),)),
             _ret(3)], []),
    ], entry=0)


def build_while_loop() -> IRFunction:
    """while (rcx < 10) { rcx = rcx + 1; }; ret -- pre-test loop. The body
    write to rcx is naturally live: the header CMP re-reads it."""
    return _fn([
        (0, [_cmp(0, _reg("rcx"), _imm(10, 64)),
             _br(0, then_ea=1, else_ea=2, token="lt",
                 flags=("SF", "OF"))], [1, 2]),
        (1, [IRInsn(1, Op.ADD, dst=_reg("rcx"),
                    args=(_reg("rcx"), _imm(1, 64))),
             _jmp(1, 0)], [0]),
        (2, [_ret(2)], []),
    ], entry=0)


# -- Signature inference (2) ---------------------------------------------
def build_two_arg_returning_sum() -> IRFunction:
    """rax = rcx + rdx; store [rsp-8] = rax; ret -- rcx and rdx are ABI arg
    regs read before any def, so the signature says two args returning a value."""
    return _fn([
        (0, [
            IRInsn(0, Op.ADD, dst=_reg("rax"),
                   args=(_reg("rcx"), _reg("rdx"))),
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rax"),)),
            _ret(0),
        ], []),
    ], entry=0)


def build_void_no_args() -> IRFunction:
    """xor eax, eax; ret -- ASSIGN of the constant 0 is the void-return idiom;
    no arg-reg reads and no non-zero rax write, so the signature is
    ``void sub(void)``."""
    return _fn([
        (0, [
            IRInsn(0, Op.ASSIGN, dst=_reg("rax"), args=(_imm(0, 64),)),
            _ret(0),
        ], []),
    ], entry=0)


# -- Struct recovery (1) --------------------------------------------------
def build_struct_two_fields() -> IRFunction:
    """*(u64)[rcx+0] = 1; *(u64)[rcx+8] = 2; ret -- two distinct disps through
    the same base promotes rcx to `struct auto_1` with `field_0` and `field_8`."""
    return _fn([
        (0, [
            IRInsn(0, Op.STORE, dst=_mem(base="rcx", disp=0, size=64),
                   args=(_imm(1, 64),)),
            IRInsn(0, Op.STORE, dst=_mem(base="rcx", disp=8, size=64),
                   args=(_imm(2, 64),)),
            _ret(0),
        ], []),
    ], entry=0)


# -- Memory-SSA integration (1) ------------------------------------------
def build_stack_roundtrip() -> IRFunction:
    """store rax at [rsp-8]; load rbx from [rsp-8]; store rbx at [rsp-16]; ret.

    The trailing STORE is there so DCE can't remove the load result. After
    memory_ssa, the LOAD should rewrite to ``rbx = rax;`` and the raw
    ``*(uint64_t*)(rsp - 0x8)`` should be gone from the READ side of the source
    (the write-side STORE is still emitted for its memory side effect)."""
    return _fn([
        (0, [
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rax"),)),
            IRInsn(0, Op.LOAD, dst=_reg("rbx"),
                   args=(_mem(base="rsp", disp=-8, size=64),)),
            IRInsn(0, Op.STORE, dst=_mem(base="rsp", disp=-16, size=64),
                   args=(_reg("rbx"),)),
            _ret(0),
        ], []),
    ], entry=0)


# -- Simplify integration (1) --------------------------------------------
def build_opaque_predicate_true() -> IRFunction:
    """cmp (rax*rax), 0; jl .never; add rbx, 1; store rbx; .never: ret.

    ``x * x < 0`` is provably impossible, so ``opaque_predicate_pass`` rewrites
    the BR into an unconditional JMP down the fallthrough. The subsequent
    decompile pipeline then emits straight-line code -- no ``if``, no ``goto``.

    We run the pass HERE (in the fixture builder) so the golden captures the
    post-simplify decompilation. Structuring is done inside
    ``decompile_function``.
    """
    fn = _fn([
        # block 0: t = rax * rax ; cmp t, 0 ; setflags ; jl .never
        (0, [
            IRInsn(0, Op.IMUL, dst=_temp("t0", 64),
                   args=(_reg("rax"), _reg("rax"))),
            _cmp(0, _temp("t0", 64), _imm(0, 64)),
            _br(0, then_ea=2, else_ea=1, token="lt",
                flags=("SF", "OF")),
        ], [1, 2]),
        # block 1: rbx += 1 ; store rbx to a stack slot so DCE keeps it alive
        (1, [
            IRInsn(1, Op.ADD, dst=_reg("rbx"),
                   args=(_reg("rbx"), _imm(1, 64))),
            IRInsn(1, Op.STORE, dst=_mem(base="rsp", disp=-8, size=64),
                   args=(_reg("rbx"),)),
            _jmp(1, 2),
        ], [2]),
        # block 2: .never -- just returns
        (2, [_ret(2)], []),
    ], entry=0)
    # Feed the opaque-predicate pass first so the golden reflects post-simplify
    # decompilation. The pass keys on structural equality + SSA base names, so
    # it works on this pre-SSA hand-built IR (documented behaviour).
    removed = opaque_predicate_pass(fn)
    assert removed == 1, (
        f"opaque_predicate_pass expected to fire exactly once, got {removed}."
        " If simplify semantics changed, the fixture must be updated -- do NOT"
        " silently accept a new golden here without understanding why.")
    return fn


# ---------------------------------------------------------------------------
# Fixture registry (ordered for stable parametrize ids)
# ---------------------------------------------------------------------------
FIXTURES = [
    # basic emission
    ("assign_immediate",       build_assign_immediate),
    ("arith_add",              build_arith_add),
    ("sub_and_return",         build_sub_and_return),
    ("nested_arith",           build_nested_arith),
    # control flow
    ("if_only",                build_if_only),
    ("if_else",                build_if_else),
    ("while_loop",             build_while_loop),
    # signature inference
    ("two_arg_returning_sum",  build_two_arg_returning_sum),
    ("void_no_args",           build_void_no_args),
    # struct recovery
    ("struct_two_fields",      build_struct_two_fields),
    # memory-SSA integration
    ("stack_roundtrip",        build_stack_roundtrip),
    # simplify integration
    ("opaque_predicate_true",  build_opaque_predicate_true),
]


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------
def _normalise(text: str) -> str:
    """Trailing whitespace stripped per line + a single trailing newline. Keeps
    the golden file diff-friendly and platform-neutral (CRLF/LF)."""
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("name,builder", FIXTURES,
                         ids=[n for n, _ in FIXTURES])
def test_golden(name: str, builder) -> None:
    fn = builder()
    result = decompile_function(fn, name=name)
    got = _normalise(result.source)

    golden_path = GOLDEN_DIR / f"{name}.golden.c"

    if UPDATE or not golden_path.exists():
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(got, encoding="utf-8")
        pytest.skip(f"golden updated: {golden_path.name} "
                    f"(remove {UPDATE_ENV} and re-run to lock)")

    expected = _normalise(golden_path.read_text(encoding="utf-8"))
    if got == expected:
        return

    diff = "".join(difflib.unified_diff(
        expected.splitlines(keepends=True),
        got.splitlines(keepends=True),
        fromfile=f"{golden_path.name} (expected)",
        tofile=f"{name} (got)",
        n=3,
    ))
    pytest.fail(
        f"decompile golden drift on {name!r}. "
        f"To accept the new output, re-run with {UPDATE_ENV}=1 "
        f"and commit the updated {golden_path.name}.\n\n{diff}"
    )


# ---------------------------------------------------------------------------
# Determinism smoke: decompile each fixture TWICE in the same process and
# require identical output. Cheap insurance against a fixture that quietly
# depends on dict ordering / address hashing / process-global counters.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,builder", FIXTURES,
                         ids=[n for n, _ in FIXTURES])
def test_golden_deterministic(name: str, builder) -> None:
    a = _normalise(decompile_function(builder(), name=name).source)
    b = _normalise(decompile_function(builder(), name=name).source)
    assert a == b, f"decompile_function on {name!r} is non-deterministic"
